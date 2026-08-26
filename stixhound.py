#!/usr/bin/env python3
"""
stixhound - convert STIX 2.1 CTI bundles into BloodHound OpenGraph payloads.

    python3 stixhound.py bundle.json -o out/

Produces:
    out/<name>.opengraph.json   OpenGraph payload, ready to upload
    out/<name>.customnodes.json Icon definitions for the custom kinds
    out/<name>.cypher           Join queries: does this actor's tradecraft
                                exist in MY environment?
    out/<name>.summary.md       Human-readable rundown of what was built

Upload:
    curl -X POST $BH/api/v2/file-upload/... (see README)

The conversion is lossy on purpose. CTI bundles carry a lot of prose and
metadata that adds nodes without adding shape; the goal here is the
intrusion's topology, not a faithful re-encoding of the bundle.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter, OrderedDict
from functools import lru_cache

from mappings import (
    EMBEDDED_REF_KINDS,
    ICONS,
    NOISY_TYPES,
    RELATIONSHIP_KINDS,
    STIX_TYPE_KINDS,
    technique_edges,
)

KIND_RE = re.compile(r"^[A-Za-z0-9_]+$")
NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")

# OpenGraph reserves this prefix on kind names.
RESERVED_KIND_PREFIX = "tag_"

# Hop bound on the generated Tier Zero path query. Unbounded variable-length
# shortestPath is the single most expensive thing this tool can emit.
DEFAULT_MAX_HOPS = 6

# Properties that are noise, huge, or structurally handled elsewhere.
SKIP_PROPS = frozenset({
    "id", "type", "spec_version", "created_by_ref", "object_marking_refs",
    "granular_markings", "extensions", "object_refs", "sample_refs",
    "analysis_sco_refs", "host_vm_ref", "operating_system_ref",
    "external_references", "kill_chain_phases", "relationship_type",
    "source_ref", "target_ref", "defanged", "revoked",
})

# external_references source_name values that carry an ATT&CK ID.
ATTACK_SOURCES = frozenset({
    "mitre-attack", "mitre-pre-attack", "mitre-mobile-attack",
    "mitre-ics-attack",
})

# Embedded refs that actually produce edges, resolved once instead of
# re-filtering the None entries for every object in the bundle.
EMBEDDED_REF_EDGES = tuple(
    (prop, kind) for prop, kind in EMBEDDED_REF_KINDS.items() if kind
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=4096)
def camel(value: str) -> str:
    """Turn an arbitrary STIX verb into a legal OpenGraph edge kind."""
    parts = NON_ALNUM_RE.split(value)
    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return out or "RelatedTo"


def legal_kind(kind: str) -> bool:
    """OpenGraph kinds must match ^[A-Za-z0-9_]+$ and not claim `tag_`."""
    return bool(KIND_RE.match(kind)) and not kind.startswith(RESERVED_KIND_PREFIX)


def flatten(value):
    """
    OpenGraph property values must be primitives or homogeneous arrays of
    primitives. Nulls are not valid. Anything nested gets serialised.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        if not value:
            return None
        # One pass, classifying as we go. The old version built an
        # intermediate list and then walked it up to three more times.
        all_bool = all_num = all_str = True
        for item in value:
            if isinstance(item, bool):
                all_num = all_str = False
            elif isinstance(item, (int, float)):
                all_bool = all_str = False
            elif isinstance(item, str):
                all_bool = all_num = False
            else:
                # a non-primitive anywhere makes the whole array unusable
                return json.dumps(value, sort_keys=True)
        if all_bool or all_num or all_str:
            return value
        # mixed primitive types - the ingest rejects those, so stringify
        return [str(v) for v in value]
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def attack_id(obj: dict) -> str | None:
    """Pull the ATT&CK technique/group ID out of external_references."""
    for ref in obj.get("external_references", []) or []:
        if isinstance(ref, dict) and ref.get("source_name") in ATTACK_SOURCES:
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def _prop_key(props: dict) -> tuple:
    """
    Hashable identity for an edge's properties, for exact-duplicate checks.

    The fast path is just the items tuple, which is what every call site
    actually produces - edge properties are built in a fixed order per call
    site and flatten() yields primitives. Sorting and normalising costs about
    a third of total conversion time on a large bundle, so it is kept as the
    fallback for the array-valued case rather than paid for on every edge.
    """
    items = tuple(props.items())
    try:
        hash(items)
    except TypeError:
        return tuple(sorted(
            (k, tuple(v) if isinstance(v, list) else v) for k, v in props.items()
        ))
    return items


def cypher_str(value: str) -> str:
    """Escape a value for use inside a single-quoted Cypher string literal."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def cypher_comment(value: str) -> str:
    """Keep untrusted CTI text on one line so it cannot escape a `//` comment."""
    return " ".join(str(value).split())


def primary_source(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if not isinstance(ref, dict):
            continue
        name = ref.get("source_name")
        if name and not str(name).startswith("mitre"):
            return ref.get("url") or name
    return None


# ---------------------------------------------------------------------------
# conversion
# ---------------------------------------------------------------------------
class Converter:
    def __init__(self, source_kind: str, include_noisy: bool = False,
                 author_ids: set[str] | None = None):
        self.source_kind = source_kind
        self.include_noisy = include_noisy
        # STIX reuses `identity` for both the reporting org and the victim.
        # Anything referenced by created_by_ref is an author, not a target.
        self.author_ids = author_ids or set()
        self.nodes: "OrderedDict[str, dict]" = OrderedDict()
        self.edges: list[dict] = []
        self.techniques: "OrderedDict[str, str]" = OrderedDict()  # attack_id -> name
        # Techniques with a structural BloodHound equivalent. Tracked as we go
        # so the coverage number is never recomputed from a second scan and
        # cannot disagree with the `graph_mappable` property on the nodes.
        self.mappable: set[str] = set()
        # A malformed bundle can produce one warning per object; dedupe on the
        # way in so a 100k-object bundle cannot grow a 100k-entry list.
        self.warnings: "OrderedDict[str, None]" = OrderedDict()
        self.skipped = Counter()
        self.duplicates = Counter()
        # (kind, start, end, props) of every edge emitted, to drop exact
        # duplicates. STIX bundles legitimately repeat objects across versions,
        # and each repeat re-emits the same embedded-ref edges.
        self._edge_keys: set = set()

    def warn(self, message: str) -> None:
        self.warnings[message] = None

    # -- nodes ------------------------------------------------------------
    def add_object(self, obj: dict) -> None:
        stix_type = obj.get("type")
        if stix_type == "relationship":
            return
        if stix_type == "sighting":
            self._add_sighting(obj)
            return
        if stix_type in NOISY_TYPES and not self.include_noisy:
            self.skipped[stix_type] += 1
            return

        kind = STIX_TYPE_KINDS.get(stix_type)
        if stix_type == "identity" and obj["id"] in self.author_ids:
            kind = "Author"
        if kind is None:
            kind = camel(stix_type or "Unknown")
            self.warn(f"unmapped STIX type '{stix_type}' -> kind '{kind}'")
        if not legal_kind(kind):
            self.skipped[stix_type] += 1
            self.warn(f"illegal kind derived from '{stix_type}', skipped")
            return

        props: dict = {}
        for key, val in obj.items():
            if key in SKIP_PROPS:
                continue
            flat = flatten(val)
            if flat is not None:
                props[key] = flat

        tid = attack_id(obj)
        if tid:
            props["attack_id"] = tid
            if stix_type == "attack-pattern":
                self.techniques[tid] = obj.get("name", tid)
                # does this technique have a structural equivalent in BH?
                mapped = technique_edges(tid)
                props["graph_mappable"] = bool(mapped)
                if mapped:
                    props["bloodhound_edges"] = list(mapped)
                    self.mappable.add(tid)

        src = primary_source(obj)
        if src:
            props["source_url"] = src

        phases = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) or []
                  if p.get("phase_name")]
        if phases:
            props["kill_chain_phases"] = phases

        props.setdefault("name", obj.get("name") or obj.get("value") or obj["id"])
        props["stix_type"] = stix_type
        props["cti_source"] = self.source_kind

        # First kind drives the icon in the BloodHound UI. Max 3 kinds.
        node_id = obj["id"]
        if node_id in self.nodes:
            # STIX bundles carry object versions; last one wins, as before.
            self.duplicates[stix_type] += 1
        self.nodes[node_id] = {
            "id": node_id,
            "kinds": [kind, "CTI"],
            "properties": props,
        }

        # embedded refs behave like relationships
        for prop, edge_kind in EMBEDDED_REF_EDGES:
            targets = obj.get(prop)
            if targets is None:
                continue
            if not isinstance(targets, list):
                targets = [targets]
            for target in targets:
                if isinstance(target, str):
                    self._edge(node_id, target, edge_kind, {"embedded": True})

    def _add_sighting(self, obj: dict) -> None:
        ref = obj.get("sighting_of_ref")
        for observer in obj.get("where_sighted_refs", []) or []:
            if ref:
                self._edge(observer, ref, "Sighted", {
                    "count": obj.get("count", 1),
                    "first_seen": obj.get("first_seen", ""),
                })

    # -- edges ------------------------------------------------------------
    def add_relationship(self, obj: dict) -> None:
        verb = obj.get("relationship_type", "related-to")
        if not isinstance(verb, str):
            self.warn(f"non-string relationship_type {verb!r}, skipped")
            return
        kind = RELATIONSHIP_KINDS.get(verb) or camel(verb)
        if not legal_kind(kind):
            self.warn(f"illegal edge kind from '{verb}', skipped")
            return
        props = {}
        for key in ("description", "start_time", "stop_time", "confidence", "created"):
            if obj.get(key) is not None:
                props[key] = flatten(obj[key])
        self._edge(obj.get("source_ref"), obj.get("target_ref"), kind, props)

    def _edge(self, start: str | None, end: str | None, kind: str, props: dict) -> None:
        if not start or not end:
            return
        props = {k: v for k, v in props.items() if v is not None}
        props["cti_source"] = self.source_kind
        key = (kind, start, end, _prop_key(props))
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({
            "kind": kind,
            "start": {"value": start, "match_by": "id"},
            "end": {"value": end, "match_by": "id"},
            "properties": props,
        })

    # -- output -----------------------------------------------------------
    def prune_dangling(self) -> int:
        """Drop edges whose endpoints were filtered out. Ingest accepts them
        silently but they produce isolated edges you cannot see."""
        before = len(self.edges)
        ids = self.nodes.keys()
        self.edges = [e for e in self.edges
                      if e["start"]["value"] in ids and e["end"]["value"] in ids]
        return before - len(self.edges)

    def payload(self) -> dict:
        return {
            "graph": {
                "nodes": list(self.nodes.values()),
                "edges": self.edges,
            },
            "metadata": {"source_kind": self.source_kind},
        }

    def custom_nodes(self) -> dict:
        used = {n["kinds"][0] for n in self.nodes.values()}
        custom = {}
        for kind in sorted(used):
            icon, color = ICONS.get(kind, ("circle-question", "#7F8C8D"))
            custom[kind] = {"icon": {"type": "font-awesome", "name": icon, "color": color}}
        return {"custom_types": custom}


# ---------------------------------------------------------------------------
# the join layer
# ---------------------------------------------------------------------------
def build_cypher(techniques: dict[str, str], source_kind: str,
                 max_hops: int = DEFAULT_MAX_HOPS) -> str:
    """
    Generate queries that ask the environment graph whether the tradecraft
    described in the CTI bundle is structurally possible here.

    `max_hops` bounds the variable-length path in query 3. Leave it bounded:
    an unbounded `*1..` shortestPath over a real AD graph is the difference
    between a query that answers and a query that times out. 0 removes the
    bound if you really want it.
    """
    lines = [
        f"// ===================================================================",
        f"// Environment join queries for CTI source: {source_kind}",
        f"// Generated by stixhound. Run in BloodHound's Cypher search.",
        f"// ===================================================================",
        "",
        "// -- 1. Which of this actor's techniques exist in my environment? ---",
    ]

    mapped: list[tuple[str, str, tuple[str, ...]]] = []
    unmapped: list[tuple[str, str]] = []
    for tid, name in techniques.items():
        edges = technique_edges(tid)
        if edges:
            mapped.append((tid, cypher_comment(name), edges))
        else:
            unmapped.append((tid, cypher_comment(name)))

    if not mapped:
        lines += ["// No techniques in this bundle map to structural graph edges.",
                  "// That is a real result, not a failure - see summary.md.", ""]
    for tid, name, edges in mapped:
        rel = "|".join(edges)
        lines += [
            f"// {tid} - {name}",
            f"MATCH p = (s)-[r:{rel}]->(t)",
            f"RETURN p LIMIT 250",
            "",
        ]

    if mapped:
        all_edges = sorted({e for _, _, es in mapped for e in es})
        rel = "|".join(all_edges)
        if max_hops > 0:
            hops = f"*1..{max_hops}"
            hop_note = [
                f"//     Bounded to {max_hops} hops (--max-hops). An unbounded",
                "//     variable-length search will not return on a large graph.",
            ]
        else:
            hops = "*1.."
            hop_note = [
                "//     UNBOUNDED path length. Expect this to be slow, or to not",
                "//     return at all on a production-sized graph.",
            ]
        lines += [
            "// -- 2. Full tradecraft overlay: every edge this actor could use ----",
            f"MATCH p = (s)-[r:{rel}]->(t)",
            "RETURN p LIMIT 1000",
            "",
            "// -- 3. Actor tradecraft that reaches Tier Zero ---------------------",
            "//     This is the question worth answering. Everything above is",
            "//     inventory; this is exposure.",
            *hop_note,
            "//     Anchor on Tier Zero first so the variable-length expansion",
            "//     starts from a small set rather than the whole graph.",
            "MATCH (t) WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0'",
            f"MATCH p = shortestPath((s)-[r:{rel}{hops}]->(t))",
            "WHERE s <> t",
            "RETURN p LIMIT 250",
            "",
            "// -- 4. Count exposure per technique --------------------------------",
        ]
        for tid, name, edges in mapped:
            rel_i = "|".join(edges)
            lines += [
                f"// {tid} - {name}",
                f"MATCH (s)-[r:{rel_i}]->(t)",
                f"RETURN '{cypher_str(tid)}' AS technique, COUNT(r) AS edge_count",
                "",
            ]

    lines += [
        "// -- 5. The CTI subgraph itself (what the bundle described) ---------",
        f"MATCH p = (n:CTI)-[r]->(m:CTI)",
        f"WHERE n.cti_source = '{cypher_str(source_kind)}'",
        "RETURN p LIMIT 500",
        "",
        "// -- 6. Controls the reporting says would mitigate this --------------",
        "MATCH p = (c:Control)-[:Mitigates]->(a:AttackPattern)",
        f"WHERE a.cti_source = '{cypher_str(source_kind)}'",
        "RETURN p",
        "",
    ]

    if unmapped:
        lines.append("// -- Techniques with no structural equivalent in the graph ----------")
        lines.append("//    (execution, defense evasion, C2 and similar leave no trace in a")
        lines.append("//     configuration graph - they need telemetry, not topology)")
        for tid, name in unmapped:
            lines.append(f"//    {tid} - {name}")
        lines.append("")

    return "\n".join(lines)


def build_summary(conv: Converter, mapped_n: int, dangling: int, name: str) -> str:
    kinds = Counter(n["kinds"][0] for n in conv.nodes.values())
    edge_kinds = Counter(e["kind"] for e in conv.edges)
    total_tech = len(conv.techniques)
    pct = (mapped_n / total_tech * 100) if total_tech else 0.0

    out = [
        f"# stixhound: {name}",
        "",
        f"- **source_kind**: `{conv.source_kind}` (use this to filter or delete the whole ingest)",
        f"- **nodes**: {len(conv.nodes)}",
        f"- **edges**: {len(conv.edges)}",
        f"- **ATT&CK techniques**: {total_tech}",
        f"- **structurally mappable to BloodHound edges**: {mapped_n} of {total_tech} ({pct:.0f}%)",
        "",
        "## Node kinds",
        "",
    ]
    for kind, count in kinds.most_common():
        out.append(f"- `{kind}` x{count}")
    out += ["", "## Edge kinds", ""]
    for kind, count in edge_kinds.most_common():
        out.append(f"- `{kind}` x{count}")

    if conv.skipped:
        out += ["", "## Skipped (noise filter)", ""]
        for stype, count in conv.skipped.most_common():
            out.append(f"- `{stype}` x{count} - re-run with `--include-noisy` to keep")
    if conv.duplicates:
        total_dupes = sum(conv.duplicates.values())
        out += ["", f"## Re-declared {total_dupes} object(s)", "",
                "The bundle carried the same STIX id more than once. The last",
                "declaration won, which is the STIX versioning convention.", ""]
        for stype, count in conv.duplicates.most_common():
            out.append(f"- `{stype}` x{count}")
    if dangling:
        out += ["", f"## Pruned {dangling} dangling edge(s)",
                "", "Endpoints were filtered out. OpenGraph accepts these silently but",
                "they create isolated edges you cannot see in the UI."]
    if conv.warnings:
        out += ["", "## Warnings", ""]
        for warn in sorted(conv.warnings):
            out.append(f"- {warn}")

    out += [
        "",
        "## Read the coverage number honestly",
        "",
        f"{pct:.0f}% of this actor's techniques have a structural equivalent in an",
        "identity graph. That is not a shortfall in the conversion - a",
        "configuration graph describes what is *possible*, so techniques about",
        "execution, evasion, and C2 genuinely have nothing to match against.",
        "The mappable subset is the part you can act on before an intrusion,",
        "which is the entire argument for doing this at all.",
        "",
    ]
    return "\n".join(out)


# ---------------------------------------------------------------------------
def convert(bundle: dict, source_kind: str, include_noisy: bool) -> Converter:
    # A bundle is a JSON object. Anything else - a bare array, a string, a
    # number - is not STIX, and saying so beats an AttributeError.
    if not isinstance(bundle, dict):
        raise ValueError(
            f"expected a STIX bundle object, got {type(bundle).__name__}")

    objects = bundle.get("objects")
    if objects is None:
        objects = [bundle] if bundle.get("type") else []
    elif not isinstance(objects, list):
        raise ValueError("bundle 'objects' must be an array")
    if not objects:
        raise ValueError("no STIX objects found - is this a bundle?")

    # One pass to collect the author identities and split SDOs from SROs.
    # Relationships have to be applied after the nodes exist, but the bundle
    # itself only needs walking once.
    author_ids: set[str] = set()
    sdos: list[dict] = []
    sros: list[dict] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        author = obj.get("created_by_ref")
        if isinstance(author, str):
            author_ids.add(author)
        if "id" not in obj:
            continue
        (sros if obj.get("type") == "relationship" else sdos).append(obj)

    conv = Converter(source_kind, include_noisy, author_ids)
    for obj in sdos:
        conv.add_object(obj)
    for obj in sros:
        conv.add_relationship(obj)
    return conv


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Convert STIX 2.1 CTI bundles to BloodHound OpenGraph payloads.")
    ap.add_argument("bundle", help="path to a STIX 2.1 bundle (JSON)")
    ap.add_argument("-o", "--outdir", default="out", help="output directory")
    ap.add_argument("-s", "--source-kind", default=None,
                    help="OpenGraph metadata.source_kind tag (default: derived from filename)")
    ap.add_argument("--include-noisy", action="store_true",
                    help="keep indicators, observed-data and notes")
    ap.add_argument("--max-hops", type=int, default=DEFAULT_MAX_HOPS, metavar="N",
                    help=f"hop bound on the Tier Zero path query "
                         f"(default {DEFAULT_MAX_HOPS}; 0 for unbounded)")
    ap.add_argument("--indent", type=int, default=None, metavar="N",
                    help="pretty-print the OpenGraph payload with N-space indent. "
                         "Off by default: the payload is uploaded, not read, and "
                         "indenting a large one costs far more than it is worth.")
    args = ap.parse_args()

    if args.max_hops < 0:
        print("error: --max-hops must be 0 or greater", file=sys.stderr)
        return 1

    path = pathlib.Path(args.bundle)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 1

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    except UnicodeDecodeError as exc:
        print(f"error: {path} is not UTF-8 text: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 1

    stem = path.stem.replace(".", "_")
    source_kind = args.source_kind or camel(stem)

    try:
        conv = convert(bundle, source_kind, args.include_noisy)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    dangling = conv.prune_dangling()
    mapped_n = len(conv.mappable)

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    payload_kwargs = ({"indent": args.indent} if args.indent is not None
                      else {"separators": (",", ":")})
    with (outdir / f"{stem}.opengraph.json").open("w", encoding="utf-8") as fh:
        json.dump(conv.payload(), fh, **payload_kwargs)
    (outdir / f"{stem}.customnodes.json").write_text(
        json.dumps(conv.custom_nodes(), indent=2), encoding="utf-8")
    (outdir / f"{stem}.cypher").write_text(
        build_cypher(conv.techniques, source_kind, args.max_hops), encoding="utf-8")
    (outdir / f"{stem}.summary.md").write_text(
        build_summary(conv, mapped_n, dangling, stem), encoding="utf-8")

    print(f"source_kind : {source_kind}")
    print(f"nodes       : {len(conv.nodes)}")
    print(f"edges       : {len(conv.edges)}")
    print(f"techniques  : {len(conv.techniques)} ({mapped_n} map to BloodHound edges)")
    if dangling:
        print(f"pruned      : {dangling} dangling edge(s)")
    print(f"written to  : {outdir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
