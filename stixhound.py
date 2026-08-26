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

from mappings import (
    EMBEDDED_REF_KINDS,
    ICONS,
    NOISY_TYPES,
    RELATIONSHIP_KINDS,
    STIX_TYPE_KINDS,
    TECHNIQUE_EDGE_MAP,
)

KIND_RE = re.compile(r"^[A-Za-z0-9_]+$")

# Properties that are noise, huge, or structurally handled elsewhere.
SKIP_PROPS = {
    "id", "type", "spec_version", "created_by_ref", "object_marking_refs",
    "granular_markings", "extensions", "object_refs", "sample_refs",
    "analysis_sco_refs", "host_vm_ref", "operating_system_ref",
    "external_references", "kill_chain_phases", "relationship_type",
    "source_ref", "target_ref", "defanged", "revoked",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def camel(value: str) -> str:
    """Turn an arbitrary STIX verb into a legal OpenGraph edge kind."""
    parts = re.split(r"[^A-Za-z0-9]+", value)
    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return out or "RelatedTo"


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
        prims = [v for v in value if isinstance(v, (str, int, float, bool))]
        if len(prims) == len(value):
            # homogenise - mixed-type arrays are rejected by the ingest
            if all(isinstance(v, bool) for v in prims):
                return prims
            if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in prims):
                return prims
            return [str(v) for v in prims]
        return json.dumps(value, sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def attack_id(obj: dict) -> str | None:
    """Pull the ATT&CK technique/group ID out of external_references."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-pre-attack",
                                      "mitre-mobile-attack", "mitre-ics-attack"):
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def primary_source(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
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
        self.warnings: list[str] = []
        self.skipped = Counter()

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
            self.warnings.append(f"unmapped STIX type '{stix_type}' -> kind '{kind}'")
        if not KIND_RE.match(kind):
            self.skipped[stix_type] += 1
            self.warnings.append(f"illegal kind derived from '{stix_type}', skipped")
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
                mapped = TECHNIQUE_EDGE_MAP.get(tid) or TECHNIQUE_EDGE_MAP.get(tid.split(".")[0])
                props["graph_mappable"] = bool(mapped)
                if mapped:
                    props["bloodhound_edges"] = sorted(mapped)

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
        self.nodes[obj["id"]] = {
            "id": obj["id"],
            "kinds": [kind, "CTI"],
            "properties": props,
        }

        # embedded refs behave like relationships
        for prop, edge_kind in EMBEDDED_REF_KINDS.items():
            if edge_kind is None or prop not in obj:
                continue
            targets = obj[prop]
            targets = targets if isinstance(targets, list) else [targets]
            for target in targets:
                if isinstance(target, str):
                    self._edge(obj["id"], target, edge_kind, {"embedded": True})

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
        kind = RELATIONSHIP_KINDS.get(verb) or camel(verb)
        if not KIND_RE.match(kind) or kind.startswith("tag_"):
            self.warnings.append(f"illegal edge kind from '{verb}', skipped")
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
        ids = set(self.nodes)
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
def build_cypher(techniques: dict[str, str], source_kind: str) -> str:
    """
    Generate queries that ask the environment graph whether the tradecraft
    described in the CTI bundle is structurally possible here.
    """
    lines = [
        f"// ===================================================================",
        f"// Environment join queries for CTI source: {source_kind}",
        f"// Generated by stixhound. Run in BloodHound's Cypher search.",
        f"// ===================================================================",
        "",
        "// -- 1. Which of this actor's techniques exist in my environment? ---",
    ]

    mapped: list[tuple[str, str, list[str]]] = []
    unmapped: list[tuple[str, str]] = []
    for tid, name in techniques.items():
        edges = TECHNIQUE_EDGE_MAP.get(tid) or TECHNIQUE_EDGE_MAP.get(tid.split(".")[0])
        if edges:
            mapped.append((tid, name, sorted(edges)))
        else:
            unmapped.append((tid, name))

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
        lines += [
            "// -- 2. Full tradecraft overlay: every edge this actor could use ----",
            f"MATCH p = (s)-[r:{rel}]->(t)",
            "RETURN p LIMIT 1000",
            "",
            "// -- 3. Actor tradecraft that reaches Tier Zero ---------------------",
            "//     This is the question worth answering. Everything above is",
            "//     inventory; this is exposure.",
            f"MATCH p = shortestPath((s)-[r:{rel}*1..]->(t))",
            "WHERE COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0'",
            "  AND s <> t",
            "RETURN p LIMIT 250",
            "",
            "// -- 4. Count exposure per technique --------------------------------",
        ]
        for tid, name, edges in mapped:
            rel_i = "|".join(edges)
            lines += [
                f"// {tid} - {name}",
                f"MATCH (s)-[r:{rel_i}]->(t)",
                f"RETURN '{tid}' AS technique, COUNT(r) AS edge_count",
                "",
            ]

    lines += [
        "// -- 5. The CTI subgraph itself (what the bundle described) ---------",
        f"MATCH p = (n:CTI)-[r]->(m:CTI)",
        f"WHERE n.cti_source = '{source_kind}'",
        "RETURN p LIMIT 500",
        "",
        "// -- 6. Controls the reporting says would mitigate this --------------",
        "MATCH p = (c:Control)-[:Mitigates]->(a:AttackPattern)",
        f"WHERE a.cti_source = '{source_kind}'",
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
    if dangling:
        out += ["", f"## Pruned {dangling} dangling edge(s)",
                "", "Endpoints were filtered out. OpenGraph accepts these silently but",
                "they create isolated edges you cannot see in the UI."]
    if conv.warnings:
        out += ["", "## Warnings", ""]
        for warn in sorted(set(conv.warnings)):
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
    objects = bundle.get("objects")
    if objects is None:
        objects = [bundle] if bundle.get("type") else []
    if not objects:
        raise ValueError("no STIX objects found - is this a bundle?")

    author_ids = {
        obj["created_by_ref"] for obj in objects
        if isinstance(obj, dict) and isinstance(obj.get("created_by_ref"), str)
    }

    conv = Converter(source_kind, include_noisy, author_ids)
    for obj in objects:
        if not isinstance(obj, dict) or "id" not in obj:
            continue
        conv.add_object(obj)
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "relationship":
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
    args = ap.parse_args()

    path = pathlib.Path(args.bundle)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 1

    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    stem = path.stem.replace(".", "_")
    source_kind = args.source_kind or camel(stem)

    try:
        conv = convert(bundle, source_kind, args.include_noisy)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    dangling = conv.prune_dangling()

    mapped_n = sum(
        1 for tid in conv.techniques
        if TECHNIQUE_EDGE_MAP.get(tid) or TECHNIQUE_EDGE_MAP.get(tid.split(".")[0])
    )

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    (outdir / f"{stem}.opengraph.json").write_text(
        json.dumps(conv.payload(), indent=2), encoding="utf-8")
    (outdir / f"{stem}.customnodes.json").write_text(
        json.dumps(conv.custom_nodes(), indent=2), encoding="utf-8")
    (outdir / f"{stem}.cypher").write_text(
        build_cypher(conv.techniques, source_kind), encoding="utf-8")
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
