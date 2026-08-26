# stixhound

Convert STIX 2.1 CTI bundles into BloodHound OpenGraph payloads — and generate
the Cypher that asks whether the tradecraft in that report is structurally
possible in *your* environment.

The point isn't the picture. Any tool can draw a threat report as a graph. The
point is that the CTI and the environment end up in the same graph, so
"here's what this actor does" becomes a query you can run against yourself.

## Usage

```bash
python stixhound.py samples/owareaper.json -o out/
```

No dependencies beyond the standard library. Python 3.10+.

```
out/<name>.opengraph.json     OpenGraph payload, ready to upload
out/<name>.customnodes.json   Icon definitions for the custom kinds
out/<name>.cypher             Environment join queries
out/<name>.summary.md         What was built, and what was dropped
```

Options:

| Flag | Effect |
|---|---|
| `-o, --outdir` | output directory (default `out`) |
| `-s, --source-kind` | `metadata.source_kind` tag (default: derived from filename) |
| `--include-noisy` | keep indicators, observed-data, notes (dropped by default) |

## Uploading

Verify these endpoints against your BloodHound version — the API has moved
between 8.x and 9.x, and the v9 extension-schema path is different from the
generic-graph path below.

```bash
BH=http://localhost:8080
TOKEN=<JWT>

# 1. Icons for the custom node kinds
curl -X POST $BH/api/v2/custom-nodes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Prefer: wait=30" \
  -d @out/owareaper.customnodes.json

# 2. The graph itself (start / upload / end)
JOB=$(curl -s -X POST $BH/api/v2/file-upload/start \
  -H "Authorization: Bearer $TOKEN" | jq -r '.data.id')

curl -X POST $BH/api/v2/file-upload/$JOB \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @out/owareaper.opengraph.json

curl -X POST $BH/api/v2/file-upload/$JOB/end \
  -H "Authorization: Bearer $TOKEN"
```

Everything is tagged with `metadata.source_kind`, so you can filter or delete
an entire ingest later without touching the rest of your data.

## What it does

**Nodes.** Each STIX SDO becomes a node. `intrusion-set` → `IntrusionSet`,
`attack-pattern` → `AttackPattern`, `course-of-action` → `Control`, and so on.
Every node carries a second kind of `CTI` so you can isolate the imported
subgraph. Properties are flattened to primitives — nested objects are
serialised, mixed arrays are homogenised, nulls are dropped, because the
ingest rejects all three.

**Edges.** STIX relationships become edges (`uses` → `Uses`, `attributed-to`
→ `AttributedTo`). Embedded refs like `created_by_ref` are relationships in
all but name, so they're converted too. Edges whose endpoints got filtered
out are pruned — OpenGraph accepts them silently and you end up with
invisible isolated edges.

**The join.** This is the part that matters. `mappings.py` contains
`TECHNIQUE_EDGE_MAP`: ATT&CK technique → the BloodHound edge kinds that
represent the same capability. T1003.006 maps to `DCSync|GetChanges|
GetChangesAll|AllExtendedRights`. T1649 maps to the ADCS ESC edges. From that,
the tool generates Cypher that finds those edges in your environment — and,
most usefully, the ones that reach Tier Zero.

## Read the coverage number honestly

The summary reports what fraction of the bundle's techniques map to graph
edges. On the sample it's 67%. That is not a conversion failure.

A configuration graph describes what is *possible*. Techniques about
execution, defense evasion, and C2 leave no structural trace in it — they
need telemetry, not topology. The tool lists those separately rather than
inventing bad mappings for them. The mappable subset is the part you can fix
before an intrusion, which is the whole argument.

## Caveats

- **`TECHNIQUE_EDGE_MAP` is opinionated and incomplete.** It's a starting
  point covering techniques with a genuine identity-graph signature. Some
  mappings are judgment calls (T1098 → a broad set of ACL edges will be
  noisy in most environments). Tune it against your own data before trusting
  the output.
- **`HasSPNConfigured` is not a real BloodHound edge.** T1558.003
  (Kerberoasting) is a node property, not an edge, so that mapping will
  return nothing. It's left in deliberately as a marker — the honest fix is
  a property-based query, not an edge match.
- **Tier Zero detection uses `system_tags CONTAINS 'admin_tier_0'`**, which
  is the BloodHound convention but varies by version and by whether you've
  customised Tier Zero. Check query #3 before relying on it.
- **Prose-to-graph is lossy and human.** Deciding that "moved laterally using
  a compromised service account" means `AdminTo` rather than `CanPSRemote` is
  an analyst judgment. This tool converts *structured* STIX; it does not read
  reports. Bundle quality is the ceiling on output quality.
- **The v9 structured-graph path is better than what this does.** This emits
  a generic graph. Defining an extension schema would give you Entity Info
  panels and a more integrated experience. Worth doing if this survives
  contact with real use.
- **Watch the licensing** if you convert other vendors' published reports and
  redistribute the result.
