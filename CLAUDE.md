# CLAUDE.md

Context for Claude Code working in this repo.

## What this is

`stixhound` converts STIX 2.1 CTI bundles into BloodHound OpenGraph payloads,
and generates Cypher that joins the imported CTI against the user's own
environment graph.

The thesis: most CTI is prose. The topology is the actual content and every
reader reconstructs it in their head. If the CTI and the environment live in
the same graph, "here's what this actor does" becomes a query you can run
against yourself — and the answer is a short list of real exposures rather
than a wall of paths.

## Layout

```
stixhound.py            CLI + converter. Single entry point.
mappings.py             Three lookup tables. This is where the thinking is.
samples/owareaper.json  Synthetic STIX bundle for testing.
tests/                  unittest suite. Stdlib only; pytest collects it too.
out/                    Generated. Not committed.
```

Read `TECHNIQUE_EDGE_MAP` through `mappings.technique_edges()`, never by
indexing it directly. The sub-technique -> parent fallback lives in that
function, and three call sites used to reimplement it.

## The important part

`TECHNIQUE_EDGE_MAP` in `mappings.py` maps ATT&CK technique IDs to BloodHound
edge kinds. This is the product; everything else is plumbing. When editing it:

- Only map techniques with a genuine **structural** signature in an identity
  graph. Execution, defense evasion, and C2 techniques leave no trace in a
  configuration graph. Leaving them unmapped is correct — the tool reports
  them separately, and the coverage percentage is meant to be honest.
- Prefer precision over coverage. A noisy mapping (T1098 → eight ACL edge
  kinds) is worse than no mapping, because it destroys the signal that makes
  the output worth reading.
- Verify edge names against the BloodHound version in use. Edge kinds change
  between releases, especially the ADCS ESC and NTLM relay families.

## Known issues / open work

- `HasSPNConfigured` (T1558.003) is **not a real edge**. Kerberoasting is a
  node property. Left in as a deliberate marker; the fix is a property-based
  query path, which the current architecture doesn't support.
- Tier Zero detection assumes `system_tags CONTAINS 'admin_tier_0'`. Varies
  by version and by customised Tier Zero definitions.
- Emits a **generic** OpenGraph. The v9 extension-schema path would give
  Entity Info panels and better UI integration. Worth doing if this gets real
  use.
- `MITIGATES` edges from `course-of-action` nodes are imported but unused.
  The interesting direction is control-gap analysis: which mitigations for
  this actor's techniques are *not* in place. Not built yet.

## Tests

```bash
python -m unittest discover        # what CI should run; no dependencies
python -m unittest tests.test_cli  # the slow ones, ~1s
```

`tests/_stix.py` has builders for minimal STIX objects — use them rather than
pasting bundle literals into tests.

Two suites are load-bearing beyond their own code:

- `tests/test_opengraph_contract.py` asserts the ingest rules (legal kinds,
  <=3 kinds per node, no nulls, homogeneous primitive arrays) against a
  deliberately hostile bundle. If you change `flatten()` or `payload()`,
  this is the one that catches a payload BloodHound would drop silently.
- `tests/test_mappings.py` pins the documented compromises — the
  `HasSPNConfigured` marker and the eight-edge `T1098` mapping. They are meant
  to fail if someone changes them, so the docs get updated in the same commit.

`tests/test_summary.py` pins the sample expectations (16/15/6/4, 67%) that
this file and the README both quote.

## Conventions

- Standard library only. Do not add dependencies without a strong reason —
  the low-friction install is part of the point. The test suite is `unittest`
  for the same reason; pytest collects it but is not required.
- OpenGraph constraints are strict and the ingest fails quietly: node/edge
  kinds must match `^[A-Za-z0-9_]+$`, `tag_` is reserved, max 3 kinds per
  node, property values must be primitives or homogeneous primitive arrays,
  no nulls. `flatten()` enforces this — change it carefully.
- The OpenGraph payload is written compact; `--indent N` opts back in. On a
  16k-object bundle, `indent=2` serialisation measured 0.36s against 0.07s
  compact, and 12.5MB against 7.5MB, for a file that is POSTed rather than
  read.
- Edge dedupe (`_prop_key`) is on the hot path. Its fast path is the raw
  items tuple; the sorted/normalised form is a fallback for unhashable
  values. Sorting unconditionally measured ~30% of total conversion time.
- The generated Tier Zero query is hop-bounded (`--max-hops`, default 6).
  Unbounded `*1..` shortestPath does not return on a real AD graph.
- Anything from the bundle that lands in generated Cypher goes through
  `cypher_str()` (string literals) or `cypher_comment()` (comments). Technique
  ids and names are attacker-influenced text.
- Run `python stixhound.py samples/owareaper.json -o out/` after any change.
  Expected: 16 nodes, 15 edges, 6 techniques, 4 mappable. Then
  `python -m unittest discover`.
