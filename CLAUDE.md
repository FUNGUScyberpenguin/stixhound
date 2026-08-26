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
out/                    Generated. Not committed.
```

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
- No test suite. Edge cases verified manually: empty bundle, malformed JSON,
  missing file, bare object with no bundle wrapper, dangling refs, null
  properties, heterogeneous arrays, illegal relationship verbs. Worth
  formalising into pytest before changing `flatten()` or `prune_dangling()`.
- `MITIGATES` edges from `course-of-action` nodes are imported but unused.
  The interesting direction is control-gap analysis: which mitigations for
  this actor's techniques are *not* in place. Not built yet.

## Conventions

- Standard library only. Do not add dependencies without a strong reason —
  the low-friction install is part of the point.
- OpenGraph constraints are strict and the ingest fails quietly: node/edge
  kinds must match `^[A-Za-z0-9_]+$`, `tag_` is reserved, max 3 kinds per
  node, property values must be primitives or homogeneous primitive arrays,
  no nulls. `flatten()` enforces this — change it carefully.
- Run `python stixhound.py samples/owareaper.json -o out/` after any change.
  Expected: 16 nodes, 15 edges, 6 techniques, 4 mappable.
