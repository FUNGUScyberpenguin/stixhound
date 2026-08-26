"""Builders for minimal-but-valid STIX 2.1 objects.

Tests read better when the object under test shows only the fields that
matter to it, so everything else gets a plausible default here.
"""

from __future__ import annotations

import itertools
import pathlib
import sys

# Import the tool from the repo root regardless of how the suite was invoked.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "samples" / "owareaper.json"

_counter = itertools.count(1)


def stix_id(stix_type: str, seed: int | None = None) -> str:
    """A syntactically valid, deterministic-per-call STIX id."""
    n = next(_counter) if seed is None else seed
    return f"{stix_type}--{n:08x}-0000-4000-8000-000000000000"


def obj(stix_type: str, **fields) -> dict:
    """A STIX SDO. Pass `id=` to pin it, otherwise one is generated."""
    out = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": fields.pop("id", None) or stix_id(stix_type),
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
    }
    out.update(fields)
    return out


def technique(attack_id: str, name: str | None = None, **fields) -> dict:
    """An attack-pattern carrying an ATT&CK external reference."""
    refs = fields.pop("external_references", None) or [
        {"source_name": "mitre-attack", "external_id": attack_id,
         "url": f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}"}
    ]
    return obj("attack-pattern", name=name or f"Technique {attack_id}",
               external_references=refs, **fields)


def rel(source: str, target: str, verb: str = "uses", **fields) -> dict:
    """A STIX SRO."""
    return obj("relationship", relationship_type=verb,
               source_ref=source, target_ref=target, **fields)


def bundle(*objects: dict) -> dict:
    return {
        "type": "bundle",
        "id": stix_id("bundle", 0),
        "objects": list(objects),
    }
