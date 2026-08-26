"""The OpenGraph ingest contract.

The ingest fails *quietly* on a malformed payload, so a bad node looks like a
missing node rather than an error. These are the rules, asserted against a
deliberately hostile bundle so the checks have something to bite on.
"""

import json
import unittest

from ._stix import SAMPLE, bundle, obj, rel, technique

from stixhound import convert, legal_kind

PRIMITIVES = (str, int, float, bool)

MAX_KINDS_PER_NODE = 3


def assert_payload_is_legal(case, payload):
    node_ids = set()
    for node in payload["graph"]["nodes"]:
        case.assertEqual(set(node), {"id", "kinds", "properties"})
        case.assertTrue(node["id"])
        node_ids.add(node["id"])

        case.assertTrue(node["kinds"], "a node needs at least one kind")
        case.assertLessEqual(len(node["kinds"]), MAX_KINDS_PER_NODE)
        for kind in node["kinds"]:
            case.assertTrue(legal_kind(kind), f"illegal node kind {kind!r}")

        for key, value in node["properties"].items():
            assert_property_is_legal(case, f"node {node['id']}.{key}", value)

    for edge in payload["graph"]["edges"]:
        case.assertEqual(set(edge), {"kind", "start", "end", "properties"})
        case.assertTrue(legal_kind(edge["kind"]), f"illegal edge kind {edge['kind']!r}")
        for end in ("start", "end"):
            case.assertEqual(set(edge[end]), {"value", "match_by"})
            case.assertEqual(edge[end]["match_by"], "id")
            case.assertTrue(edge[end]["value"])
        for key, value in edge["properties"].items():
            assert_property_is_legal(case, f"edge {edge['kind']}.{key}", value)

    return node_ids


def assert_property_is_legal(case, where, value):
    case.assertIsNotNone(value, f"{where} is null")
    if isinstance(value, list):
        case.assertTrue(value, f"{where} is an empty array")
        types = {bool if isinstance(v, bool) else type(v) for v in value}
        case.assertEqual(len(types), 1, f"{where} is a heterogeneous array")
        for item in value:
            case.assertIsInstance(item, PRIMITIVES, f"{where} holds a non-primitive")
    else:
        case.assertIsInstance(value, PRIMITIVES, f"{where} is not a primitive")


HOSTILE = bundle(
    obj("identity", id="identity--author", name="Author Co"),
    obj("malware", name="Nulls", description=None, x_empty=[],
        x_nested={"a": {"b": [1, 2]}}, x_mixed=[1, "two", True],
        x_deep=[[1], [2]], created_by_ref="identity--author"),
    obj("x-weird type/with punctuation!", name="Camelised"),
    obj("infrastructure", value="1.2.3.4"),  # no name at all
    technique("T1003.006", "DCSync\nwith a newline"),
    technique("T9999.001", "Unmapped"),
    obj("report", name="R", object_refs=["malware--missing", 42, None]),
    obj("sighting", sighting_of_ref="identity--author",
        where_sighted_refs=["identity--author"]),
    rel("identity--author", "malware--missing", "weird verb/here"),
    rel("identity--author", None, "uses"),
    rel("identity--author", "identity--author", "uses", description=None),
)


class TestPayloadContract(unittest.TestCase):
    def test_sample_bundle_payload_is_legal(self):
        conv = convert(json.loads(SAMPLE.read_text()), "Owareaper", False)
        conv.prune_dangling()
        assert_payload_is_legal(self, conv.payload())

    def test_hostile_bundle_payload_is_legal(self):
        conv = convert(HOSTILE, "Hostile", False)
        conv.prune_dangling()
        assert_payload_is_legal(self, conv.payload())

    def test_hostile_bundle_with_noise_included_is_legal(self):
        conv = convert(HOSTILE, "Hostile", True)
        conv.prune_dangling()
        assert_payload_is_legal(self, conv.payload())

    def test_no_edge_survives_pruning_with_a_missing_endpoint(self):
        conv = convert(HOSTILE, "Hostile", False)
        conv.prune_dangling()
        ids = set(conv.nodes)
        for edge in conv.edges:
            self.assertIn(edge["start"]["value"], ids)
            self.assertIn(edge["end"]["value"], ids)

    def test_payload_round_trips_through_json(self):
        conv = convert(HOSTILE, "Hostile", False)
        conv.prune_dangling()
        payload = conv.payload()
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_custom_nodes_declares_an_icon_for_every_primary_kind(self):
        conv = convert(HOSTILE, "Hostile", False)
        custom = conv.custom_nodes()["custom_types"]
        for node in conv.payload()["graph"]["nodes"]:
            self.assertIn(node["kinds"][0], custom)


if __name__ == "__main__":
    unittest.main()
