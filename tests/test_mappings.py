"""The mapping tables.

`TECHNIQUE_EDGE_MAP` is the part of this repo with actual judgement in it, so
these tests are less about code paths than about keeping the table honest:
every kind it names has to be something the ingest will accept, and the
documented deliberate exceptions have to stay documented.
"""

import unittest

from ._stix import obj  # noqa: F401  (sets sys.path)

from mappings import (
    EMBEDDED_REF_KINDS,
    ICONS,
    NOISY_TYPES,
    RELATIONSHIP_KINDS,
    STIX_TYPE_KINDS,
    TECHNIQUE_EDGE_MAP,
    technique_edges,
)
from stixhound import legal_kind


class TestTechniqueEdges(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(
            technique_edges("T1003.006"),
            ("AllExtendedRights", "DCSync", "GetChanges", "GetChangesAll"),
        )

    def test_falls_back_from_sub_technique_to_parent(self):
        # T1021.004 (SSH) is not mapped, but T1021 is not either - use a pair
        # where the parent genuinely exists.
        self.assertEqual(technique_edges("T1078"), technique_edges("T1078.999"))
        self.assertTrue(technique_edges("T1078.999"))

    def test_own_entry_wins_over_parent(self):
        self.assertIn("T1078", TECHNIQUE_EDGE_MAP)
        self.assertIn("T1078.004", TECHNIQUE_EDGE_MAP)
        self.assertNotEqual(technique_edges("T1078.004"), technique_edges("T1078"))

    def test_unknown_and_empty_inputs_return_nothing(self):
        for value in ("T9999", "T9999.001", "", None, "not-a-technique"):
            with self.subTest(value=value):
                self.assertEqual(technique_edges(value), ())

    def test_results_are_sorted_deduplicated_and_immutable(self):
        for tid in TECHNIQUE_EDGE_MAP:
            with self.subTest(tid=tid):
                edges = technique_edges(tid)
                self.assertIsInstance(edges, tuple)
                self.assertEqual(list(edges), sorted(set(edges)))

    def test_caching_cannot_leak_a_mutable_result(self):
        first = technique_edges("T1187")
        second = technique_edges("T1187")
        self.assertEqual(first, second)
        with self.assertRaises((AttributeError, TypeError)):
            first.append("Injected")  # tuples have no append


class TestTableInvariants(unittest.TestCase):
    """Anything in these tables ends up in a payload or a query verbatim."""

    def test_every_node_kind_is_ingest_legal(self):
        for stix_type, kind in STIX_TYPE_KINDS.items():
            with self.subTest(stix_type=stix_type):
                self.assertTrue(legal_kind(kind), f"{stix_type} -> {kind}")

    def test_every_edge_kind_is_ingest_legal(self):
        for verb, kind in RELATIONSHIP_KINDS.items():
            with self.subTest(verb=verb):
                self.assertTrue(legal_kind(kind), f"{verb} -> {kind}")

    def test_every_embedded_ref_kind_is_ingest_legal(self):
        for prop, kind in EMBEDDED_REF_KINDS.items():
            if kind is None:
                continue  # deliberately dropped
            with self.subTest(prop=prop):
                self.assertTrue(legal_kind(kind), f"{prop} -> {kind}")

    def test_every_bloodhound_edge_name_is_ingest_legal(self):
        for tid, edges in TECHNIQUE_EDGE_MAP.items():
            with self.subTest(tid=tid):
                self.assertTrue(edges, f"{tid} maps to nothing - drop the key instead")
                for edge in edges:
                    self.assertTrue(legal_kind(edge), f"{tid} -> {edge}")

    def test_no_technique_repeats_an_edge(self):
        for tid, edges in TECHNIQUE_EDGE_MAP.items():
            with self.subTest(tid=tid):
                self.assertEqual(len(edges), len(set(edges)))

    def test_technique_ids_look_like_attack_ids(self):
        for tid in TECHNIQUE_EDGE_MAP:
            with self.subTest(tid=tid):
                self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")

    def test_noisy_types_are_all_known_stix_types(self):
        # A typo here silently disables the noise filter for that type.
        unknown = NOISY_TYPES - set(STIX_TYPE_KINDS) - {"marking-definition"}
        self.assertEqual(unknown, set())

    def test_icons_only_describe_kinds_that_can_exist(self):
        producible = set(STIX_TYPE_KINDS.values()) | {"Author"}
        self.assertEqual(set(ICONS) - producible, set())

    def test_icon_entries_are_a_name_and_a_hex_colour(self):
        for kind, entry in ICONS.items():
            with self.subTest(kind=kind):
                name, colour = entry
                self.assertTrue(name and isinstance(name, str))
                self.assertRegex(colour, r"^#[0-9A-Fa-f]{6}$")


class TestDocumentedExceptions(unittest.TestCase):
    """Deliberate compromises. If one of these fails, update the docs too."""

    def test_kerberoasting_still_points_at_the_placeholder_edge(self):
        # HasSPNConfigured is NOT a real BloodHound edge. It is left in as a
        # marker that T1558.003 needs a property-based query path instead.
        # README and CLAUDE.md both say so - change all three together.
        self.assertEqual(technique_edges("T1558.003"), ("HasSPNConfigured",))

    def test_account_manipulation_is_still_the_broad_acl_mapping(self):
        # T1098 -> eight ACL edges is knowingly noisy and called out in the
        # README as a judgement call. Pinned so narrowing it is a decision,
        # not a drive-by edit.
        self.assertEqual(len(technique_edges("T1098")), 8)


if __name__ == "__main__":
    unittest.main()
