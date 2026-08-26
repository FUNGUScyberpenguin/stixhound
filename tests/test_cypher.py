"""The generated join queries.

Nothing here executes Cypher. These tests check the two things that can go
wrong without a database: the query text is well-formed, and untrusted text
from the bundle cannot escape the literal or comment it lands in.
"""

import unittest

from ._stix import obj  # noqa: F401  (sets sys.path)

from mappings import technique_edges
from stixhound import DEFAULT_MAX_HOPS, build_cypher


class TestStructure(unittest.TestCase):
    def test_header_names_the_source_kind(self):
        out = build_cypher({}, "Owareaper")
        self.assertIn("CTI source: Owareaper", out)

    def test_mapped_technique_gets_its_own_query(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test")
        self.assertIn("// T1003.006 - DCSync", out)
        for edge in technique_edges("T1003.006"):
            self.assertIn(edge, out)

    def test_unmapped_techniques_are_listed_as_comments_only(self):
        out = build_cypher({"T1059.001": "PowerShell"}, "Test")
        self.assertIn("no structural equivalent", out)
        self.assertIn("//    T1059.001 - PowerShell", out)
        # It must not become a relationship pattern.
        self.assertNotIn("[r:T1059", out)

    def test_a_fully_unmapped_bundle_says_so_instead_of_emitting_nothing(self):
        out = build_cypher({"T1059.001": "PowerShell"}, "Test")
        self.assertIn("No techniques in this bundle map to structural graph edges",
                      out)
        self.assertNotIn("shortestPath", out)

    def test_overlay_query_unions_every_mapped_edge(self):
        out = build_cypher({"T1003.006": "DCSync", "T1021.001": "RDP"}, "Test")
        expected = sorted(set(technique_edges("T1003.006"))
                          | set(technique_edges("T1021.001")))
        self.assertIn("|".join(expected), out)

    def test_the_cti_subgraph_and_control_queries_are_always_present(self):
        out = build_cypher({}, "Test")
        self.assertIn("MATCH p = (n:CTI)-[r]->(m:CTI)", out)
        self.assertIn("(c:Control)-[:Mitigates]->(a:AttackPattern)", out)

    def test_every_line_is_cypher_or_a_comment(self):
        out = build_cypher({"T1003.006": "DCSync", "T1059.001": "PowerShell"},
                           "Test")
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            self.assertRegex(stripped, r"^(MATCH|WHERE|RETURN|WITH|UNWIND|CALL)\b",
                             f"stray line: {line!r}")


class TestHopBound(unittest.TestCase):
    def test_default_is_bounded(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test")
        self.assertIn(f"*1..{DEFAULT_MAX_HOPS}]", out)
        self.assertNotIn("*1..]", out)

    def test_explicit_bound_is_honoured(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test", max_hops=3)
        self.assertIn("*1..3]", out)
        self.assertIn("Bounded to 3 hops", out)

    def test_zero_means_unbounded_and_says_so(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test", max_hops=0)
        self.assertIn("*1..]", out)
        self.assertIn("UNBOUNDED", out)

    def test_tier_zero_is_anchored_before_the_variable_length_expansion(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test")
        anchor = out.index("CONTAINS 'admin_tier_0'")
        expand = out.index("shortestPath")
        self.assertLess(anchor, expand,
                        "Tier Zero must be matched before the path expansion")


class TestUntrustedInput(unittest.TestCase):
    """Technique ids and names come from the bundle, which is not ours."""

    def test_technique_id_is_emitted_as_a_literal(self):
        out = build_cypher({"T1003.006": "DCSync"}, "Test")
        self.assertIn("'T1003.006' AS technique", out)

    def test_quote_in_a_technique_id_cannot_break_out_of_the_literal(self):
        # Resolves through its parent T1078, so it reaches the per-technique
        # count query where the id is interpolated into a string literal.
        hostile = "T1078.004' RETURN 1 //"
        out = build_cypher({hostile: "x"}, "Test")
        self.assertIn("'T1078.004\\' RETURN 1 //' AS technique", out)
        self.assertNotIn("'T1078.004' RETURN 1 //' AS technique", out)

    def test_hostile_unmappable_id_stays_in_a_comment(self):
        hostile = "T9999' RETURN 1 //"
        out = build_cypher({hostile: "x"}, "Test")
        for line in out.splitlines():
            if "RETURN 1" in line:
                self.assertTrue(line.strip().startswith("//"), line)

    def test_newline_in_a_technique_name_stays_inside_the_comment(self):
        out = build_cypher({"T1003.006": "DCSync\nMATCH (n) DETACH DELETE n"},
                           "Test")
        for line in out.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
                self.assertNotIn("DETACH DELETE", stripped)

    def test_quote_in_the_source_kind_is_escaped(self):
        out = build_cypher({}, "It's")
        self.assertIn("n.cti_source = 'It\\'s'", out)


if __name__ == "__main__":
    unittest.main()
