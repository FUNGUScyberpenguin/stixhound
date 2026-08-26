"""The summary document.

The coverage percentage is the number a reader will quote, so it gets pinned
here rather than left to whatever the last edit to the mapping table did.
"""

import unittest

from ._stix import bundle, obj, rel, technique

from stixhound import build_summary, convert


def summarise(*objects, include_noisy=False):
    conv = convert(bundle(*objects), "Test", include_noisy)
    dangling = conv.prune_dangling()
    return conv, build_summary(conv, len(conv.mappable), dangling, "test")


class TestCounts(unittest.TestCase):
    def test_headline_numbers_match_the_converter(self):
        a, b = obj("intrusion-set", name="A"), obj("malware", name="B")
        conv, out = summarise(a, b, rel(a["id"], b["id"], "uses"),
                              technique("T1003.006", "DCSync"))
        self.assertIn(f"**nodes**: {len(conv.nodes)}", out)
        self.assertIn(f"**edges**: {len(conv.edges)}", out)
        self.assertIn("**ATT&CK techniques**: 1", out)

    def test_coverage_percentage(self):
        _, out = summarise(technique("T1003.006", "DCSync"),
                           technique("T1059.001", "PowerShell"),
                           technique("T1027", "Obfuscation"),
                           technique("T1021.001", "RDP"))
        self.assertIn("2 of 4 (50%)", out)

    def test_zero_techniques_does_not_divide_by_zero(self):
        _, out = summarise(obj("malware", name="M"))
        self.assertIn("0 of 0 (0%)", out)

    def test_all_mappable_reads_as_one_hundred_percent(self):
        _, out = summarise(technique("T1003.006", "DCSync"))
        self.assertIn("1 of 1 (100%)", out)


class TestSections(unittest.TestCase):
    def test_node_and_edge_kind_breakdowns(self):
        a, b = obj("intrusion-set", name="A"), obj("malware", name="B")
        _, out = summarise(a, b, rel(a["id"], b["id"], "uses"))
        self.assertIn("- `IntrusionSet` x1", out)
        self.assertIn("- `Malware` x1", out)
        self.assertIn("- `Uses` x1", out)

    def test_skipped_section_appears_only_when_something_was_skipped(self):
        _, clean = summarise(obj("malware", name="M"))
        self.assertNotIn("Skipped (noise filter)", clean)

        _, noisy = summarise(obj("malware", name="M"),
                             obj("indicator", name="I", pattern="[x=1]"))
        self.assertIn("Skipped (noise filter)", noisy)
        self.assertIn("- `indicator` x1", noisy)

    def test_pruned_section_reports_the_count(self):
        mal = obj("malware", name="M")
        ind = obj("indicator", name="I", pattern="[x=1]")
        _, out = summarise(mal, ind, rel(ind["id"], mal["id"], "indicates"))
        self.assertIn("Pruned 1 dangling edge(s)", out)

    def test_duplicate_declarations_are_reported(self):
        first = obj("malware", id="malware--dup", name="Old")
        second = obj("malware", id="malware--dup", name="New")
        _, out = summarise(first, second)
        self.assertIn("Re-declared 1 object(s)", out)

    def test_warnings_are_listed_once_each(self):
        _, out = summarise(obj("x-vendor-thing", name="a"),
                           obj("x-vendor-thing", name="b"))
        self.assertEqual(out.count("unmapped STIX type"), 1)

    def test_the_honesty_note_is_always_present(self):
        _, out = summarise(obj("malware", name="M"))
        self.assertIn("Read the coverage number honestly", out)


class TestSampleBundle(unittest.TestCase):
    def test_documented_expectations_for_the_shipped_sample(self):
        # CLAUDE.md and the README both quote these numbers.
        import json

        from ._stix import SAMPLE

        conv = convert(json.loads(SAMPLE.read_text()), "Owareaper", False)
        conv.prune_dangling()
        self.assertEqual(len(conv.nodes), 16)
        self.assertEqual(len(conv.edges), 15)
        self.assertEqual(len(conv.techniques), 6)
        self.assertEqual(len(conv.mappable), 4)

        out = build_summary(conv, len(conv.mappable), 0, "owareaper")
        self.assertIn("4 of 6 (67%)", out)


if __name__ == "__main__":
    unittest.main()
