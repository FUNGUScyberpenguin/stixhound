"""End-to-end runs of the command line, in a subprocess.

These are the slow tests. They exist because the four output files and the
exit codes are the actual interface, and everything else in the suite tests
the pieces behind it.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from ._stix import SAMPLE, bundle, obj, technique

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "stixhound.py"


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              cwd=REPO, capture_output=True, text=True)

    def write_bundle(self, payload, name="input.json"):
        path = self.tmp / name
        path.write_text(json.dumps(payload) if not isinstance(payload, str)
                        else payload, encoding="utf-8")
        return path

    def outputs(self, stem, outdir=None):
        outdir = outdir or (self.tmp / "out")
        return {suffix: (outdir / f"{stem}.{suffix}")
                for suffix in ("opengraph.json", "customnodes.json",
                               "cypher", "summary.md")}


class TestHappyPath(CliTestCase):
    def test_sample_bundle_produces_the_documented_numbers(self):
        result = self.run_cli(SAMPLE, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nodes       : 16", result.stdout)
        self.assertIn("edges       : 15", result.stdout)
        self.assertIn("techniques  : 6 (4 map to BloodHound edges)", result.stdout)
        self.assertIn("source_kind : Owareaper", result.stdout)

    def test_all_four_files_are_written(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        for suffix, path in self.outputs("owareaper").items():
            with self.subTest(suffix=suffix):
                self.assertTrue(path.is_file(), f"{path} missing")
                self.assertTrue(path.stat().st_size > 0)

    def test_output_directory_is_created(self):
        nested = self.tmp / "a" / "b" / "c"
        self.assertEqual(self.run_cli(SAMPLE, "-o", nested).returncode, 0)
        self.assertTrue((nested / "owareaper.opengraph.json").is_file())

    def test_payload_is_valid_json_with_the_source_kind_tag(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        payload = json.loads(self.outputs("owareaper")["opengraph.json"].read_text())
        self.assertEqual(payload["metadata"]["source_kind"], "Owareaper")
        self.assertEqual(len(payload["graph"]["nodes"]), 16)
        self.assertEqual(len(payload["graph"]["edges"]), 15)

    def test_custom_nodes_is_valid_json(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        custom = json.loads(self.outputs("owareaper")["customnodes.json"].read_text())
        self.assertIn("IntrusionSet", custom["custom_types"])

    def test_rerunning_overwrites_cleanly(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        first = self.outputs("owareaper")["opengraph.json"].read_text()
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        self.assertEqual(self.outputs("owareaper")["opengraph.json"].read_text(),
                         first)


class TestOptions(CliTestCase):
    def test_source_kind_override(self):
        result = self.run_cli(SAMPLE, "-o", self.tmp / "out", "-s", "MyIngest")
        self.assertIn("source_kind : MyIngest", result.stdout)
        payload = json.loads(self.outputs("owareaper")["opengraph.json"].read_text())
        self.assertEqual(payload["metadata"]["source_kind"], "MyIngest")
        self.assertIn("MyIngest", self.outputs("owareaper")["cypher"].read_text())

    def test_include_noisy_keeps_the_indicator(self):
        plain = self.run_cli(SAMPLE, "-o", self.tmp / "plain")
        noisy = self.run_cli(SAMPLE, "-o", self.tmp / "noisy", "--include-noisy")
        self.assertIn("nodes       : 16", plain.stdout)
        self.assertIn("nodes       : 17", noisy.stdout)

    def test_payload_is_compact_by_default(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out")
        text = self.outputs("owareaper")["opengraph.json"].read_text()
        self.assertNotIn("\n", text)
        self.assertIn('","', text)  # no space after the separator

    def test_indent_makes_it_readable_without_changing_the_content(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "compact")
        self.run_cli(SAMPLE, "-o", self.tmp / "pretty", "--indent", "2")
        compact = self.outputs("owareaper", self.tmp / "compact")["opengraph.json"]
        pretty = self.outputs("owareaper", self.tmp / "pretty")["opengraph.json"]

        self.assertIn("\n", pretty.read_text())
        self.assertGreater(pretty.stat().st_size, compact.stat().st_size)
        self.assertEqual(json.loads(pretty.read_text()),
                         json.loads(compact.read_text()))

    def test_max_hops_reaches_the_generated_query(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out", "--max-hops", "4")
        self.assertIn("*1..4]", self.outputs("owareaper")["cypher"].read_text())

    def test_max_hops_zero_is_unbounded(self):
        self.run_cli(SAMPLE, "-o", self.tmp / "out", "--max-hops", "0")
        self.assertIn("*1..]", self.outputs("owareaper")["cypher"].read_text())

    def test_negative_max_hops_is_refused(self):
        result = self.run_cli(SAMPLE, "-o", self.tmp / "out", "--max-hops", "-1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("--max-hops", result.stderr)

    def test_filename_drives_the_default_source_kind(self):
        path = self.write_bundle(bundle(obj("malware", name="M")),
                                 name="acme.report-2026.json")
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertIn("source_kind : AcmeReport2026", result.stdout)
        self.assertTrue((self.tmp / "out" / "acme_report-2026.summary.md").is_file())


class TestFailureModes(CliTestCase):
    def test_missing_file(self):
        result = self.run_cli(self.tmp / "nope.json", "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)
        self.assertFalse((self.tmp / "out").exists())

    def test_malformed_json(self):
        path = self.write_bundle("{not json")
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not valid JSON", result.stderr)

    def test_empty_bundle(self):
        path = self.write_bundle({"type": "bundle", "objects": []})
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no STIX objects found", result.stderr)

    def test_json_that_is_not_an_object(self):
        for payload in ("[]", '"a string"', "null", "42"):
            with self.subTest(payload=payload):
                path = self.write_bundle(payload)
                result = self.run_cli(path, "-o", self.tmp / "out")
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.count("Traceback"), 0,
                                 f"crashed instead of failing cleanly:\n{result.stderr}")

    def test_bare_object_without_a_bundle_wrapper_still_works(self):
        path = self.write_bundle(obj("intrusion-set", name="Lonely"))
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nodes       : 1", result.stdout)

    def test_bundle_of_only_unmappable_techniques_is_not_an_error(self):
        path = self.write_bundle(bundle(technique("T1059.001", "PowerShell"),
                                        technique("T1027", "Obfuscation")))
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("techniques  : 2 (0 map to BloodHound edges)", result.stdout)
        cypher = self.outputs("input")["cypher"].read_text()
        self.assertIn("No techniques in this bundle map", cypher)

    def test_dangling_edges_are_reported_on_stdout(self):
        mal = obj("malware", name="M")
        path = self.write_bundle(bundle(mal, {
            "type": "relationship", "spec_version": "2.1",
            "id": "relationship--dangler", "relationship_type": "uses",
            "source_ref": mal["id"], "target_ref": "tool--absent"}))
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pruned      : 1 dangling edge(s)", result.stdout)


class TestNonUtf8Input(CliTestCase):
    def test_invalid_encoding_fails_without_a_traceback(self):
        path = self.tmp / "binary.json"
        path.write_bytes(b'{"type": "bundle", "objects": [\xff\xfe]}')
        result = self.run_cli(path, "-o", self.tmp / "out")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
