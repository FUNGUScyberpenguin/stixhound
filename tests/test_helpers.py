"""The pure functions: kind derivation, property flattening, ref extraction."""

import unittest

from ._stix import obj  # noqa: F401  (sets sys.path for the imports below)

from stixhound import (
    KIND_RE,
    attack_id,
    camel,
    cypher_comment,
    cypher_str,
    flatten,
    legal_kind,
    primary_source,
)


class TestCamel(unittest.TestCase):
    def test_known_stix_verbs(self):
        self.assertEqual(camel("uses"), "Uses")
        self.assertEqual(camel("attributed-to"), "AttributedTo")
        self.assertEqual(camel("communicates-with"), "CommunicatesWith")
        self.assertEqual(camel("x_custom-thing"), "XCustomThing")

    def test_preserves_interior_capitals(self):
        # ATT&CK ids and vendor kinds must survive intact.
        self.assertEqual(camel("T1003"), "T1003")
        self.assertEqual(camel("ADCSESC6a"), "ADCSESC6a")

    def test_empty_and_punctuation_only_fall_back(self):
        self.assertEqual(camel(""), "RelatedTo")
        self.assertEqual(camel("---"), "RelatedTo")
        self.assertEqual(camel("!!! ???"), "RelatedTo")

    def test_output_is_always_a_legal_kind(self):
        # camel() is the last line of defence against a hostile bundle putting
        # something unquotable into a kind name.
        nasty = [
            "with space", "with/slash", "with'quote", 'with"quote',
            "with\nnewline", "héllo-wörld", "42-first", "--",
            "tag_reserved", " null", "a" * 300, "emoji-\U0001f600-here",
        ]
        for value in nasty:
            with self.subTest(value=value):
                self.assertRegex(camel(value), KIND_RE)
                self.assertTrue(legal_kind(camel(value)))


class TestLegalKind(unittest.TestCase):
    def test_accepts_alphanumeric_and_underscore(self):
        for kind in ("Uses", "AttackPattern", "A_B", "T1003", "_leading"):
            self.assertTrue(legal_kind(kind), kind)

    def test_rejects_illegal_characters_and_reserved_prefix(self):
        for kind in ("", "Has-Session", "has session", "tag_zero", "a.b", "é"):
            self.assertFalse(legal_kind(kind), kind)

    def test_reserved_prefix_is_case_sensitive(self):
        # OpenGraph reserves the literal lowercase prefix only.
        self.assertFalse(legal_kind("tag_x"))
        self.assertTrue(legal_kind("Tag_x"))


class TestFlatten(unittest.TestCase):
    def test_none_is_dropped(self):
        self.assertIsNone(flatten(None))

    def test_primitives_pass_through_unchanged(self):
        for value in ("text", 42, 3.5, True, False, 0, "", -1):
            with self.subTest(value=value):
                self.assertEqual(flatten(value), value)
                self.assertIs(type(flatten(value)), type(value))

    def test_empty_list_is_dropped(self):
        # An empty array is not a valid OpenGraph property value.
        self.assertIsNone(flatten([]))

    def test_homogeneous_arrays_survive(self):
        self.assertEqual(flatten(["a", "b"]), ["a", "b"])
        self.assertEqual(flatten([1, 2, 3]), [1, 2, 3])
        self.assertEqual(flatten([1.5, 2.5]), [1.5, 2.5])
        self.assertEqual(flatten([True, False]), [True, False])

    def test_ints_and_floats_together_count_as_homogeneous(self):
        # Both land in the same JSON number type on the wire.
        self.assertEqual(flatten([1, 2.5]), [1, 2.5])

    def test_mixed_primitive_arrays_are_stringified(self):
        self.assertEqual(flatten([1, "two"]), ["1", "two"])

    def test_arrays_containing_nulls_are_serialised_not_stringified(self):
        # A null inside an array is not a primitive, so the whole array is
        # serialised rather than silently losing the null.
        self.assertEqual(flatten(["a", None]), '["a", null]')

    def test_bools_never_mix_with_numbers(self):
        # bool is a subclass of int; the ingest still treats them as distinct.
        self.assertEqual(flatten([True, 1]), ["True", "1"])

    def test_nested_structures_are_serialised_deterministically(self):
        self.assertEqual(flatten({"b": 1, "a": 2}), '{"a": 2, "b": 1}')
        self.assertEqual(flatten([{"a": 1}]), '[{"a": 1}]')
        self.assertEqual(flatten([[1, 2]]), "[[1, 2]]")

    def test_dict_key_order_does_not_change_output(self):
        self.assertEqual(flatten({"a": 1, "b": 2}), flatten({"b": 2, "a": 1}))

    def test_unknown_objects_become_strings(self):
        class Thing:
            def __str__(self):
                return "thing"

        self.assertEqual(flatten(Thing()), "thing")

    def test_result_is_always_ingest_legal(self):
        cases = [None, "s", 1, 1.5, True, [], ["a"], [1, "a"], [[1]], {"k": []},
                 [{"a": 1}], [None], [True, 2, "x"]]
        for case in cases:
            with self.subTest(case=case):
                out = flatten(case)
                if out is None:
                    continue
                if isinstance(out, list):
                    self.assertTrue(out, "empty arrays must be dropped, not emitted")
                    types = {bool if isinstance(v, bool) else type(v) for v in out}
                    self.assertEqual(len(types), 1, f"heterogeneous array {out}")
                    self.assertTrue(all(isinstance(v, (str, int, float, bool))
                                        for v in out))
                else:
                    self.assertIsInstance(out, (str, int, float, bool))


class TestAttackId(unittest.TestCase):
    def test_finds_the_mitre_reference(self):
        self.assertEqual(attack_id(obj("attack-pattern", external_references=[
            {"source_name": "vendor", "url": "https://example.invalid/"},
            {"source_name": "mitre-attack", "external_id": "T1003.006"},
        ])), "T1003.006")

    def test_accepts_every_mitre_domain(self):
        for source in ("mitre-attack", "mitre-pre-attack",
                       "mitre-mobile-attack", "mitre-ics-attack"):
            with self.subTest(source=source):
                self.assertEqual(attack_id(obj("attack-pattern", external_references=[
                    {"source_name": source, "external_id": "T1059"}])), "T1059")

    def test_absent_malformed_and_null_references(self):
        self.assertIsNone(attack_id(obj("malware")))
        self.assertIsNone(attack_id(obj("malware", external_references=None)))
        self.assertIsNone(attack_id(obj("malware", external_references=[])))
        self.assertIsNone(attack_id(obj("malware", external_references=[
            {"source_name": "mitre-attack"}])))  # no external_id
        self.assertIsNone(attack_id(obj("malware", external_references=[
            "not-an-object", 7])))


class TestPrimarySource(unittest.TestCase):
    def test_prefers_the_first_non_mitre_url(self):
        self.assertEqual(primary_source(obj("campaign", external_references=[
            {"source_name": "mitre-attack", "url": "https://attack.mitre.org/"},
            {"source_name": "vendor", "url": "https://example.invalid/r"},
        ])), "https://example.invalid/r")

    def test_falls_back_to_the_source_name(self):
        self.assertEqual(primary_source(obj("campaign", external_references=[
            {"source_name": "vendor"}])), "vendor")

    def test_ignores_mitre_only_and_malformed_references(self):
        self.assertIsNone(primary_source(obj("campaign", external_references=[
            {"source_name": "mitre-attack", "url": "https://attack.mitre.org/"}])))
        self.assertIsNone(primary_source(obj("campaign", external_references=[None])))
        self.assertIsNone(primary_source(obj("campaign")))


class TestCypherEscaping(unittest.TestCase):
    def test_quotes_and_backslashes_are_escaped(self):
        self.assertEqual(cypher_str("T1003"), "T1003")
        self.assertEqual(cypher_str("it's"), "it\\'s")
        self.assertEqual(cypher_str("a\\b"), "a\\\\b")
        # A backslash must not end up escaping the escape of the quote.
        self.assertEqual(cypher_str("a\\'b"), "a\\\\\\'b")

    def test_comments_are_collapsed_to_one_line(self):
        self.assertEqual(cypher_comment("a\nb"), "a b")
        self.assertEqual(cypher_comment("a\r\n  b\tc "), "a b c")
        self.assertNotIn("\n", cypher_comment("MATCH (n) DETACH DELETE n\nRETURN 1"))


if __name__ == "__main__":
    unittest.main()
