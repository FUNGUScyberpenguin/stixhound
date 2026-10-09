"""Converter: STIX objects in, OpenGraph nodes and edges out."""

import unittest
from unittest import mock

from ._stix import bundle, obj, rel, stix_id, technique

import stixhound
from stixhound import Converter, convert


def convert_objects(*objects, include_noisy=False, source_kind="Test"):
    """Run a list of STIX objects through the full conversion."""
    return convert(bundle(*objects), source_kind, include_noisy)


class TestNodes(unittest.TestCase):
    def test_node_shape(self):
        actor = obj("intrusion-set", name="TA488", aliases=["Reaper"])
        conv = convert_objects(actor)

        node = conv.nodes[actor["id"]]
        self.assertEqual(node["id"], actor["id"])
        self.assertEqual(node["kinds"], ["IntrusionSet", "CTI"])
        self.assertEqual(node["properties"]["name"], "TA488")
        self.assertEqual(node["properties"]["aliases"], ["Reaper"])
        self.assertEqual(node["properties"]["stix_type"], "intrusion-set")
        self.assertEqual(node["properties"]["cti_source"], "Test")

    def test_every_node_carries_the_cti_kind_second(self):
        conv = convert_objects(obj("malware", name="M"), obj("tool", name="T"))
        for node in conv.nodes.values():
            self.assertEqual(node["kinds"][1], "CTI")
            self.assertLessEqual(len(node["kinds"]), 3)  # OpenGraph maximum

    def test_structural_properties_are_not_copied_into_the_node(self):
        conv = convert_objects(obj("malware", name="M", revoked=False,
                                   granular_markings=[{"marking_ref": "x"}]))
        props = next(iter(conv.nodes.values()))["properties"]
        for key in ("id", "type", "spec_version", "revoked", "granular_markings"):
            self.assertNotIn(key, props)

    def test_null_properties_are_dropped(self):
        conv = convert_objects(obj("malware", name="M", description=None,
                                   malware_types=[]))
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertNotIn("description", props)
        self.assertNotIn("malware_types", props)

    def test_name_falls_back_to_value_then_id(self):
        anon = obj("infrastructure", value="1.2.3.4")
        bare = obj("infrastructure")
        conv = convert_objects(anon, bare)
        self.assertEqual(conv.nodes[anon["id"]]["properties"]["name"], "1.2.3.4")
        self.assertEqual(conv.nodes[bare["id"]]["properties"]["name"], bare["id"])

    def test_unmapped_stix_type_is_camelised_and_warned_about(self):
        conv = convert_objects(obj("x-vendor-thing", name="Odd"))
        node = next(iter(conv.nodes.values()))
        self.assertEqual(node["kinds"][0], "XVendorThing")
        self.assertTrue(any("unmapped STIX type" in w for w in conv.warnings))

    def test_illegal_node_kind_is_skipped_rather_than_emitted(self):
        # Only reachable through a bad mapping table entry, which is exactly
        # the mistake this guard exists to survive.
        with mock.patch.dict(stixhound.STIX_TYPE_KINDS,
                             {"malware": "tag_reserved"}):
            conv = convert_objects(obj("malware", name="M"))
        self.assertEqual(len(conv.nodes), 0)
        self.assertEqual(conv.skipped["malware"], 1)
        self.assertTrue(any("illegal kind" in w for w in conv.warnings))

    def test_repeated_ids_keep_the_last_version_and_are_counted(self):
        first = obj("malware", id=stix_id("malware", 1), name="Old")
        second = obj("malware", id=stix_id("malware", 1), name="New")
        conv = convert_objects(first, second)
        self.assertEqual(len(conv.nodes), 1)
        self.assertEqual(conv.nodes[first["id"]]["properties"]["name"], "New")
        self.assertEqual(conv.duplicates["malware"], 1)

    def test_warnings_are_deduplicated(self):
        conv = convert_objects(*[obj("x-vendor-thing", name=f"n{i}")
                                 for i in range(50)])
        self.assertEqual(len(conv.warnings), 1)


class TestIdentitySplit(unittest.TestCase):
    """STIX reuses `identity` for the report's author and for the victim."""

    def test_author_and_victim_get_different_kinds(self):
        author = obj("identity", name="Research Co", identity_class="organization")
        victim = obj("identity", name="Acme Corp", identity_class="organization")
        report = obj("campaign", name="C", created_by_ref=author["id"])

        conv = convert_objects(author, victim, report)
        self.assertEqual(conv.nodes[author["id"]]["kinds"][0], "Author")
        self.assertEqual(conv.nodes[victim["id"]]["kinds"][0], "Victim")

    def test_authorship_is_detected_regardless_of_object_order(self):
        # The author identity is usually declared first, but nothing requires
        # it - the reference that names it may appear anywhere in the bundle.
        author = obj("identity", name="Research Co")
        report = obj("campaign", name="C", created_by_ref=author["id"])
        conv = convert_objects(report, author)  # reference before declaration
        self.assertEqual(conv.nodes[author["id"]]["kinds"][0], "Author")


class TestNoiseFilter(unittest.TestCase):
    def test_noisy_types_are_dropped_by_default(self):
        conv = convert_objects(obj("malware", name="M"),
                               obj("indicator", name="I", pattern="[x=1]"),
                               obj("note", content="c"))
        self.assertEqual(len(conv.nodes), 1)
        self.assertEqual(conv.skipped["indicator"], 1)
        self.assertEqual(conv.skipped["note"], 1)

    def test_include_noisy_keeps_them(self):
        conv = convert_objects(obj("malware", name="M"),
                               obj("indicator", name="I", pattern="[x=1]"),
                               include_noisy=True)
        self.assertEqual(len(conv.nodes), 2)
        self.assertFalse(conv.skipped)


class TestEdges(unittest.TestCase):
    def test_known_verb_becomes_the_mapped_kind(self):
        a, b = obj("intrusion-set", name="A"), obj("malware", name="B")
        conv = convert_objects(a, b, rel(a["id"], b["id"], "uses"))
        edge = conv.edges[0]
        self.assertEqual(edge["kind"], "Uses")
        self.assertEqual(edge["start"], {"value": a["id"], "match_by": "id"})
        self.assertEqual(edge["end"], {"value": b["id"], "match_by": "id"})
        self.assertEqual(edge["properties"]["cti_source"], "Test")

    def test_unknown_verb_is_camelised(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert_objects(a, b, rel(a["id"], b["id"], "shells-out-to"))
        self.assertEqual(conv.edges[0]["kind"], "ShellsOutTo")

    def test_edge_carries_the_relationship_metadata(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert_objects(a, b, rel(a["id"], b["id"], "uses",
                                         description="d", confidence=80,
                                         start_time="2026-01-01T00:00:00Z"))
        props = conv.edges[0]["properties"]
        self.assertEqual(props["description"], "d")
        self.assertEqual(props["confidence"], 80)
        self.assertEqual(props["start_time"], "2026-01-01T00:00:00Z")

    def test_relationship_without_endpoints_is_dropped(self):
        a = obj("malware", name="A")
        conv = convert_objects(a, rel(a["id"], None), rel(None, a["id"]))
        self.assertEqual(conv.edges, [])

    def test_non_string_verb_is_refused(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert_objects(a, b, rel(a["id"], b["id"], verb=None),
                               )
        self.assertEqual(conv.edges, [])
        self.assertTrue(any("non-string relationship_type" in w
                            for w in conv.warnings))

    def test_exact_duplicate_edges_are_emitted_once(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert_objects(a, b,
                               rel(a["id"], b["id"], "uses"),
                               rel(a["id"], b["id"], "uses"))
        self.assertEqual(len(conv.edges), 1)

    def test_dedupe_handles_array_valued_edge_properties(self):
        # A malformed bundle can put an array where a string belongs, which
        # makes the fast dedupe key unhashable. It must still dedupe, not raise.
        a, b = obj("malware", name="A"), obj("tool", name="B")
        listy = rel(a["id"], b["id"], "uses", description=["one", "two"])
        conv = convert_objects(a, b, listy, dict(listy, id="relationship--other"))
        self.assertEqual(len(conv.edges), 1)
        self.assertEqual(conv.edges[0]["properties"]["description"], ["one", "two"])

    def test_differing_edges_between_the_same_pair_are_both_kept(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert_objects(a, b,
                               rel(a["id"], b["id"], "uses", description="first"),
                               rel(a["id"], b["id"], "uses", description="second"),
                               rel(a["id"], b["id"], "drops"))
        self.assertEqual(len(conv.edges), 3)


class TestEmbeddedRefs(unittest.TestCase):
    def test_created_by_ref_becomes_an_edge(self):
        author = obj("identity", name="Research Co")
        camp = obj("campaign", name="C", created_by_ref=author["id"])
        conv = convert_objects(author, camp)
        kinds = {e["kind"] for e in conv.edges}
        self.assertIn("CreatedBy", kinds)
        self.assertTrue(conv.edges[0]["properties"]["embedded"])

    def test_list_valued_refs_fan_out(self):
        a, b = obj("malware", name="A"), obj("tool", name="B")
        report = obj("report", name="R", object_refs=[a["id"], b["id"]])
        conv = convert_objects(a, b, report)
        contains = [e for e in conv.edges if e["kind"] == "Contains"]
        self.assertEqual({e["end"]["value"] for e in contains}, {a["id"], b["id"]})

    def test_marking_refs_are_dropped_not_turned_into_edges(self):
        conv = convert_objects(obj("malware", name="A",
                                   object_marking_refs=["marking-definition--x"]))
        self.assertEqual(conv.edges, [])

    def test_non_string_ref_entries_are_ignored(self):
        conv = convert_objects(obj("report", name="R",
                                   object_refs=[{"nested": "object"}, 42]))
        self.assertEqual(conv.edges, [])


class TestSightings(unittest.TestCase):
    def test_sighting_becomes_an_edge_per_observer(self):
        mal = obj("malware", name="M")
        v1, v2 = obj("identity", name="V1"), obj("identity", name="V2")
        sighting = obj("sighting", sighting_of_ref=mal["id"], count=3,
                       first_seen="2026-01-02T00:00:00Z",
                       where_sighted_refs=[v1["id"], v2["id"]])
        conv = convert_objects(mal, v1, v2, sighting)

        seen = [e for e in conv.edges if e["kind"] == "Sighted"]
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0]["properties"]["count"], 3)
        # The sighting itself is not a node.
        self.assertNotIn(sighting["id"], conv.nodes)

    def test_sighting_without_observers_produces_nothing(self):
        mal = obj("malware", name="M")
        conv = convert_objects(mal, obj("sighting", sighting_of_ref=mal["id"]))
        self.assertEqual(conv.edges, [])


class TestTechniques(unittest.TestCase):
    def test_mappable_technique_is_annotated(self):
        conv = convert_objects(technique("T1003.006", "DCSync"))
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertEqual(props["attack_id"], "T1003.006")
        self.assertTrue(props["graph_mappable"])
        self.assertIn("DCSync", props["bloodhound_edges"])
        self.assertEqual(conv.techniques, {"T1003.006": "DCSync"})
        self.assertEqual(conv.mappable, {"T1003.006"})

    def test_unmappable_technique_is_recorded_but_not_annotated(self):
        conv = convert_objects(technique("T1059.001", "PowerShell"))
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertFalse(props["graph_mappable"])
        self.assertNotIn("bloodhound_edges", props)
        self.assertIn("T1059.001", conv.techniques)
        self.assertEqual(conv.mappable, set())

    def test_sub_technique_inherits_its_parents_mapping(self):
        conv = convert_objects(technique("T1078.999", "Invented sub-technique"))
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertTrue(props["graph_mappable"])
        self.assertEqual(conv.mappable, {"T1078.999"})

    def test_attack_ids_on_non_techniques_do_not_count_as_coverage(self):
        # course-of-action objects carry Mxxxx mitigation ids.
        mitigation = obj("course-of-action", name="Mit", external_references=[
            {"source_name": "mitre-attack", "external_id": "M1047"}])
        conv = convert_objects(mitigation)
        self.assertEqual(next(iter(conv.nodes.values()))
                         ["properties"]["attack_id"], "M1047")
        self.assertEqual(conv.techniques, {})
        self.assertEqual(conv.mappable, set())

    def test_source_url_is_lifted_out_of_external_references(self):
        conv = convert_objects(technique("T1003.006", "DCSync", external_references=[
            {"source_name": "mitre-attack", "external_id": "T1003.006"},
            {"source_name": "vendor", "url": "https://example.invalid/r"}]))
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertEqual(props["source_url"], "https://example.invalid/r")

    def test_kill_chain_phases_are_flattened_to_names(self):
        conv = convert_objects(technique("T1003.006", "DCSync", kill_chain_phases=[
            {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
            {"kill_chain_name": "mitre-attack"}]))  # malformed, no phase_name
        props = next(iter(conv.nodes.values()))["properties"]
        self.assertEqual(props["kill_chain_phases"], ["credential-access"])


class TestPruneDangling(unittest.TestCase):
    def test_edges_to_filtered_nodes_are_removed(self):
        mal = obj("malware", name="M")
        ind = obj("indicator", name="I", pattern="[x=1]")  # filtered as noise
        conv = convert_objects(mal, ind, rel(ind["id"], mal["id"], "indicates"))

        self.assertEqual(len(conv.edges), 1)
        self.assertEqual(conv.prune_dangling(), 1)
        self.assertEqual(conv.edges, [])

    def test_edges_to_objects_absent_from_the_bundle_are_removed(self):
        mal = obj("malware", name="M")
        conv = convert_objects(mal, rel(mal["id"], stix_id("tool", 99), "uses"))
        self.assertEqual(conv.prune_dangling(), 1)

    def test_prune_is_idempotent(self):
        mal = obj("malware", name="M")
        conv = convert_objects(mal, rel(mal["id"], stix_id("tool", 98), "uses"))
        conv.prune_dangling()
        self.assertEqual(conv.prune_dangling(), 0)


class TestPayloadAndCustomNodes(unittest.TestCase):
    def test_payload_structure(self):
        conv = convert_objects(obj("malware", name="M"))
        payload = conv.payload()
        self.assertEqual(set(payload), {"graph", "metadata"})
        self.assertEqual(set(payload["graph"]), {"nodes", "edges"})
        self.assertEqual(payload["metadata"]["source_kind"], "Test")

    def test_custom_nodes_covers_every_primary_kind(self):
        conv = convert_objects(obj("malware", name="M"),
                               obj("intrusion-set", name="A"))
        custom = conv.custom_nodes()["custom_types"]
        self.assertEqual(set(custom), {"Malware", "IntrusionSet"})
        self.assertEqual(custom["Malware"]["icon"]["type"], "font-awesome")

    def test_unknown_kinds_still_get_a_fallback_icon(self):
        conv = convert_objects(obj("x-vendor-thing", name="Odd"))
        icon = conv.custom_nodes()["custom_types"]["XVendorThing"]["icon"]
        self.assertEqual(icon["name"], "circle-question")


class TestConvertEntryPoint(unittest.TestCase):
    def test_bare_object_without_a_bundle_wrapper(self):
        conv = convert(obj("malware", name="Lonely"), "Test", False)
        self.assertEqual(len(conv.nodes), 1)

    def test_empty_and_shapeless_input_is_refused(self):
        for payload in ({}, {"type": "bundle", "objects": []}, {"objects": []}):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    convert(payload, "Test", False)

    def test_junk_entries_are_skipped_not_fatal(self):
        good = obj("malware", name="M")
        junk = bundle(good, "a string", 42, None, [], {"type": "malware"})
        conv = convert(junk, "Test", False)  # no "id" on the last one
        self.assertEqual(len(conv.nodes), 1)

    def test_relationships_are_applied_after_all_nodes_exist(self):
        # The SRO is declared before both of its endpoints.
        a, b = obj("malware", name="A"), obj("tool", name="B")
        conv = convert(bundle(rel(a["id"], b["id"], "uses"), a, b), "Test", False)
        self.assertEqual(conv.prune_dangling(), 0)
        self.assertEqual(len(conv.edges), 1)


class TestConverterDirectly(unittest.TestCase):
    def test_relationship_objects_are_ignored_by_add_object(self):
        conv = Converter("Test")
        conv.add_object(rel(stix_id("malware", 1), stix_id("tool", 2)))
        self.assertEqual(conv.nodes, {})


if __name__ == "__main__":
    unittest.main()
