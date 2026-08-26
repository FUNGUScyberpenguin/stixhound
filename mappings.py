"""
Mapping tables for STIX 2.1 -> BloodHound OpenGraph conversion.

Three maps live here:
  1. STIX_TYPE_KINDS      - STIX SDO type   -> OpenGraph node kind
  2. RELATIONSHIP_KINDS   - STIX SRO verb   -> OpenGraph edge kind
  3. TECHNIQUE_EDGE_MAP   - ATT&CK technique -> BloodHound edge kinds

Map 3 is the interesting one. It is the join between "what the adversary
did somewhere else" and "what is structurally possible in your environment."
It is deliberately incomplete and opinionated - tune it against your own
data before trusting it.
"""

# ---------------------------------------------------------------------------
# 1. STIX SDO type -> OpenGraph node kind
#    Edge/node kinds must match ^[A-Za-z0-9_]+$ and must not use the
#    reserved "tag_" prefix.
# ---------------------------------------------------------------------------
STIX_TYPE_KINDS = {
    "intrusion-set": "IntrusionSet",
    "threat-actor": "ThreatActor",
    "campaign": "Campaign",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "AttackPattern",
    "vulnerability": "Vulnerability",
    "infrastructure": "Infrastructure",
    "identity": "Victim",
    "location": "Location",
    "course-of-action": "Control",
    "indicator": "Indicator",
    "observed-data": "ObservedData",
    "malware-analysis": "MalwareAnalysis",
    "report": "CTIReport",
    "grouping": "Grouping",
    "note": "Note",
    "opinion": "Opinion",
}

# STIX types that are structural rather than narrative. Skipped by default
# because they add volume without adding shape to the intrusion story.
NOISY_TYPES = {"indicator", "observed-data", "note", "opinion", "marking-definition"}

# ---------------------------------------------------------------------------
# 2. STIX relationship_type -> OpenGraph edge kind
# ---------------------------------------------------------------------------
RELATIONSHIP_KINDS = {
    "uses": "Uses",
    "targets": "Targets",
    "attributed-to": "AttributedTo",
    "indicates": "Indicates",
    "mitigates": "Mitigates",
    "exploits": "Exploits",
    "compromises": "Compromises",
    "communicates-with": "CommunicatesWith",
    "controls": "Controls",
    "delivers": "Delivers",
    "downloads": "Downloads",
    "drops": "Drops",
    "hosts": "Hosts",
    "owns": "Owns",
    "located-at": "LocatedAt",
    "originates-from": "OriginatesFrom",
    "impersonates": "Impersonates",
    "beacons-to": "BeaconsTo",
    "exfiltrate-to": "ExfiltrateTo",
    "consists-of": "ConsistsOf",
    "variant-of": "VariantOf",
    "related-to": "RelatedTo",
    "derived-from": "DerivedFrom",
    "duplicate-of": "DuplicateOf",
    "authored-by": "AuthoredBy",
    "characterizes": "Characterizes",
    "based-on": "BasedOn",
    "investigates": "Investigates",
    "remediates": "Remediates",
    "has": "Has",
}

# Embedded reference properties that are relationships in all but name.
EMBEDDED_REF_KINDS = {
    "created_by_ref": "CreatedBy",
    "object_refs": "Contains",
    "sample_refs": "HasSample",
    "analysis_sco_refs": "AnalyzedAs",
    "host_vm_ref": "HostedOn",
    "operating_system_ref": "RunsOn",
    "object_marking_refs": None,  # dropped - pure metadata
}

# ---------------------------------------------------------------------------
# 3. ATT&CK technique -> BloodHound edge kinds
#
# This is the join table. When a CTI bundle says an actor used T1003.006,
# these are the edges in YOUR graph that represent the same capability.
#
# Coverage is intentionally limited to techniques that have a *structural*
# signature in an identity graph. Techniques like defense evasion or
# execution leave no trace in a configuration graph and are omitted rather
# than mapped badly.
# ---------------------------------------------------------------------------
TECHNIQUE_EDGE_MAP = {
    # --- Credential access -------------------------------------------------
    "T1003.006": ["DCSync", "GetChanges", "GetChangesAll", "AllExtendedRights"],
    "T1003.001": ["AdminTo", "HasSession"],
    "T1003.002": ["AdminTo"],
    "T1003.003": ["AdminTo", "DCSync"],
    "T1552.001": ["ReadGMSAPassword", "ReadLAPSPassword"],
    "T1555": ["AdminTo", "HasSession"],
    "T1558.001": ["DCSync", "GetChangesAll"],
    "T1558.002": ["AllowedToDelegate"],
    "T1558.003": ["HasSPNConfigured"],
    "T1649": [
        "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC5",
        "ADCSESC6a", "ADCSESC6b", "ADCSESC7", "ADCSESC9a",
        "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
        "Enroll", "ManageCA", "ManageCertificates", "WritePKIEnrollmentFlag",
    ],
    # --- Coercion / relay --------------------------------------------------
    "T1187": [
        "CoerceToTGT", "CoerceAndRelayNTLMToSMB",
        "CoerceAndRelayNTLMToADCS", "CoerceAndRelayNTLMToLDAP",
        "CoerceAndRelayNTLMToLDAPS",
    ],
    "T1557.001": [
        "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToADCS",
        "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS",
    ],
    # --- Lateral movement --------------------------------------------------
    "T1021.001": ["CanRDP"],
    "T1021.002": ["AdminTo"],
    "T1021.006": ["CanPSRemote"],
    "T1047": ["ExecuteDCOM", "AdminTo"],
    "T1550.002": ["AdminTo", "CanRDP", "HasSession"],
    "T1550.003": ["AllowedToDelegate", "AllowedToAct", "HasSession"],
    "T1570": ["AdminTo"],
    # --- Privilege escalation / persistence --------------------------------
    "T1098": [
        "AddMember", "AddSelf", "ForceChangePassword",
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    ],
    "T1098.001": ["AddKeyCredentialLink", "AddSecret", "AddOwner"],
    "T1098.005": ["AddKeyCredentialLink"],
    "T1134.001": ["HasSession"],
    "T1134.005": ["HasSIDHistory"],
    "T1484.001": ["GenericAll", "GenericWrite", "WriteDacl", "GPOAppliesTo"],
    "T1484.002": ["AZAddSecret", "AZOwns", "AZGlobalAdmin"],
    "T1543.003": ["AdminTo"],
    "T1053.005": ["AdminTo"],
    "T1207": ["DCSync", "GetChangesAll"],
    "T1548": ["AdminTo"],
    # --- Discovery (recon that maps to real structure) ---------------------
    "T1069.002": ["MemberOf"],
    "T1482": ["TrustedBy", "SameForestTrust", "CrossForestTrust"],
    "T1087.002": ["MemberOf"],
    # --- Valid accounts / cloud -------------------------------------------
    "T1078": ["HasSession", "MemberOf"],
    "T1078.004": [
        "AZUserAccessAdministrator", "AZOwner", "AZContributor",
        "AZGlobalAdmin", "AZPrivilegedRoleAdmin",
    ],
    "T1136.003": ["AZAddOwner", "AZAddSecret"],
}

# Node kind -> Font Awesome icon + colour, for the /api/v2/custom-nodes endpoint.
ICONS = {
    "IntrusionSet":   ("user-secret",       "#B31B1B"),
    "ThreatActor":    ("user-ninja",        "#8B0000"),
    "Campaign":       ("bullseye",          "#C1440E"),
    "Malware":        ("virus",             "#6A0DAD"),
    "Tool":           ("screwdriver-wrench", "#4B6584"),
    "AttackPattern":  ("crosshairs",        "#E67E22"),
    "Vulnerability":  ("bug",               "#D35400"),
    "Infrastructure": ("server",            "#2C3E50"),
    "Victim":         ("building",          "#7F8C8D"),
    "Location":       ("map-pin",           "#16A085"),
    "Control":        ("shield-halved",     "#27AE60"),
    "CTIReport":      ("file-lines",        "#34495E"),
    "Author":         ("id-card",           "#5D6D7E"),
    "Grouping":       ("layer-group",       "#95A5A6"),
}
