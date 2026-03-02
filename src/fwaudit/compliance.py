def check_cis_compliance(parse):
    findings = []

    # CIS ASA Benchmark checks

    # 1. Ensure default deny exists
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[CIS-HIGH] CIS Control: No default deny-all rule found")

    # 2. Ensure no any/any permit rules exist
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[CIS-HIGH] CIS Control: {len(any_any)} any/any permit rule(s) violate least privilege")

    # 3. Ensure all permit rules have logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[CIS-MEDIUM] CIS Control: Permit rule missing logging: {rule.text}")

    return findings


def check_pci_compliance(parse):
    findings = []

    # PCI-DSS Requirement 1 checks

    # 1. No any/any rules (PCI Req 1.3)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) found - direct routes to cardholder data prohibited")

    # 2. All permit rules must log (PCI Req 10.2)
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text}")

    # 3. Explicit deny all must exist (PCI Req 1.2)
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance(parse):
    findings = []

    # NIST SP 800-41 checks

    # 1. Least privilege - no any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any rule(s) violate least privilege principle")

    # 2. Audit trail - logging required
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text}")

    # 3. Boundary protection - deny all must exist
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings