import json
import subprocess


def get_firewall_rules():
    """
    Fetch all firewall rules in the current project.
    Returns a list of firewall rule dicts.
    """
    result = subprocess.run(
        ["gcloud", "compute", "firewall-rules", "list", "--format=json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)


# High-risk ports that should rarely be exposed to the internet
HIGH_RISK_PORTS = ["22", "3389", "3306", "5432", "27017", "6379"]


def check_public_exposure(rules):
    """
    Rule 1: Flag any firewall rule that allows traffic from 0.0.0.0/0 (entire internet).
    
    Returns a list of findings.
    """
    findings = []

    for rule in rules:
        source_ranges = rule.get("sourceRanges", [])
        
        if "0.0.0.0/0" in source_ranges:
            allowed = rule.get("allowed", [])
            ports = []
            
            # Extract port numbers from the allowed protocols
            for protocol in allowed:
                if "ports" in protocol:
                    ports.extend(protocol["ports"])
            
            findings.append({
                "severity": "HIGH",
                "rule": "PUBLIC_FIREWALL_RULE",
                "resource": rule["name"],
                "source": "0.0.0.0/0",
                "ports": ports if ports else ["all"],
                "reason": f"Firewall rule '{rule['name']}' allows traffic from entire internet (0.0.0.0/0)"
            })

    return findings


def check_high_risk_ports(rules):
    """
    Rule 2: Flag firewall rules that expose high-risk ports to the internet.
    
    High-risk ports include:
    - 22 (SSH) — remote access, frequent brute force target
    - 3389 (RDP) — Windows remote desktop, massive attack surface
    - 3306 (MySQL), 5432 (PostgreSQL) — databases should never face internet
    - 27017 (MongoDB), 6379 (Redis) — NoSQL/cache exposed = data breach
    """

    findings = []

    for rule in rules:
        source_ranges = rule.get('sourceRanges', [])

        if "0.0.0.0/0" in source_ranges:
            allowed = rule.get('allowed', [])

            for protocol in allowed:
                ports = protocol.get("ports", [])

                for port in ports:
                    if str(port) in HIGH_RISK_PORTS:
                        findings.append({
                            "severity": "CRITICAL",
                            "rule": "HIGH_RISK_PORT_EXPOSED",
                            "resource": rule["name"],
                            "source": "0.0.0.0/0",
                            "ports": ports if ports else ["all"],
                            "reason": f"Firewall rule '{rule['name']}' exposes high-risk ports {ports} to the internet."
                        })
                        break

    return findings


def check_logging_disabled(rules):
    """
    Rule 3: Flag firewall rules that don't have logging enabled.
    
    Without logs, you can't:
    - Detect attacks
    - Investigate incidents
    - Build threat intelligence
    """

    findings = []

    for rule in rules:
        if not rule.get("logConfig", {}).get("enable") is False:
            findings.append({
                "severity": "MEDIUM",
                "rule": "FIREWALL_LOGGING_DISABLED",
                "resource": rule["name"],
                "reason": f"Firewall rule '{rule['name']}' does not logging (Disabled)."
            })

    return findings


def analyze_firewall(rules):
    """
    Master function. Runs all checks and returns combined findings.
    I give you this one — shows how pieces connect.
    """
    findings = []
    findings.extend(check_public_exposure(rules))
    findings.extend(check_high_risk_ports(rules))
    findings.extend(check_logging_disabled(rules))
    return findings


def print_report(findings):
    
    print("══════════════════════════════════════")
    print("GCP Firewall Security Audit Report")
    print("══════════════════════════════════════\n")

    count_medium = 0
    count_high = 0
    count_critical = 0

    for finding in findings:
        print(f"[{finding['severity']}] {finding['rule']}")
        print(f"Resource: {finding['resource']}")  # Fixed: changed 'resource' to 'finding'

        if "source" in finding:
            print(f"Source: {finding['source']}")

        if "ports" in finding:
            ports_str = ", ".join(map(str, finding["ports"]))
            print(f"Ports: {ports_str}")

        print(f"Reason: {finding['reason']}")  # Fixed: changed 'reason' to 'finding["reason"]'
        print("──────────────────────────────────────")

        if finding["severity"] == "MEDIUM":
            count_medium += 1
        elif finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "CRITICAL":
            count_critical += 1

    total = count_medium + count_high + count_critical
    print(f"\nTotal findings: {total} ({count_medium} MEDIUM, {count_high} HIGH, {count_critical} CRITICAL)")

if __name__ == "__main__":
    rules = get_firewall_rules()
    findings = analyze_firewall(rules)
    print_report(findings)
