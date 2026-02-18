"""
GCP Security Scanner - Unified Tool
Runs IAM, Firewall, and Storage audits in one command.
"""

from iam_auditor import get_project_id, get_iam_policy, analyze_policy
from firewall_auditor import get_firewall_rules, analyze_firewall
from storage_auditor import get_buckets, analyze_storage


def run_full_scan():
    """
    Run all security audits and return combined findings.
    """
    print("Starting GCP Security Scan...\n")
    
    findings = {
        "iam": [],
        "firewall": [],
        "storage": []
    }
    
    # Run IAM audit
    print("[1/3] Scanning IAM policies...")
    try:
        project_id = get_project_id()
        policy = get_iam_policy(project_id)
        findings["iam"] = analyze_policy(policy)
        print(f"  ✓ Found {len(findings['iam'])} IAM findings")
    except Exception as e:
        print(f"  ✗ IAM scan failed: {e}")
    
    # Run Firewall audit
    print("[2/3] Scanning Firewall rules...")
    try:
        rules = get_firewall_rules()
        findings["firewall"] = analyze_firewall(rules)
        print(f"  ✓ Found {len(findings['firewall'])} Firewall findings")
    except Exception as e:
        print(f"  ✗ Firewall scan failed: {e}")
    
    # Run Storage audit
    print("[3/3] Scanning Storage buckets...")
    try:
        buckets = get_buckets()
        findings["storage"] = analyze_storage(buckets)
        print(f"  ✓ Found {len(findings['storage'])} Storage findings")
    except Exception as e:
        print(f"  ✗ Storage scan failed: {e}")
    
    return findings


def print_unified_report(findings):

    total_iam = len(findings["iam"])
    total_firewall = len(findings["firewall"])
    total_storage = len(findings["storage"])
    total = total_iam + total_firewall + total_storage
    
    print(f"Total findings: {total}")
    print(f"- IAM: {total_iam}")
    print(f"- Firewall: {total_firewall}")
    print(f"- Storage: {total_storage}")

    # Count severities across all findings
    count_critical = 0
    count_high = 0
    count_medium = 0
    
    # Count from IAM findings
    for finding in findings["iam"]:
        if finding["severity"] == "CRITICAL":
            count_critical += 1
        elif finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "MEDIUM":
            count_medium += 1
    
    # Count from Firewall findings
    for finding in findings["firewall"]:
        if finding["severity"] == "CRITICAL":
            count_critical += 1
        elif finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "MEDIUM":
            count_medium += 1
    
    # Count from Storage findings
    for finding in findings["storage"]:
        if finding["severity"] == "CRITICAL":
            count_critical += 1
        elif finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "MEDIUM":
            count_medium += 1
    
    print(f"\nBy severity:")
    print(f"- Critical: {count_critical}")
    print(f"- High: {count_high}")
    print(f"- Medium: {count_medium}")

    # Print IAM findings
    if findings["iam"]:
        print("\n" + "="*60)
        print("IAM FINDINGS:")
        print("="*60)
        for finding in findings["iam"]:
            print(f"\n[{finding['severity']}] {finding['rule']}")
            print(f"Member : {finding['member']}")
            print(f"Role   : {finding['role']}")
            print(f"Reason : {finding['reason']}")
    
    # Print Firewall findings
    if findings["firewall"]:
        print("\n" + "="*60)
        print("FIREWALL FINDINGS:")
        print("="*60)
        for finding in findings["firewall"]:
            print(f"\n[{finding['severity']}] {finding['rule']}")
            print(f"Resource : {finding['resource']}")
            if "source" in finding:
                print(f"Source   : {finding['source']}")
            if "ports" in finding:
                ports_str = ", ".join(map(str, finding["ports"]))
                print(f"Ports    : {ports_str}")
            print(f"Reason   : {finding['reason']}")
    
    # Print Storage findings
    if findings["storage"]:
        print("\n" + "="*60)
        print("STORAGE FINDINGS:")
        print("="*60)
        for finding in findings["storage"]:
            print(f"\n[{finding['severity']}] {finding['rule']}")
            print(f"Resource : {finding['resource']}")
            if "member" in finding:
                print(f"Member   : {finding['member']}")
            if "role" in finding:
                print(f"Role     : {finding['role']}")
            print(f"Reason   : {finding['reason']}")

if __name__ == "__main__":
    findings = run_full_scan()
    print_unified_report(findings)
