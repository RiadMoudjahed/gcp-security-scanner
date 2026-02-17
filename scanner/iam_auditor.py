from enum import member
import json
import subprocess


def get_project_id():
    """Get the current GCP project ID from gcloud config."""
    result = subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip()


def get_iam_policy(project_id):
    """
    Fetch the IAM policy for a project.
    Returns a dict with 'bindings' key.
    """
    result = subprocess.run(
        ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)


PRIMITIVE_ROLES = ["roles/owner", "roles/editor"]

PUBLIC_MEMBERS = ["allUsers", "allAuthenticatedUsers"]


def check_primitive_roles(bindings):
    """
    Rule 1: Flag any user or service account with a primitive role.
    Primitive roles = roles/owner, roles/editor, roles/viewer

    Returns a list of findings.
    """
    findings = []

    for binding in bindings:
        role = binding["role"]
        members = binding["members"]

        if role in PRIMITIVE_ROLES:
            for member in members:
                findings.append({
                    "severity": "HIGH",
                    "rule": "PRIMITIVE_ROLE_ASSIGNED",
                    "member": member,
                    "role": role,
                    "reason": f"{member} has primitive role {role}. Use specific roles instead."
                })

    return findings


def check_public_access(bindings):
    """
    Rule 2: Flag any binding that includes allUsers or allAuthenticatedUsers.
    This means the resource is exposed to the public internet.

    Returns a list of findings.
    """
    findings = []
    
    for binding in bindings:
        role = binding["role"]
        members = binding["members"]

        if member in PUBLIC_MEMBERS:
            for member in members:
                findings.append({
                    "severity": "CRITICAL",
                    "rule": "PUBLIC_ACCESS_GRANTED",
                    "member": member,
                    "role": role,
                    "reason": f"{member} has public access to {role}. Use least privilege instead."
                })
    
    return findings


def check_service_account_primitive_roles(bindings):
    """
    Rule 3: Flag service accounts that have primitive roles.
    Service accounts are non-human identities — they should follow
    least privilege even more strictly than users.

    A service account member starts with: "serviceAccount:"
    """
    findings = []

    for binding in bindings:
        role = binding["role"]
        members = binding["members"]

        for member in members:
            if role in PRIMITIVE_ROLES and member.startswith("serviceAccount:"):
                findings.append({
                "severity": "HIGH",
                "rule": "SA_PRIMITIVE_ROLE",
                "member": member,
                "role": role,
                "reason": f"{member} has primitive role {role}. Use specific roles instead."
        })
                    


    return findings


def analyze_policy(policy):
    """
    Master function. Runs all checks and returns combined findings.
    I give you this one — it shows you how the pieces connect.
    """
    bindings = policy.get("bindings", [])
    
    findings = []
    findings.extend(check_primitive_roles(bindings))
    findings.extend(check_public_access(bindings))
    findings.extend(check_service_account_primitive_roles(bindings))
    
    return findings


def print_report(findings, project_id):
  """Print a clean report."""
    print("══════════════════════════════════════")
    print("GCP IAM Security Audit Report")
    print(f"Project: {project_id}")
    print("══════════════════════════════════════\n")

    for finding in findings:
        print(f"{finding['severity']} {finding['rule']}")
        print(f"Member : {finding['member']}")
        print(f"Role   : {finding['role']}")
        print(f"Reason : {finding['reason']}")
        print("─────────────────────────────────────")

        count_high = 0
        count_critical = 0

        if finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "CRITICAL":
            count_critical += 1
        
        total = count_high + count_critical
        print(f"\nTotal findings: {total}({count_high} HIGH, {count_critical} CRITICAL)")


if __name__ == "__main__":
    project_id = get_project_id()
    policy = get_iam_policy(project_id)
    findings = analyze_policy(policy)
    print_report(findings, project_id)
