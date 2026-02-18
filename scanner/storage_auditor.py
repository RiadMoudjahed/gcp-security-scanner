import json
import subprocess


def get_buckets():
    """
    List all storage buckets in the current project.
    Returns a list of bucket names.
    """
    result = subprocess.run(
        ["gsutil", "ls"],
        capture_output=True,
        text=True
    )
    # gsutil ls returns: gs://bucket-name-1\ngs://bucket-name-2\n
    buckets = [line.strip() for line in result.stdout.strip().split('\n') if line]
    return buckets


def get_bucket_iam_policy(bucket):
    """
    Get the IAM policy for a specific bucket.
    Returns a dict with 'bindings' key (similar to project IAM).
    """
    result = subprocess.run(
        ["gsutil", "iam", "get", bucket],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)


def get_bucket_metadata(bucket):
    """
    Get metadata for a bucket (uniform access, versioning, etc).
    Returns a dict with bucket configuration.
    """
    result = subprocess.run(
        ["gsutil", "uniformbucketlevelaccess", "get", bucket],
        capture_output=True,
        text=True
    )
    
    # Also check versioning
    versioning_result = subprocess.run(
        ["gsutil", "versioning", "get", bucket],
        capture_output=True,
        text=True
    )
    
    return {
        "uniform_access": "enabled" in result.stdout.lower(),
        "versioning": "enabled" in versioning_result.stdout.lower()
    }


PUBLIC_MEMBERS = ["allUsers", "allAuthenticatedUsers"]


def check_public_access(buckets):
    """
    Rule 1: Flag any bucket that grants access to allUsers or allAuthenticatedUsers.
    
    Returns a list of findings.
    """
    findings = []

    for bucket in buckets:
        try:
            policy = get_bucket_iam_policy(bucket)
            bindings = policy.get("bindings", [])
            
            for binding in bindings:
                members = binding.get("members", [])
                role = binding.get("role", "")
                
                for member in members:
                    if member in PUBLIC_MEMBERS:
                        findings.append({
                            "severity": "CRITICAL",
                            "rule": "PUBLIC_BUCKET_ACCESS",
                            "resource": bucket,
                            "member": member,
                            "role": role,
                            "reason": f"Bucket {bucket} grants {role} to {member} (public access)"
                        })
        except Exception as e:
            # Skip buckets we can't access
            continue

    return findings


def check_uniform_access(buckets):
    """
    Rule 2: Flag buckets that don't have uniform bucket-level access enabled.
    
    Uniform access means: only IAM policies control access, not legacy ACLs.
    Without it, you have two security systems to manage = confusion + risk.
    
    YOUR JOB:
    - Loop through buckets
    - Call get_bucket_metadata(bucket) to get metadata
    - Check if metadata["uniform_access"] is False
    - If False → append a finding
    - Severity: "MEDIUM" (not as urgent as public access, but bad practice)
    - Rule name: "UNIFORM_ACCESS_DISABLED"
    
    Hints:
    - Wrap in try/except to skip buckets you can't access
    - Use the same pattern as check_public_access
    """
    findings = []

    for bucket in buckets:
        try:
            metadata = get_bucket_metadata(bucket)
            if not metadata["uniform_access"]:
                findings.append({
                    "severity": "MEDIUM",
                    "rule": "UNIFORM_ACCESS_DISABLED",
                    "resource": bucket,
                    "reason": f"Bucket {bucket} doesn't have a uniform bucket-level access enabled."
                })
        except Exception as e:
            # skip buckets you can't access
            continue

    return findings


def check_versioning(buckets):
    """
    Rule 3: Flag buckets that don't have versioning enabled.
    
    Versioning = keep old versions of files when they're overwritten or deleted.
    Without it: ransomware deletes your files → they're gone forever.
    
    YOUR JOB:
    - Loop through buckets
    - Call get_bucket_metadata(bucket)
    - Check if metadata["versioning"] is False
    - If False → append a finding
    - Severity: "MEDIUM"
    - Rule name: "VERSIONING_DISABLED"
    """
    findings = []

    for bucket in buckets:
        try:
            metadata = get_bucket_metadata(bucket)
            if not metadata["versioning"]:
                findings.append({
                    "severity": "MEDIUM",
                    "rule": "VERSIONING_DISABLED",
                    "resource": bucket,
                    "reason": f"Bucket {bucket} doesn't have versioning enabled."
                })
        except Exception as e:
            # skip buckets you can't access
            continue

    return findings


def analyze_storage(buckets):
    """
    Master function. Runs all checks and returns combined findings.
    """
    findings = []
    findings.extend(check_public_access(buckets))
    findings.extend(check_uniform_access(buckets))
    findings.extend(check_versioning(buckets))
    return findings


def print_report(findings):
    print("══════════════════════════════════════")
    print("GCP Storage Security Audit Report")
    print("══════════════════════════════════════\n")

    count_critical = 0
    count_high = 0
    count_medium = 0

    for finding in findings:
        print(f"[{finding['severity']}] {finding['rule']}")
        print(f"Resource : {finding['resource']}")
        
        if "member" in finding:
            print(f"Member   : {finding['member']}")
        if "role" in finding:
            print(f"Role     : {finding['role']}")
        
        print(f"Reason   : {finding['reason']}")
        print("──────────────────────────────────────")

        if finding["severity"] == "CRITICAL":
            count_critical += 1
        elif finding["severity"] == "HIGH":
            count_high += 1
        elif finding["severity"] == "MEDIUM":
            count_medium += 1

    total = count_critical + count_high + count_medium
    print(f"\nTotal findings: {total} ({count_critical} CRITICAL, {count_high} HIGH, {count_medium} MEDIUM)")

if __name__ == "__main__":
    buckets = get_buckets()
    findings = analyze_storage(buckets)
    print_report(findings)
