import pytest
from scanner.iam_auditor import (
    analyze_policy,
    check_primitive_roles,
    check_public_access,
    check_service_account_primitive_roles
)


class TestIAMBasicRisks:
    """Tests for high-severity IAM misconfigurations"""

    def test_detects_primitive_role_on_user(self):
        """
        GIVEN: A user account has roles/owner
        WHEN:  We analyze the IAM policy
        THEN:  The auditor flags it as HIGH risk
        """
        fake_policy = {
            "bindings": [{
                "role": "roles/owner",
                "members": ["user:admin@example.com"]
            }]
        }

        findings = analyze_policy(fake_policy)
        
        assert len(findings) > 0
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["rule"] == "PRIMITIVE_ROLE_ASSIGNED"
        assert findings[0]["member"] == "user:admin@example.com"

    def test_detects_allUsers_binding(self):
        """
        GIVEN: A resource has allUsers as a member
        WHEN:  We analyze the policy
        THEN:  The auditor flags it as CRITICAL — public exposure
        """
        fake_policy = {
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"]
            }]
        }

        findings = analyze_policy(fake_policy)
        
        assert len(findings) > 0
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["rule"] == "PUBLIC_ACCESS_GRANTED"
        assert findings[0]["member"] == "allUsers"

    def test_detects_service_account_with_owner_role(self):
        """
        GIVEN: A service account has roles/editor
        WHEN:  We analyze the policy
        THEN:  The auditor flags it — service accounts shouldn't have primitive roles
        """
        fake_policy = {
            "bindings": [{
                "role": "roles/editor",
                "members": ["serviceAccount:my-sa@project.iam.gserviceaccount.com"]
            }]
        }

        findings = analyze_policy(fake_policy)
        
        # This will trigger BOTH rules: PRIMITIVE_ROLE_ASSIGNED and SA_PRIMITIVE_ROLE
        assert len(findings) == 2
        assert any(f["rule"] == "SA_PRIMITIVE_ROLE" for f in findings)
        assert all(f["severity"] == "HIGH" for f in findings)


class TestIAMEdgeCases:
    """Edge cases and validation tests"""

    def test_empty_policy_returns_no_findings(self):
        """
        GIVEN: An IAM policy with no bindings (empty project)
        WHEN:  We analyze it
        THEN:  We get back an empty findings list, no crash
        """
        fake_policy = {"bindings": []}
        
        findings = analyze_policy(fake_policy)
        
        assert findings == []
        assert len(findings) == 0

    def test_multiple_bindings_flags_all_violations(self):
        """
        GIVEN: A policy with 3 bindings, 2 of which are violations
        WHEN:  We analyze it
        THEN:  We get exactly 2 findings back (or more due to overlapping rules)
        """
        fake_policy = {
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",  # safe
                    "members": ["user:safe@example.com"]
                },
                {
                    "role": "roles/owner",  # violation: primitive role
                    "members": ["user:admin@example.com"]
                },
                {
                    "role": "roles/compute.viewer",  # violation: public access
                    "members": ["allUsers"]
                }
            ]
        }

        findings = analyze_policy(fake_policy)
        
        # Should find at least the 2 violations
        assert len(findings) >= 2
        # Check both rule types are present
        rules = [f["rule"] for f in findings]
        assert "PRIMITIVE_ROLE_ASSIGNED" in rules
        assert "PUBLIC_ACCESS_GRANTED" in rules

    def test_legitimate_role_returns_no_finding(self):
        """
        GIVEN: A user has a specific, scoped role
        WHEN:  We analyze the policy
        THEN:  No findings — this is legitimate least-privilege
        """
        fake_policy = {
            "bindings": [{
                "role": "roles/storage.objectViewer",  # specific, not primitive
                "members": ["user:viewer@example.com"]  # not public, not SA
            }]
        }

        findings = analyze_policy(fake_policy)
        
        assert len(findings) == 0
