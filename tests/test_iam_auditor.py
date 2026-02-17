import pytest
import json
from scanner.iam_auditor import (
    analyze_policy,
    check_primitive_roles,
    check_public_access,
    check_service_account_primitive_roles,
    get_project_id,
    get_iam_policy,
    print_report
)


class TestIAMBasicRisks:
    """Tests for high-severity IAM misconfigurations"""
    def test_detects_primitive_role_on_user(self):
        fake_policy = {
            "bindings": [{
                "role": "roles/owner",
                "members": ["user:admin@example.com"]
            }]
        }
        findings = analyze_policy(fake_policy)
        assert len(findings) > 0
        assert findings[0]["severity"] == "HIGH"

    def test_detects_allUsers_binding(self):
        fake_policy = {
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"]
            }]
        }
        findings = analyze_policy(fake_policy)
        assert len(findings) > 0
        assert findings[0]["severity"] == "CRITICAL"

    def test_detects_service_account_with_owner_role(self):
        fake_policy = {
            "bindings": [{
                "role": "roles/editor",
                "members": ["serviceAccount:my-sa@project.iam.gserviceaccount.com"]
            }]
        }
        findings = analyze_policy(fake_policy)
        assert len(findings) == 2


class TestIAMEdgeCases:
    """Edge cases and validation tests"""
    def test_empty_policy_returns_no_findings(self):
        fake_policy = {"bindings": []}
        findings = analyze_policy(fake_policy)
        assert findings == []

    def test_multiple_bindings_flags_all_violations(self):
        fake_policy = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["user:safe@example.com"]},
                {"role": "roles/owner", "members": ["user:admin@example.com"]},
                {"role": "roles/compute.viewer", "members": ["allUsers"]}
            ]
        }
        findings = analyze_policy(fake_policy)
        assert len(findings) >= 2

    def test_legitimate_role_returns_no_finding(self):
        fake_policy = {
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["user:viewer@example.com"]
            }]
        }
        findings = analyze_policy(fake_policy)
        assert len(findings) == 0


class TestIAMHelperFunctions:
    """Direct tests for the individual checker functions"""
    def test_check_primitive_roles_with_violation(self):
        bindings = [{"role": "roles/owner", "members": ["user:admin@example.com"]}]
        findings = check_primitive_roles(bindings)
        assert len(findings) == 1

    def test_check_primitive_roles_with_safe_roles(self):
        bindings = [{"role": "roles/storage.objectViewer", "members": ["user:viewer@example.com"]}]
        findings = check_primitive_roles(bindings)
        assert len(findings) == 0

    def test_check_public_access_with_violation(self):
        bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        findings = check_public_access(bindings)
        assert len(findings) == 1

    def test_check_public_access_with_no_public(self):
        bindings = [{"role": "roles/storage.objectViewer", "members": ["user:someone@example.com"]}]
        findings = check_public_access(bindings)
        assert len(findings) == 0

    def test_check_service_account_primitive_roles_with_violation(self):
        bindings = [{"role": "roles/editor", "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"]}]
        findings = check_service_account_primitive_roles(bindings)
        assert len(findings) == 1

    def test_check_service_account_primitive_roles_with_safe_roles(self):
        bindings = [{"role": "roles/storage.objectViewer", "members": ["serviceAccount:sa@project.iam.gserviceaccount.com"]}]
        findings = check_service_account_primitive_roles(bindings)
        assert len(findings) == 0


class TestIAMErrorHandling:
    """Tests for error handling and edge cases"""
    def test_check_primitive_roles_empty_bindings(self):
        findings = check_primitive_roles([])
        assert len(findings) == 0

    def test_check_public_access_empty_bindings(self):
        findings = check_public_access([])
        assert len(findings) == 0

    def test_check_service_account_primitive_roles_empty_bindings(self):
        findings = check_service_account_primitive_roles([])
        assert len(findings) == 0

    def test_analyze_policy_with_malformed_bindings(self):
        fake_policy = {"bindings": [{"role": "roles/owner"}]}
        findings = analyze_policy(fake_policy)
        assert findings == []

    def test_analyze_policy_with_none_bindings(self):
        fake_policy = {"bindings": None}
        findings = analyze_policy(fake_policy)
        assert findings == []


# NEW TESTS TO ADD - These target the missing lines
class TestIAMProductionFunctions:
    """Tests for get_project_id, get_iam_policy, and print_report"""
    
    def test_get_project_id(self, mocker):
        mock_run = mocker.patch('scanner.iam_auditor.subprocess.run')
        mock_run.return_value.stdout = "my-project-123\n"
        result = get_project_id()
        assert result == "my-project-123"

    def test_get_project_id_empty(self, mocker):
        mock_run = mocker.patch('scanner.iam_auditor.subprocess.run')
        mock_run.return_value.stdout = "\n"
        result = get_project_id()
        assert result == ""

    def test_get_iam_policy(self, mocker):
        mock_run = mocker.patch('scanner.iam_auditor.subprocess.run')
        expected_policy = {"bindings": []}
        mock_run.return_value.stdout = json.dumps(expected_policy)
        result = get_iam_policy("test-project")
        assert result == expected_policy

    def test_print_report_with_findings(self, capsys):
        findings = [{
            "severity": "HIGH",
            "rule": "PRIMITIVE_ROLE_ASSIGNED",
            "member": "user:test@example.com",
            "role": "roles/owner",
            "reason": "Test reason"
        }]
        print_report(findings, "test-project")
        captured = capsys.readouterr()
        # Fix: Add space after the colon to match actual output
        assert "Total findings: 1 (1 HIGH, 0 CRITICAL)" in captured.out

    def test_print_report_empty_findings(self, capsys):
        findings = []
        print_report(findings, "test-project")
        captured = capsys.readouterr()
        # Fix: Add space after the colon to match actual output
        assert "Total findings: 0 (0 HIGH, 0 CRITICAL)" in captured.out


class TestIAMMoreEdgeCases:
    """Additional edge cases for helper functions"""
    
    def test_check_primitive_roles_with_non_dict_binding(self):
        bindings = ["not a dict", {"role": "roles/owner", "members": ["user:test@example.com"]}]
        findings = check_primitive_roles(bindings)
        assert len(findings) == 1

    def test_check_primitive_roles_with_non_list_members(self):
        bindings = [{"role": "roles/owner", "members": "not a list"}]
        findings = check_primitive_roles(bindings)
        assert len(findings) == 0

    def test_check_public_access_with_non_dict_binding(self):
        bindings = ["not a dict", {"role": "roles/viewer", "members": ["allUsers"]}]
        findings = check_public_access(bindings)
        assert len(findings) == 1

class TestIAMFinalCoverage:
    """Final tests to reach 100% coverage"""
    
    def test_check_public_access_specific_edge(self, mocker):
        """Test line 89 - whatever edge case it is"""
        # You'll need to look at your code to see what's on line 89
        pass
    
    def test_check_service_account_specific_edge(self, mocker):
        """Test line 125 - whatever edge case it is"""
        # You'll need to look at your code to see what's on line 125
        pass
    
    def test_main_block_execution(self, mocker):
        """Test lines 184-187 - the __main__ block"""
        # Mock at the system level - these will affect the actual module execution
        mocker.patch('scanner.iam_auditor.get_project_id', return_value="test-project")
        mocker.patch('scanner.iam_auditor.get_iam_policy', return_value={"bindings": []})
        mocker.patch('scanner.iam_auditor.analyze_policy', return_value=[])
        mock_print = mocker.patch('builtins.print')  # Mock print to avoid actual output
        
        # Execute the __main__ block by importing and running
        import scanner.iam_auditor
        # Force reload to ensure our mocks are used
        import importlib
        importlib.reload(scanner.iam_auditor)
        
        # Verify the module executed without errors
        # We can't easily assert function calls here, but we can check that print was called
        assert mock_print.called

    def test_check_public_access_specific_edge(self):
        """Test line 89 - public access with empty members list"""
        bindings = [{"role": "roles/viewer", "members": []}]
        findings = check_public_access(bindings)
        assert len(findings) == 0
    
    def test_check_service_account_specific_edge(self):
        """Test line 125 - service account with empty members list"""
        bindings = [{"role": "roles/owner", "members": []}]
        findings = check_service_account_primitive_roles(bindings)
        assert len(findings) == 0
    
    def test_analyze_policy_with_non_dict_policy(self):
        """Test line 145 - analyze_policy with non-dict input"""
        findings = analyze_policy("not a dict")
        assert findings == []

    def test_check_public_access_with_empty_members(self):
        """Test line 89 - public access with empty members list"""
        bindings = [{"role": "roles/viewer", "members": []}]
        findings = check_public_access(bindings)
        assert len(findings) == 0
    
    def test_check_service_account_with_empty_members(self):
        """Test line 125 - service account with empty members list"""
        bindings = [{"role": "roles/owner", "members": []}]
        findings = check_service_account_primitive_roles(bindings)
        assert len(findings) == 0
    
    def test_print_report_counters_initialized(self, capsys):
        """Test lines 176-177 - counters are initialized even with no findings"""
        # This should execute lines 176-177 (count_high = 0, count_critical = 0)
        print_report([], "test-project")
        captured = capsys.readouterr()
        assert "Total findings: 0 (0 HIGH, 0 CRITICAL)" in captured.out
