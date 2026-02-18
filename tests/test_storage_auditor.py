import pytest
from unittest.mock import patch, MagicMock
from scanner.storage_auditor import (
    get_buckets,
    get_bucket_iam_policy,
    get_bucket_metadata,
    check_public_access,
    check_uniform_access,
    check_versioning,
    analyze_storage,
    print_report
)


class TestStorageBasicRisks:
    """Tests for storage security misconfigurations"""

    def test_detects_public_bucket_access(self):
        """
        GIVEN: A bucket grants access to allUsers
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as CRITICAL
        """
        fake_buckets = ["gs://test-bucket"]
        
        # Mock the get_bucket_iam_policy function
        with patch('scanner.storage_auditor.get_bucket_iam_policy') as mock_get_policy:
            mock_get_policy.return_value = {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"]
                    }
                ]
            }
            
            findings = check_public_access(fake_buckets)
            
            assert len(findings) == 1
            assert findings[0]["severity"] == "CRITICAL"
            assert findings[0]["rule"] == "PUBLIC_BUCKET_ACCESS"
            assert findings[0]["resource"] == "gs://test-bucket"
            assert findings[0]["member"] == "allUsers"
            assert findings[0]["role"] == "roles/storage.objectViewer"

    def test_detects_uniform_access_disabled(self):
        """
        GIVEN: A bucket has uniform bucket-level access disabled
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as MEDIUM
        """
        fake_buckets = ["gs://test-bucket"]
        
        # Mock the get_bucket_metadata function
        with patch('scanner.storage_auditor.get_bucket_metadata') as mock_get_metadata:
            mock_get_metadata.return_value = {
                "uniform_access": False,
                "versioning": True
            }
            
            findings = check_uniform_access(fake_buckets)
            
            assert len(findings) == 1
            assert findings[0]["severity"] == "MEDIUM"
            assert findings[0]["rule"] == "UNIFORM_ACCESS_DISABLED"
            assert findings[0]["resource"] == "gs://test-bucket"

    def test_detects_versioning_disabled(self):
        """
        GIVEN: A bucket has versioning disabled
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as MEDIUM
        """
        fake_buckets = ["gs://test-bucket"]
        
        # Mock the get_bucket_metadata function
        with patch('scanner.storage_auditor.get_bucket_metadata') as mock_get_metadata:
            mock_get_metadata.return_value = {
                "uniform_access": True,
                "versioning": False
            }
            
            findings = check_versioning(fake_buckets)
            
            assert len(findings) == 1
            assert findings[0]["severity"] == "MEDIUM"
            assert findings[0]["rule"] == "VERSIONING_DISABLED"
            assert findings[0]["resource"] == "gs://test-bucket"


class TestStorageEdgeCases:
    """Edge cases and validation tests"""

    def test_empty_buckets_returns_no_findings(self):
        """
        GIVEN: No buckets exist (empty list)
        WHEN:  We analyze them
        THEN:  We get back an empty findings list, no crash
        """
        fake_buckets = []
        
        findings = analyze_storage(fake_buckets)
        
        assert len(findings) == 0

    def test_secure_bucket_returns_no_finding(self):
        """
        GIVEN: A bucket with:
              - No public access
              - Uniform access enabled
              - Versioning enabled
        WHEN:  We analyze the buckets
        THEN:  No findings — this is a legitimate, secure bucket
        """
        fake_buckets = ["gs://secure-bucket"]
        
        # Mock both the IAM policy and metadata functions
        with patch('scanner.storage_auditor.get_bucket_iam_policy') as mock_get_policy, \
             patch('scanner.storage_auditor.get_bucket_metadata') as mock_get_metadata:
            
            mock_get_policy.return_value = {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["user:test@example.com"]
                    }
                ]
            }
            
            mock_get_metadata.return_value = {
                "uniform_access": True,
                "versioning": True
            }
            
            findings = analyze_storage(fake_buckets)
            
            assert len(findings) == 0

    def test_public_access_multiple_members(self):
        """
        GIVEN: A bucket with multiple public members and roles
        WHEN:  We analyze the buckets
        THEN:  The auditor flags all public access findings
        """
        fake_buckets = ["gs://test-bucket"]
        
        with patch('scanner.storage_auditor.get_bucket_iam_policy') as mock_get_policy:
            mock_get_policy.return_value = {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"]
                    },
                    {
                        "role": "roles/storage.objectAdmin",
                        "members": ["allAuthenticatedUsers"]
                    }
                ]
            }
            
            findings = check_public_access(fake_buckets)
            
            assert len(findings) == 2
            assert findings[0]["member"] == "allUsers"
            assert findings[1]["member"] == "allAuthenticatedUsers"

    def test_error_handling_skips_problem_buckets(self):
        """
        GIVEN: A bucket that causes an error when accessing
        WHEN:  We analyze the buckets
        THEN:  The auditor skips it without crashing
        """
        fake_buckets = ["gs://error-bucket", "gs://good-bucket"]
        
        with patch('scanner.storage_auditor.get_bucket_iam_policy') as mock_get_policy, \
             patch('scanner.storage_auditor.get_bucket_metadata') as mock_get_metadata:
            
            # First bucket raises exception
            mock_get_policy.side_effect = [Exception("Access denied"), {"bindings": []}]
            
            # Metadata for the good bucket
            mock_get_metadata.return_value = {
                "uniform_access": False,
                "versioning": False
            }
            
            findings = analyze_storage(fake_buckets)
            
            # Should only have findings from the second bucket
            assert len(findings) == 2  # One for uniform_access, one for versioning


class TestStorageHelperFunctions:
    """Tests for helper functions (get_buckets, get_bucket_iam_policy, get_bucket_metadata)"""

    @patch('scanner.storage_auditor.subprocess.run')
    def test_get_buckets_success(self, mock_run):
        """Test get_buckets successfully parses gsutil output"""
        mock_result = MagicMock()
        mock_result.stdout = "gs://bucket1\ngs://bucket2\n"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        buckets = get_buckets()
        
        assert buckets == ["gs://bucket1", "gs://bucket2"]
        mock_run.assert_called_once_with(
            ["gsutil", "ls"],
            capture_output=True,
            text=True
        )

    @patch('scanner.storage_auditor.subprocess.run')
    def test_get_buckets_empty(self, mock_run):
        """Test get_buckets with no buckets"""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        buckets = get_buckets()
        
        assert buckets == []

    @patch('scanner.storage_auditor.subprocess.run')
    def test_get_bucket_iam_policy(self, mock_run):
        """Test get_bucket_iam_policy parses JSON correctly"""
        mock_result = MagicMock()
        mock_result.stdout = '{"bindings": [{"role": "test", "members": ["user:test@test.com"]}]}'
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        policy = get_bucket_iam_policy("gs://test-bucket")
        
        assert policy["bindings"][0]["role"] == "test"
        mock_run.assert_called_once_with(
            ["gsutil", "iam", "get", "gs://test-bucket"],
            capture_output=True,
            text=True
        )

    @patch('scanner.storage_auditor.subprocess.run')
    def test_get_bucket_metadata(self, mock_run):
        """Test get_bucket_metadata returns correct metadata dict"""
        # Mock uniform access response
        mock_uniform_result = MagicMock()
        mock_uniform_result.stdout = "Enabled"
        mock_uniform_result.stderr = ""
        
        # Mock versioning response
        mock_versioning_result = MagicMock()
        mock_versioning_result.stdout = "Enabled"
        mock_versioning_result.stderr = ""
        
        mock_run.side_effect = [mock_uniform_result, mock_versioning_result]
        
        metadata = get_bucket_metadata("gs://test-bucket")
        
        assert metadata["uniform_access"] is True
        assert metadata["versioning"] is True
        assert mock_run.call_count == 2

    @patch('scanner.storage_auditor.subprocess.run')
    def test_get_bucket_metadata_disabled(self, mock_run):
        """Test get_bucket_metadata when features are disabled"""
        # Mock uniform access response
        mock_uniform_result = MagicMock()
        mock_uniform_result.stdout = "Disabled"
        mock_uniform_result.stderr = ""
        
        # Mock versioning response
        mock_versioning_result = MagicMock()
        mock_versioning_result.stdout = "Disabled"
        mock_versioning_result.stderr = ""
        
        mock_run.side_effect = [mock_uniform_result, mock_versioning_result]
        
        metadata = get_bucket_metadata("gs://test-bucket")
        
        assert metadata["uniform_access"] is False
        assert metadata["versioning"] is False


class TestStorageReport:
    """Tests for the print_report function"""

    def test_print_report_with_findings(self, capsys):
        """Test print_report outputs findings correctly"""
        findings = [
            {
                "severity": "CRITICAL",
                "rule": "PUBLIC_BUCKET_ACCESS",
                "resource": "gs://test-bucket",
                "member": "allUsers",
                "role": "roles/storage.objectViewer",
                "reason": "Bucket gs://test-bucket grants roles/storage.objectViewer to allUsers (public access)"
            },
            {
                "severity": "MEDIUM",
                "rule": "UNIFORM_ACCESS_DISABLED",
                "resource": "gs://test-bucket",
                "reason": "Bucket gs://test-bucket doesn't have uniform bucket-level access enabled."
            }
        ]
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "GCP Storage Security Audit Report" in captured.out
        assert "[CRITICAL] PUBLIC_BUCKET_ACCESS" in captured.out
        assert "[MEDIUM] UNIFORM_ACCESS_DISABLED" in captured.out
        assert "Total findings: 2 (1 CRITICAL, 0 HIGH, 1 MEDIUM)" in captured.out

    def test_print_report_empty_findings(self, capsys):
        """Test print_report with no findings"""
        findings = []
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "GCP Storage Security Audit Report" in captured.out
        assert "Total findings: 0 (0 CRITICAL, 0 HIGH, 0 MEDIUM)" in captured.out


class TestStorageAnalyzeFunction:
    """Tests for the analyze_storage master function"""

    def test_analyze_storage_combines_all_findings(self):
        """Test analyze_storage combines findings from all checks"""
        fake_buckets = ["gs://test-bucket"]
        
        with patch('scanner.storage_auditor.check_public_access') as mock_public, \
             patch('scanner.storage_auditor.check_uniform_access') as mock_uniform, \
             patch('scanner.storage_auditor.check_versioning') as mock_versioning:
            
            mock_public.return_value = [{"rule": "PUBLIC_BUCKET_ACCESS"}]
            mock_uniform.return_value = [{"rule": "UNIFORM_ACCESS_DISABLED"}]
            mock_versioning.return_value = [{"rule": "VERSIONING_DISABLED"}]
            
            findings = analyze_storage(fake_buckets)
            
            assert len(findings) == 3
            assert findings[0]["rule"] == "PUBLIC_BUCKET_ACCESS"
            assert findings[1]["rule"] == "UNIFORM_ACCESS_DISABLED"
            assert findings[2]["rule"] == "VERSIONING_DISABLED"
