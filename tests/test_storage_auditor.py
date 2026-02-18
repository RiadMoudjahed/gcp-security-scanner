import pytest
from unittest.mock import patch, MagicMock
from scanner.storage_auditor import (
    analyze_storage,
    check_public_access,
    check_uniform_access,
    check_versioning
)


class TestStorageBasicRisks:
    """Tests for storage security misconfigurations"""

    @patch('scanner.storage_auditor.get_bucket_iam_policy')
    def test_detects_public_bucket_access(self, mock_get_policy):
        """
        GIVEN: A bucket grants access to allUsers
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as CRITICAL
        """
        mock_get_policy.return_value = {
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"]
            }]
        }
        
        buckets = ["gs://public-bucket"]
        findings = check_public_access(buckets)
        
        assert len(findings) > 0
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["rule"] == "PUBLIC_BUCKET_ACCESS"
        assert findings[0]["member"] == "allUsers"

    @patch('scanner.storage_auditor.get_bucket_metadata')
    def test_detects_uniform_access_disabled(self, mock_get_metadata):
        """
        GIVEN: A bucket has uniform access disabled
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as MEDIUM
        """
        mock_get_metadata.return_value = {
            "uniform_access": False,
            "versioning": True
        }
        
        buckets = ["gs://mixed-access-bucket"]
        findings = check_uniform_access(buckets)
        
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["rule"] == "UNIFORM_ACCESS_DISABLED"

    @patch('scanner.storage_auditor.get_bucket_metadata')
    def test_detects_versioning_disabled(self, mock_get_metadata):
        """
        GIVEN: A bucket has versioning disabled
        WHEN:  We analyze the buckets
        THEN:  The auditor flags it as MEDIUM
        """
        mock_get_metadata.return_value = {
            "uniform_access": True,
            "versioning": False
        }

        buckets = ["gs://no-versioning-bucket"]
        findings = check_versioning(buckets)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["rule"] == "VERSIONING_DISABLED"


class TestStorageEdgeCases:
    """Edge cases and validation tests"""

    def test_empty_buckets_returns_no_findings(self):
        """
        GIVEN: No buckets exist (empty list)
        WHEN:  We analyze them
        THEN:  We get back an empty findings list, no crash
        """
        buckets = []
        findings = analyze_storage(buckets)
        
        assert len(findings) == 0

    @patch('scanner.storage_auditor.get_bucket_metadata')
    @patch('scanner.storage_auditor.get_bucket_iam_policy')
    def test_secure_bucket_returns_no_finding(self, mock_get_policy, mock_get_metadata):
        """
        GIVEN: A bucket with secure settings
        WHEN:  We analyze the buckets
        THEN:  No findings — this is a secure bucket
        """
        # Mock IAM policy with no public access
        mock_get_policy.return_value = {
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["user:admin@example.com"]  # specific user, not public
            }]
        }
        
        # Mock metadata with secure settings
        mock_get_metadata.return_value = {
            "uniform_access": True,
            "versioning": True
        }
        
        buckets = ["gs://secure-bucket"]
        findings = analyze_storage(buckets)
        
        assert len(findings) == 0
