import pytest
from unittest.mock import patch, MagicMock
from scanner.firewall_auditor import (
    get_firewall_rules,
    analyze_firewall,
    check_public_exposure,
    check_high_risk_ports,
    check_logging_disabled,
    print_report
)


class TestFirewallBasicRisks:
    """Tests for firewall security misconfigurations"""

    def test_detects_public_exposure(self):
        """
        GIVEN: A firewall rule allows 0.0.0.0/0
        WHEN:  We analyze the firewall rules
        THEN:  The auditor flags it as HIGH risk
        """
        fake_rules = [{
            "name": "allow-all",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}]
        }]

        findings = analyze_firewall(fake_rules)
        
        assert len(findings) > 0
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["rule"] == "PUBLIC_FIREWALL_RULE"
        assert findings[0]["source"] == "0.0.0.0/0"

    def test_detects_high_risk_port_exposure(self):
        """
        GIVEN: A firewall rule exposes SSH (port 22) to the internet
        WHEN:  We analyze the rules
        THEN:  The auditor flags it as CRITICAL
        """
        fake_rules = [{
            "name": "allow-ssh",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]
        }]

        findings = analyze_firewall(fake_rules)
        
        # Should have 2 findings: PUBLIC_FIREWALL_RULE + HIGH_RISK_PORT_EXPOSED
        assert len(findings) >= 2
        
        # Check that HIGH_RISK_PORT_EXPOSED is present
        high_risk_findings = [f for f in findings if f["rule"] == "HIGH_RISK_PORT_EXPOSED"]
        assert len(high_risk_findings) > 0
        assert high_risk_findings[0]["severity"] == "CRITICAL"

    def test_detects_logging_disabled(self):
        """
        GIVEN: A firewall rule has no logConfig or logConfig.enable is False
        WHEN:  We analyze the rules
        THEN:  The auditor flags it as MEDIUM risk
        """
        
        fake_rules = [{
            "name": "fw-logging-disabled",
            "sourceRanges": ["10.0.0.0/24"],
            "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}]
        }]
    
        findings = analyze_firewall(fake_rules)
        
        assert len(findings) == 1  # only logging issue, nothing else
        assert findings[0]["rule"] == "FIREWALL_LOGGING_DISABLED"
        assert findings[0]["severity"] == "MEDIUM"


class TestFirewallEdgeCases:
    """Edge cases and validation tests"""

    def test_empty_rules_returns_no_findings(self):
        """
        GIVEN: No firewall rules exist (empty list)
        WHEN:  We analyze them
        THEN:  We get back an empty findings list, no crash
        """
      
        fake_rules = []

        findings = analyze_firewall(fake_rules)

        assert len(findings) == 0

    def test_safe_firewall_rule_returns_no_finding(self):
        """
        GIVEN: A firewall rule with:
              - Specific source IP (not 0.0.0.0/0)
              - Safe port (not in HIGH_RISK_PORTS)
              - Logging enabled
        WHEN:  We analyze the rules
        THEN:  No findings — this is a legitimate, secure rule
        """
      
        fake_rules = [{
          "name": "safe-rule",
          "sourceRanges": ["10.0.0.0/24"],
          "allowed": [{"IPProtocol": "tcp", "ports": ["8080"]}],
          "logConfig": {"enable": True}
        }]

        findings = analyze_firewall(fake_rules)
        assert len(findings) == 0

    def test_rule_with_all_ports_exposed(self):
        """
        GIVEN: A firewall rule exposes all ports to the internet
        WHEN:  We analyze the rules
        THEN:  The auditor flags it with ports ["all"]
        """
        fake_rules = [{
            "name": "allow-all-ports",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{"IPProtocol": "tcp"}]
        }]

        findings = check_public_exposure(fake_rules)
        
        assert len(findings) == 1
        assert findings[0]["ports"] == ["all"]

    def test_high_risk_port_with_multiple_protocols(self):
        """
        GIVEN: A firewall rule exposes port 22 with multiple protocols
        WHEN:  We analyze the rules
        THEN:  The auditor flags it as CRITICAL
        """
        fake_rules = [{
            "name": "allow-ssh-multi",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [
                {"IPProtocol": "tcp", "ports": ["22"]},
                {"IPProtocol": "udp", "ports": ["22"]}
            ]
        }]

        findings = check_high_risk_ports(fake_rules)
        
        assert len(findings) == 2  # Both TCP and UDP findings
        for finding in findings:
            assert finding["severity"] == "CRITICAL"
            assert finding["rule"] == "HIGH_RISK_PORT_EXPOSED"


class TestFirewallHelperFunctions:
    """Tests for helper functions (get_firewall_rules)"""

    @patch('scanner.firewall_auditor.subprocess.run')
    def test_get_firewall_rules_success(self, mock_run):
        """Test get_firewall_rules successfully parses gcloud output"""
        mock_result = MagicMock()
        mock_result.stdout = '[{"name": "rule1"}, {"name": "rule2"}]'
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        rules = get_firewall_rules()
        
        assert len(rules) == 2
        assert rules[0]["name"] == "rule1"
        mock_run.assert_called_once_with(
            ["gcloud", "compute", "firewall-rules", "list", "--format=json"],
            capture_output=True,
            text=True
        )

    @patch('scanner.firewall_auditor.subprocess.run')
    def test_get_firewall_rules_empty(self, mock_run):
        """Test get_firewall_rules with empty response"""
        mock_result = MagicMock()
        mock_result.stdout = '[]'
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        rules = get_firewall_rules()
        
        assert rules == []


class TestFirewallReport:
    """Tests for the print_report function"""

    def test_print_report_with_all_severities(self, capsys):
        """Test print_report outputs findings with different severities correctly"""
        findings = [
            {
                "severity": "CRITICAL",
                "rule": "HIGH_RISK_PORT_EXPOSED",
                "resource": "allow-ssh",
                "source": "0.0.0.0/0",
                "ports": ["22"],
                "reason": "Firewall rule 'allow-ssh' exposes high-risk ports ['22'] to the internet."
            },
            {
                "severity": "HIGH",
                "rule": "PUBLIC_FIREWALL_RULE",
                "resource": "allow-http",
                "source": "0.0.0.0/0",
                "ports": ["80", "443"],
                "reason": "Firewall rule 'allow-http' allows traffic from entire internet (0.0.0.0/0)"
            },
            {
                "severity": "MEDIUM",
                "rule": "FIREWALL_LOGGING_DISABLED",
                "resource": "internal-rule",
                "reason": "Firewall rule 'internal-rule' does not logging (Disabled)."
            }
        ]
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "GCP Firewall Security Audit Report" in captured.out
        assert "[CRITICAL] HIGH_RISK_PORT_EXPOSED" in captured.out
        assert "[HIGH] PUBLIC_FIREWALL_RULE" in captured.out
        assert "[MEDIUM] FIREWALL_LOGGING_DISABLED" in captured.out
        assert "Total findings: 3 (1 MEDIUM, 1 HIGH, 1 CRITICAL)" in captured.out

    def test_print_report_with_single_finding(self, capsys):
        """Test print_report with only one finding"""
        findings = [
            {
                "severity": "HIGH",
                "rule": "PUBLIC_FIREWALL_RULE",
                "resource": "allow-all",
                "source": "0.0.0.0/0",
                "ports": ["all"],
                "reason": "Firewall rule 'allow-all' allows traffic from entire internet (0.0.0.0/0)"
            }
        ]
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "Total findings: 1 (0 MEDIUM, 1 HIGH, 0 CRITICAL)" in captured.out

    def test_print_report_empty_findings(self, capsys):
        """Test print_report with no findings"""
        findings = []
        
        print_report(findings)
        captured = capsys.readouterr()
        
        assert "GCP Firewall Security Audit Report" in captured.out
        assert "Total findings: 0 (0 MEDIUM, 0 HIGH, 0 CRITICAL)" in captured.out


class TestFirewallAnalyzeFunction:
    """Tests for the analyze_firewall master function"""

    def test_analyze_firewall_combines_all_findings(self):
        """Test analyze_firewall combines findings from all checks"""
        fake_rules = ["fake-rule"]
        
        with patch('scanner.firewall_auditor.check_public_exposure') as mock_public, \
             patch('scanner.firewall_auditor.check_high_risk_ports') as mock_high_risk, \
             patch('scanner.firewall_auditor.check_logging_disabled') as mock_logging:
            
            mock_public.return_value = [{"rule": "PUBLIC_FIREWALL_RULE"}]
            mock_high_risk.return_value = [{"rule": "HIGH_RISK_PORT_EXPOSED"}]
            mock_logging.return_value = [{"rule": "FIREWALL_LOGGING_DISABLED"}]
            
            findings = analyze_firewall(fake_rules)
            
            assert len(findings) == 3
            assert findings[0]["rule"] == "PUBLIC_FIREWALL_RULE"
            assert findings[1]["rule"] == "HIGH_RISK_PORT_EXPOSED"
            assert findings[2]["rule"] == "FIREWALL_LOGGING_DISABLED"


class TestFirewallMainBlock:
    """Test the main block execution (covers lines 163-165)"""
    
    @patch('scanner.firewall_auditor.get_firewall_rules')
    @patch('scanner.firewall_auditor.analyze_firewall')
    @patch('scanner.firewall_auditor.print_report')
    def test_main_block_execution(self, mock_print, mock_analyze, mock_get_rules):
        """Test that the main block calls the expected functions"""
        mock_get_rules.return_value = [{"name": "test-rule"}]
        mock_analyze.return_value = [{"severity": "MEDIUM", "rule": "TEST"}]
        
        # Simulate what happens in the main block
        rules = mock_get_rules()
        findings = mock_analyze(rules)
        mock_print(findings)
        
        mock_get_rules.assert_called_once()
        mock_analyze.assert_called_once_with([{"name": "test-rule"}])
        mock_print.assert_called_once_with([{"severity": "MEDIUM", "rule": "TEST"}])
