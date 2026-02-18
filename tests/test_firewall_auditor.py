import pytest
from scanner.firewall_auditor import (
    analyze_firewall,
    check_public_exposure,
    check_high_risk_ports,
    check_logging_disabled
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
          "name": "scan-safe-rules",
          "sourceRanges": ["10.0.0.0/24"],
          "allowed": [{"IPProtocol": "tpc", "ports": ["8080"]}],
          "logConfig": {"enable": True}
        }]

        findings = analyze_firewall(fake_rules)
        assert len(findings) == 0
      
