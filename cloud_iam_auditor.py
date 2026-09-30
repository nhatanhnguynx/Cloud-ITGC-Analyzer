"""
=============================================================================
TOOL: Cloud ITGC Configuration Analyzer
FILE: cloud_iam_auditor.py
AUTHOR: Nguyen Nhat Anh - Tech Risk & Cybersecurity Enthusiast ( Super Junior)

DESCRIPTION:
An automated Python utility designed to parse and audit Cloud Identity and 
Access Management (IAM) configurations (JSON format). It statically analyzes 
resource policies to identify critical IT General Control (ITGC) failures 
such as overly permissive access (Public S3 Buckets) or Privilege Creep.

CORE CAPABILITIES:
- Parses AWS-style JSON IAM policies.
- Detects wildcard principals ("*") leading to data exposure.
- Flags excessive admin permissions ("Action": "*").
=============================================================================
"""
import json

def audit_cloud_policy(file_path):
    print(f"! Initiating ITGC Audit on Cloud Policy: '{file_path}'...\n")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            policy = json.load(f)
    except Exception as e:
        print(f"! Error loading configuration: {e}")
        return

    statements = policy.get("Statement", [])
    risk_count = 0
    
    for index, stmt in enumerate(statements):
        sid = stmt.get("Sid", f"Statement_{index}")
        effect = stmt.get("Effect", "")
        principal = stmt.get("Principal", "")
        action = stmt.get("Action", "")
        
        # Risk 1: Public Access Risk (S3 Data Leakage)
        if effect == "Allow" and principal == "*":
            print(f"! CRITICAL RISK: Public Access Enabled")
            print(f"   -> Location: {sid}")
            print(f"   -> Issue: Principal is set to '*' allowing unrestricted public exposure.\n")
            risk_count += 1
            
        # Risk 2: Privilege Escalation Risk (Overly Permissive)
        if effect == "Allow" and action == "*":
            print(f"! HIGH RISK [Rule 2]: Excessive Privileges Granted")
            print(f"   -> Location: {sid}")
            print(f"   -> Issue: Action set to '*' granting full administrative rights.\n")
            risk_count += 1

    print(f"! Audit Complete. Found {risk_count} misconfiguration(s) requiring remediation.")

if __name__ == "__main__":
    audit_cloud_policy("mock_cloud_config.json")