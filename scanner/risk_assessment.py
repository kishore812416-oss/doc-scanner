"""
Risk Assessment Module
----------------------
Calculates a numerical security score (0-100) and determines the overall risk level
(High, Medium, Low) based on security check findings.

Educational context:
Demonstrates a quantitative risk scoring model where baseline trust (100) is reduced
by weighted severity penalties assigned to specific misconfigurations.
"""

import logging

logger = logging.getLogger(__name__)

# Scoring Penalties Configuration
PENALTY_ROOT_USER = 25
PENALTY_RISKY_PORT = 15
MAX_PENALTY_RISKY_PORTS = 45
PENALTY_UNPINNED_TAG = 10
PENALTY_SECRET = 15
MAX_PENALTY_SECRETS = 45


def calculate_risk_score(check_results: dict) -> dict:
    """
    Calculates security score (0-100), penalty breakdown, and risk level.
    
    Rules:
    - Base score: 100
    - Running as root: -25 points
    - Risky exposed ports: -15 per risky port (max -45)
    - Unpinned / latest tag: -10 points
    - Secrets detected: -15 per secret found (max -45)
    - Score bounded between 0 and 100
    
    Risk Level Mapping:
    - High Risk: score < 50 (Red)
    - Medium Risk: 50 <= score <= 75 (Yellow/Amber)
    - Low Risk: score > 75 (Green)
    """
    base_score = 100
    deductions = []
    total_deductions = 0
    
    # 1. Root User Penalty
    root_check = check_results.get('root_user', {})
    if root_check.get('is_flagged'):
        deduction = PENALTY_ROOT_USER
        total_deductions += deduction
        deductions.append({
            'issue': 'Running as root user',
            'points': deduction,
            'category': 'Access Control'
        })

    # 2. Risky Exposed Ports Penalty
    ports_check = check_results.get('exposed_ports', {})
    if ports_check.get('is_flagged'):
        risky_count = len(ports_check.get('risky_ports', []))
        deduction = min(risky_count * PENALTY_RISKY_PORT, MAX_PENALTY_RISKY_PORTS)
        total_deductions += deduction
        deductions.append({
            'issue': f"Exposed {risky_count} risky port(s)",
            'points': deduction,
            'category': 'Network Security'
        })

    # 3. Base Image / Unpinned Tag Penalty
    tag_check = check_results.get('base_image', {})
    if tag_check.get('is_flagged'):
        deduction = PENALTY_UNPINNED_TAG
        total_deductions += deduction
        deductions.append({
            'issue': f"Using unpinned tag '{tag_check.get('current_tag')}'",
            'points': deduction,
            'category': 'Supply Chain / Policy'
        })

    # 4. Secrets Penalty
    secrets_check = check_results.get('secrets', {})
    if secrets_check.get('is_flagged'):
        secrets_count = secrets_check.get('total_detected', 0)
        deduction = min(secrets_count * PENALTY_SECRET, MAX_PENALTY_SECRETS)
        total_deductions += deduction
        deductions.append({
            'issue': f"Found {secrets_count} possible hardcoded secret(s)",
            'points': deduction,
            'category': 'Credential Security'
        })

    # Final score clamping (0 to 100)
    final_score = max(0, base_score - total_deductions)
    
    # Determine Risk Level Category & Theme Colors
    if final_score < 50:
        risk_level = "High"
        color_code = "#ef4444"  # Red
        badge_class = "risk-high"
        summary_statement = "Critical security misconfigurations detected. Immediate remediation required before production deployment."
    elif 50 <= final_score <= 75:
        risk_level = "Medium"
        color_code = "#f59e0b"  # Amber/Yellow
        badge_class = "risk-medium"
        summary_statement = "Moderate risk misconfigurations present. Review and apply security recommendations."
    else:
        risk_level = "Low"
        color_code = "#10b981"  # Green
        badge_class = "risk-low"
        summary_statement = "Good security posture. Few or minor issues detected."

    return {
        'score': final_score,
        'base_score': base_score,
        'total_deductions': total_deductions,
        'deductions': deductions,
        'risk_level': risk_level,
        'color_code': color_code,
        'badge_class': badge_class,
        'summary_statement': summary_statement
    }
