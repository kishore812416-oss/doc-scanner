"""
Report Generator Module
-----------------------
Formats security check outputs, risk assessment metrics, and generates plain-language,
actionable remediation guidance for each identified issue.

Educational context:
Translates raw vulnerability findings into actionable recommendations with clear
code examples to aid developers in writing secure Dockerfiles.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_recommendations(check_results: dict) -> list:
    """
    Generates plain-language, bulleted recommendations tied to each detected security issue.
    Includes educational explanations and Dockerfile code snippet fixes.
    """
    recommendations = []

    # 1. Root User Remediation
    root_check = check_results.get('root_user', {})
    if root_check.get('is_flagged'):
        recommendations.append({
            'title': 'Configure Non-Root User',
            'issue': 'Container runs as root by default.',
            'category': 'Access Control',
            'priority': 'High',
            'description': (
                "Avoid running application containers as root. Create a dedicated unprivileged system user "
                "in your Dockerfile and switch to it using the 'USER' directive."
            ),
            'fix_example': (
                "# Dockerfile Remediation Fix:\n"
                "RUN groupadd -r appgroup && useradd -r -g appgroup appuser\n"
                "USER appuser"
            )
        })
    else:
        recommendations.append({
            'title': 'Maintain Non-Root Execution',
            'issue': None,
            'category': 'Access Control',
            'priority': 'Info',
            'description': f"Container correctly configures non-root user execution ('{root_check.get('user_value')}'). Continue maintaining least-privilege principles.",
            'fix_example': None
        })

    # 2. Exposed Ports Remediation
    ports_check = check_results.get('exposed_ports', {})
    if ports_check.get('is_flagged'):
        risky_str = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in ports_check.get('risky_ports', [])])
        recommendations.append({
            'title': 'Restrict Risky & Administrative Ports',
            'issue': f"Image exposes risky administrative/database port(s): {risky_str}.",
            'category': 'Network Security',
            'priority': 'Medium',
            'description': (
                "Remove unnecessary EXPOSE statements for SSH, Telnet, database, or administrative endpoints. "
                "Instead of exposing SSH (port 22), use 'docker exec' for container access."
            ),
            'fix_example': (
                "# Remove SSH/DB EXPOSE directives from Dockerfile\n"
                "# Only expose necessary application HTTP/HTTPS ports:\n"
                "EXPOSE 8080"
            )
        })

    # 3. Base Image & Unpinned Tag Remediation
    tag_check = check_results.get('base_image', {})
    if tag_check.get('is_flagged'):
        recommendations.append({
            'title': 'Pin Base Image Tags to Explicit Versions',
            'issue': f"Image relies on unpinned or mutable tag '{tag_check.get('current_tag')}'.",
            'category': 'Supply Chain Security',
            'priority': 'Medium',
            'description': (
                "Replace ':latest' or unpinned tags with immutable explicit tags or SHA digests. "
                "This guarantees repeatable, audited builds and prevents unexpected upstream breaking changes."
            ),
            'fix_example': (
                "# Avoid:\n"
                "# FROM python:latest\n\n"
                "# Recommended Fix:\n"
                "FROM python:3.11.8-slim-bookworm"
            )
        })

    # 4. Hardcoded Secrets Remediation
    secrets_check = check_results.get('secrets', {})
    if secrets_check.get('is_flagged'):
        recommendations.append({
            'title': 'Remove Hardcoded Secrets & Sensitive ENV Variables',
            'issue': f"Found {secrets_check.get('total_detected')} potential secret pattern(s) in image layers or environment variables.",
            'category': 'Credential Management',
            'priority': 'High',
            'description': (
                "Never bake passwords, API keys, AWS credentials, or private tokens into Dockerfiles or ENV declarations. "
                "Inject sensitive configuration at runtime via environment variables, secret mounts, or vault integrations."
            ),
            'fix_example': (
                "# Do NOT store secrets in Dockerfile:\n"
                "# ENV API_KEY=secret_key_123\n\n"
                "# Fix: Inject secrets at runtime when starting the container:\n"
                "docker run --env-file .env.production my-app:v1"
            )
        })

    return recommendations


def generate_full_report(image_name: str, inspection_data: dict, check_results: dict, risk_assessment: dict) -> dict:
    """
    Consolidates metadata, check outputs, scoring, and recommendations into a complete report object.
    """
    metadata = inspection_data.get('metadata', {})
    recommendations = generate_recommendations(check_results)
    
    # Calculate summary counters
    checks_list = [
        check_results.get('root_user'),
        check_results.get('exposed_ports'),
        check_results.get('base_image'),
        check_results.get('secrets')
    ]
    
    total_checks = len(checks_list)
    flagged_checks = sum(1 for c in checks_list if c and c.get('is_flagged'))
    passed_checks = total_checks - flagged_checks
    
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        'scan_timestamp': scan_timestamp,
        'image_name': image_name,
        'metadata': metadata,
        'check_results': check_results,
        'risk_assessment': risk_assessment,
        'recommendations': recommendations,
        'summary': {
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'flagged_checks': flagged_checks,
            'is_simulated': inspection_data.get('is_simulated', False)
        }
    }
