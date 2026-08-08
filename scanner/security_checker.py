"""
Security Checker Module
-----------------------
Contains security checking routines for Docker image metadata:
1. Root User Execution Check
2. Exposed & Risky Ports Check
3. Base Image & Unpinned Tag Check
4. Hardcoded Secrets & Sensitive Environment Variable Detection

Educational context:
Each function inspects low-level container image config structures to identify
common security misconfigurations before deployment.
"""

import re
import logging

logger = logging.getLogger(__name__)

# Dictionary of high-risk network ports and their security descriptions
RISKY_PORTS_MAP = {
    22: ("SSH", "Remote shell access. Exposing SSH in container images is generally bad practice; use docker exec instead."),
    23: ("Telnet", "Unencrypted legacy remote terminal protocol."),
    21: ("FTP", "Unencrypted file transfer protocol."),
    3389: ("RDP", "Windows Remote Desktop Protocol."),
    2375: ("Docker API", "Unencrypted Docker Engine Daemon REST API socket exposure."),
    2376: ("Docker TLS API", "Docker Engine Daemon API TLS socket endpoint."),
    27017: ("MongoDB", "NoSQL Database endpoint; vulnerable if binding publicly without strict auth rules."),
    6379: ("Redis", "In-memory datastore; often deployed without authentication by default."),
    111: ("RPCBind", "ONC RPC Portmapper; frequent target for network amplification attacks."),
    3306: ("MySQL", "Database service port. Containers should rarely expose DB ports directly to host networks."),
    5432: ("PostgreSQL", "Database service port."),
    1433: ("MSSQL", "Microsoft SQL Server database endpoint.")
}

# Regex pattern for hardcoded secret detection in environment variables & docker history
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key)', "API Key"),
    (r'(?i)(secret[_-]?key)', "Secret Key"),
    (r'(?i)(access[_-]?key)', "Access Key"),
    (r'(?i)(pass(?:word|phrase)?)', "Password/Passphrase"),
    (r'(?i)(token)', "Auth Token"),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id)', "AWS Access Key"),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)', "AWS Secret Key"),
    (r'(?i)(private[_-]?key)', "Private Key / SSL Certificate"),
    (r'(?i)(db[_-]?(?:pass|password|url))', "Database Connection String / Credentials"),
    (r'(?i)(bearer\s+[a-zA-Z0-9_\-\.]+)', "Bearer Authentication Token"),
    (r'(?i)(jwt[_-]?secret)', "JWT Secret Token")
]


def check_root_user(attrs: dict, history: list) -> dict:
    """
    Check 1: Root User Execution Check
    ---------------------------------
    Inspects 'Config.User' and 'ContainerConfig.User'. If unspecified ("") or explicitly
    set to "root", "0", or "0:0", the container runs as root by default.
    
    Educational Note:
    Containers inherit Linux namespaces. Running processes as root increases blast radius
    if a container escape vulnerability (e.g., kernel or runtime exploit) occurs.
    """
    config = attrs.get('Config') or {}
    container_config = attrs.get('ContainerConfig') or {}
    
    user = config.get('User') or container_config.get('User') or ""
    user_str = str(user).strip().lower()
    
    # Check if user is root (empty string defaults to root in Docker execution)
    is_root = False
    details = ""
    
    if not user_str or user_str in ["root", "0", "0:0", "0:root"]:
        is_root = True
        if not user_str:
            details = "No 'USER' directive set in image metadata. Docker defaults to running as root."
        else:
            details = f"Image explicitly configures USER to '{user}' (UID 0 / root privileges)."
    else:
        is_root = False
        details = f"Image configures non-root user execution: USER '{user}'."
        
    return {
        'check_name': 'Root User Execution',
        'is_flagged': is_root,
        'user_value': user if user else "(unspecified / root)",
        'severity': 'HIGH' if is_root else 'PASS',
        'details': details
    }


def check_exposed_ports(attrs: dict) -> dict:
    """
    Check 2: Exposed & Risky Ports Check
    -----------------------------------
    Inspects 'Config.ExposedPorts' dictionary (e.g. {"80/tcp": {}, "22/tcp": {}}).
    Identifies high-risk administrative or database ports that should not be exposed.
    
    Educational Note:
    Exposing unnecessary ports expands the container's attack surface and can expose
    sensitive internal protocols to external host networks.
    """
    config = attrs.get('Config') or {}
    exposed_ports_dict = config.get('ExposedPorts') or {}
    
    exposed_list = []
    risky_ports_found = []
    
    for port_str in exposed_ports_dict.keys():
        # port_str format is usually '80/tcp' or '53/udp'
        port_num = None
        protocol = 'tcp'
        
        if '/' in port_str:
            parts = port_str.split('/')
            try:
                port_num = int(parts[0])
                protocol = parts[1]
            except ValueError:
                pass
        else:
            try:
                port_num = int(port_str)
            except ValueError:
                pass

        if port_num is not None:
            is_risky = port_num in RISKY_PORTS_MAP
            service_name, desc = RISKY_PORTS_MAP.get(port_num, ("Service", "Standard exposed port"))
            
            port_info = {
                'port': port_num,
                'protocol': protocol,
                'raw': port_str,
                'is_risky': is_risky,
                'service': service_name,
                'description': desc
            }
            
            exposed_list.append(port_info)
            if is_risky:
                risky_ports_found.append(port_info)

    is_flagged = len(risky_ports_found) > 0
    severity = 'MEDIUM' if is_flagged else ('INFO' if exposed_list else 'PASS')
    
    if not exposed_list:
        details = "No ports are exposed in the image metadata."
    elif is_flagged:
        risky_str = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in risky_ports_found])
        details = f"Exposed risky administrative/database ports detected: {risky_str}."
    else:
        ports_str = ", ".join([p['raw'] for p in exposed_list])
        details = f"Exposed standard ports: {ports_str}. No known critical risky management ports detected."

    return {
        'check_name': 'Exposed & Risky Ports',
        'is_flagged': is_flagged,
        'total_exposed': len(exposed_list),
        'exposed_ports': exposed_list,
        'risky_ports': risky_ports_found,
        'severity': severity,
        'details': details
    }


def check_base_image(attrs: dict, target_image: str) -> dict:
    """
    Check 3: Base Image & Unpinned Tag Check
    ---------------------------------------
    Evaluates image reference tag (e.g. 'latest', 'dev', '3.9-slim').
    Flags use of mutable 'latest' or unpinned tags.
    
    Educational Note:
    Using the ':latest' tag causes non-deterministic image builds. Upstream base image updates
    can introduce unexpected code changes, breaking behavior, or unvetted vulnerability regressions.
    """
    tag = "latest"
    if ':' in target_image:
        tag = target_image.split(':')[-1]
    elif '@' in target_image:
        tag = "pinned-digest"

    is_latest_or_unpinned = tag.lower() in ['latest', 'dev', 'main', 'master', 'canary']
    
    config = attrs.get('Config') or {}
    base_image_env = config.get('Image', 'Unknown')
    
    if is_latest_or_unpinned:
        severity = 'MEDIUM'
        details = (
            f"Image relies on mutable or unpinned tag '{tag}'. "
            "Using ':latest' or unpinned tags compromises build reproducibility and auditability."
        )
    else:
        severity = 'PASS'
        details = f"Image tag is explicitly pinned to '{tag}'."

    return {
        'check_name': 'Base Image & Tag Policy',
        'is_flagged': is_latest_or_unpinned,
        'current_tag': tag,
        'base_image_ref': base_image_env,
        'severity': severity,
        'details': details
    }


def check_secrets(attrs: dict, history: list) -> dict:
    """
    Check 4: Hardcoded Secrets & Sensitive Data Detection
    -----------------------------------------------------
    Scans environment variables ('Config.Env') and Docker history commands
    for secret keyword patterns (e.g. PASSWORD, API_KEY, AWS_ACCESS_KEY, TOKEN).
    
    Educational Note:
    Hardcoding credentials or API tokens in Dockerfile ENV instructions or layer histories
    bakes secrets permanently into public/shared container image layers.
    """
    config = attrs.get('Config') or {}
    env_list = config.get('Env') or []
    
    detected_secrets = []
    
    # 1. Scan Environment Variables
    for env_var in env_list:
        if '=' in env_var:
            key, val = env_var.split('=', 1)
        else:
            key, val = env_var, ""
            
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, key):
                # Obfuscate secret value for safe reporting
                masked_val = val[:3] + "..." + val[-2:] if len(val) > 6 else "***"
                detected_secrets.append({
                    'source': 'Environment Variable',
                    'key': key,
                    'masked_val': masked_val,
                    'secret_type': secret_type,
                    'raw_context': f"ENV {key}={masked_val}"
                })
                break

    # 2. Scan Image Layer History Commands
    for layer in history:
        created_by = layer.get('CreatedBy') or ''
        if not created_by:
            continue
            
        for pattern, secret_type in SECRET_PATTERNS:
            match = re.search(pattern, created_by)
            if match:
                # Truncate and sanitize layer command for report presentation
                clean_cmd = created_by.strip()
                if len(clean_cmd) > 80:
                    clean_cmd = clean_cmd[:77] + "..."
                    
                # Avoid duplicate findings from env sync
                if not any(s['raw_context'] == clean_cmd for s in detected_secrets):
                    detected_secrets.append({
                        'source': 'Dockerfile Layer History',
                        'key': match.group(0),
                        'masked_val': '[Sensitive Command Layer]',
                        'secret_type': secret_type,
                        'raw_context': clean_cmd
                    })

    is_flagged = len(detected_secrets) > 0
    severity = 'HIGH' if is_flagged else 'PASS'
    
    if is_flagged:
        types_found = list(set([s['secret_type'] for s in detected_secrets]))
        details = f"Detected {len(detected_secrets)} possible hardcoded secrets/credentials in image metadata ({', '.join(types_found)})."
    else:
        details = "No hardcoded secret keywords detected in environment variables or layer histories."

    return {
        'check_name': 'Hardcoded Secret Detection',
        'is_flagged': is_flagged,
        'total_detected': len(detected_secrets),
        'detected_secrets': detected_secrets,
        'severity': severity,
        'details': details
    }


def run_all_security_checks(attrs: dict, history: list, target_image: str) -> dict:
    """
    Executes all security checks on the given image inspect dictionary and history list.
    Returns a unified dictionary of security findings.
    """
    root_result = check_root_user(attrs, history)
    ports_result = check_exposed_ports(attrs)
    tag_result = check_base_image(attrs, target_image)
    secrets_result = check_secrets(attrs, history)
    
    return {
        'root_user': root_result,
        'exposed_ports': ports_result,
        'base_image': tag_result,
        'secrets': secrets_result
    }
