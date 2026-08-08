"""
Docker Image Security Scanner - Flask Web Application
------------------------------------------------------
Flask routes, form handlers, input validation, and controller logic for the
beginner-friendly Docker image security analyzer.

Educational Context:
This application orchestrates Docker SDK pulling, metadata inspection, security rules,
risk score computation, and HTML presentation.
"""

import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from scanner.docker_analyzer import (
    fetch_and_inspect_image,
    get_mock_image_data,
    get_docker_client,
    InvalidImageNameError,
    DockerDaemonError,
    ImageNotFoundError,
    DockerAnalysisError
)
from scanner.security_checker import run_all_security_checks
from scanner.risk_assessment import calculate_risk_score
from scanner.report_generator import generate_full_report

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("app")

app = Flask(__name__)
app.secret_key = "docker-sec-scan-secret-key-academic-use"


def check_docker_engine_connected() -> bool:
    """Helper to verify if local Docker Desktop / Engine daemon is reachable."""
    try:
        get_docker_client()
        return True
    except Exception:
        return False


@app.route('/', methods=['GET'])
def index():
    """
    Renders home scan page with image input form and Docker status.
    """
    is_docker_connected = check_docker_engine_connected()
    return render_template(
        'index.html',
        is_docker_connected=is_docker_connected,
        default_image="nginx:latest"
    )


@app.route('/scan', methods=['POST'])
def scan_image():
    """
    Primary POST route for analyzing a Docker image from form submission.
    """
    image_name = request.form.get('image_name', '').strip()
    force_pull = request.form.get('force_pull') == 'true'
    
    # Check Docker engine availability for index status indicator
    is_docker_connected = check_docker_engine_connected()

    # 1. Basic Input Validation
    if not image_name:
        return render_template(
            'index.html',
            error_message="Please enter a valid Docker image name (e.g. 'nginx:latest').",
            is_docker_connected=is_docker_connected,
            default_image=""
        ), 400

    try:
        # 2. Pull and Inspect Docker Image via SDK
        inspection_data = fetch_and_inspect_image(image_name, force_pull=force_pull)

    except InvalidImageNameError as e:
        logger.warning(f"Invalid image format: {image_name}")
        return render_template(
            'index.html',
            error_message=str(e),
            is_docker_connected=is_docker_connected,
            default_image=image_name
        ), 400

    except ImageNotFoundError as e:
        logger.warning(f"Image not found: {image_name}")
        return render_template(
            'index.html',
            error_message=str(e),
            is_docker_connected=is_docker_connected,
            default_image=image_name
        ), 444

    except DockerDaemonError as e:
        logger.info(f"Docker Engine offline ({e}). Falling back to simulated offline analysis mode.")
        # Fallback to simulated offline inspect data so user can test the UI anytime
        inspection_data = get_mock_image_data(image_name)

    except DockerAnalysisError as e:
        logger.error(f"Analysis error for {image_name}: {e}")
        return render_template(
            'index.html',
            error_message=f"Docker Analysis Error: {str(e)}",
            is_docker_connected=is_docker_connected,
            default_image=image_name
        ), 500

    except Exception as e:
        logger.error(f"Unexpected error scanning {image_name}: {e}", exc_info=True)
        return render_template(
            'index.html',
            error_message=f"An unexpected system error occurred: {str(e)}",
            is_docker_connected=is_docker_connected,
            default_image=image_name
        ), 500

    # 3. Run Security Checks
    attrs = inspection_data.get('attrs', {})
    history = inspection_data.get('history', [])
    metadata = inspection_data.get('metadata', {})
    target_image = metadata.get('target_image', image_name)

    check_results = run_all_security_checks(attrs, history, target_image)

    # 4. Calculate Risk Score & Level
    risk_assessment = calculate_risk_score(check_results)

    # 5. Generate Recommendations & Consolidated Report
    report = generate_full_report(image_name, inspection_data, check_results, risk_assessment)

    # 6. Render Report Dashboard Page
    return render_template('report.html', report=report)


@app.route('/api/scan', methods=['POST'])
def api_scan_image():
    """
    JSON API endpoint for programmatic image scanning.
    Accepts JSON body: {"image_name": "nginx:latest", "force_pull": false}
    """
    data = request.get_json(silent=True) or {}
    image_name = data.get('image_name', '').strip()
    force_pull = bool(data.get('force_pull', False))

    if not image_name:
        return jsonify({'error': 'Parameter "image_name" is required.'}), 400

    try:
        inspection_data = fetch_and_inspect_image(image_name, force_pull=force_pull)
    except DockerDaemonError:
        inspection_data = get_mock_image_data(image_name)
    except (InvalidImageNameError, ImageNotFoundError) as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f"Failed to analyze image: {str(e)}"}), 500

    attrs = inspection_data.get('attrs', {})
    history = inspection_data.get('history', [])
    target_image = inspection_data.get('metadata', {}).get('target_image', image_name)

    check_results = run_all_security_checks(attrs, history, target_image)
    risk_assessment = calculate_risk_score(check_results)
    report = generate_full_report(image_name, inspection_data, check_results, risk_assessment)

    return jsonify(report), 200


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint returning system & Docker Engine status.
    """
    is_docker_connected = check_docker_engine_connected()
    return jsonify({
        'status': 'healthy',
        'app': 'Docker Image Security Scanner',
        'docker_engine_connected': is_docker_connected
    }), 200


if __name__ == '__main__':
    logger.info("Starting Docker Image Security Scanner web server on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
