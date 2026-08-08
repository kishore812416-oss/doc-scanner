"""
Docker Analyzer Module
----------------------
Handles Docker SDK client initialization, image pulling, input validation,
and metadata extraction (image.attrs and image.history()).

Educational context:
This module demonstrates how to interact with the Docker Engine daemon programmatically
using the Docker SDK for Python (docker-py).
"""

import re
import logging
import docker
from docker.errors import ImageNotFound, APIError, DockerException

logger = logging.getLogger(__name__)

# Custom Exception Classes for structured error handling
class ScannerError(Exception):
    """Base exception class for security scanner errors."""
    pass

class InvalidImageNameError(ScannerError):
    """Raised when the user provides an invalid Docker image name format."""
    pass

class DockerDaemonError(ScannerError):
    """Raised when Docker Desktop / Engine daemon is not running or unreachable."""
    pass

class ImageNotFoundError(ScannerError):
    """Raised when the image is not found locally and cannot be pulled from registry."""
    pass

class DockerAnalysisError(ScannerError):
    """Raised when an unexpected Docker API error occurs during inspection."""
    pass


def validate_image_name(image_name: str) -> bool:
    """
    Validates Docker image name format using regex.
    Allowed examples: 'nginx', 'nginx:latest', 'library/ubuntu:20.04', 'my-registry.com/app:v1'
    
    Educational Note:
    Docker image names follow strict naming conventions:
    [registry_host[:port]/][namespace/]repository[:tag|@digest]
    """
    if not image_name or not isinstance(image_name, str):
        return False
    
    image_name = image_name.strip()
    if len(image_name) > 255:
        return False
    
    # Regex matching standard docker image reference format
    pattern = r'^(?:[a-zA-Z0-9._-]+(?::[0-9]+)?/)?(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+(?::[a-zA-Z0-9._-]+)?(?:@[a-zA-Z0-9:]+)?$'
    return bool(re.match(pattern, image_name))


def get_docker_client():
    """
    Initializes and returns a Docker SDK client connected to local Docker daemon.
    Raises DockerDaemonError if the daemon is not running.
    """
    try:
        # docker.from_env() automatically reads DOCKER_HOST and standard OS socket/pipe configurations
        client = docker.from_env(timeout=30)
        # Test connection ping
        client.ping()
        return client
    except DockerException as e:
        logger.warning(f"Failed to connect to Docker daemon: {e}")
        raise DockerDaemonError(
            "Docker daemon is not running or unreachable. "
            "Please ensure Docker Desktop is started and running locally."
        )
    except Exception as e:
        logger.warning(f"Unexpected connection error to Docker daemon: {e}")
        raise DockerDaemonError(
            "Unable to establish connection to Docker daemon. "
            "Verify Docker Desktop service permissions."
        )


def fetch_and_inspect_image(image_name: str, force_pull: bool = False):
    """
    Pulls (if needed) and inspects a Docker image.
    
    Returns a dictionary containing:
    - attrs: Raw docker inspect dictionary (Config, ContainerConfig, Architecture, OS, etc.)
    - history: Layer history list from docker history API
    - metadata: Clean extracted attributes (ID, Tags, Size, Created, etc.)
    - is_simulated: Boolean indicating if real Docker daemon or fallback mock was used.
    
    Educational Note:
    - 'image.attrs' contains low-level Docker metadata (Config.User, ExposedPorts, Env, etc.)
    - 'image.history()' lists layer commands (Dockerfile steps like RUN, ENV, EXPOSE, USER)
    """
    image_name = image_name.strip()
    
    # Step 1: Validate input
    if not validate_image_name(image_name):
        raise InvalidImageNameError(
            f"Invalid Docker image name format: '{image_name}'. "
            "Examples of valid names: 'nginx:latest', 'python:3.9-slim', 'ubuntu:22.04'."
        )

    # Normalize image tag (append ':latest' if no tag specified and no digest)
    target_image = image_name
    if ':' not in target_image and '@' not in target_image:
        target_image = f"{image_name}:latest"

    # Step 2: Attempt Docker Daemon interaction
    client = get_docker_client()
    image = None
    
    try:
        if not force_pull:
            try:
                # Try retrieving image locally first to avoid unnecessary download
                logger.info(f"Looking for local image '{target_image}'...")
                image = client.images.get(target_image)
            except ImageNotFound:
                logger.info(f"Image '{target_image}' not found locally. Pulling from Docker Hub...")
                image = client.images.pull(target_image)
        else:
            logger.info(f"Force pulling image '{target_image}' from registry...")
            image = client.images.pull(target_image)

    except ImageNotFound:
        raise ImageNotFoundError(
            f"Docker image '{target_image}' could not be found on Docker Hub or local repository."
        )
    except APIError as e:
        logger.error(f"Docker API Error while pulling/inspecting {target_image}: {e}")
        raise DockerAnalysisError(
            f"Docker API error occurred while processing '{target_image}': {e.explanation or str(e)}"
        )
    except Exception as e:
        logger.error(f"Error fetching image {target_image}: {e}")
        raise DockerAnalysisError(f"Failed to inspect image '{target_image}': {str(e)}")

    # Step 3: Extract Inspect Data & Layer History
    attrs = image.attrs or {}
    
    try:
        history = image.history() or []
    except Exception as e:
        logger.warning(f"Could not fetch history for {target_image}: {e}")
        history = []

    # Format extracted metadata
    repo_tags = attrs.get('RepoTags') or [target_image]
    size_bytes = attrs.get('Size', 0)
    size_mb = round(size_bytes / (1024 * 1024), 2)
    created_date = attrs.get('Created', 'Unknown')
    
    # Truncate ISO timestamp for clean display
    if 'T' in created_date:
        created_date = created_date.split('T')[0]

    metadata = {
        'id': (attrs.get('Id') or '')[7:19] if attrs.get('Id') else 'Unknown',
        'full_id': attrs.get('Id', 'Unknown'),
        'target_image': target_image,
        'repo_tags': repo_tags,
        'size_mb': size_mb,
        'size_bytes': size_bytes,
        'created': created_date,
        'architecture': attrs.get('Architecture', 'amd64'),
        'os': attrs.get('Os', 'linux'),
        'docker_version': attrs.get('DockerVersion', 'Unknown'),
        'author': attrs.get('Author', ''),
        'comment': attrs.get('Comment', ''),
    }

    return {
        'attrs': attrs,
        'history': history,
        'metadata': metadata,
        'is_simulated': False
    }


def get_mock_image_data(image_name: str):
    """
    Generates realistic simulated Docker image inspect & history structures for offline testing
    or educational preview when Docker Engine daemon is offline.
    """
    image_name = image_name.strip()
    if ':' not in image_name:
        image_name = f"{image_name}:latest"
        
    tag = image_name.split(':')[-1]
    repo = image_name.split(':')[0]
    
    # Pre-baked metadata profiles for popular sample test images
    if 'nginx' in repo:
        user = ""
        ports = {"80/tcp": {}, "443/tcp": {}, "22/tcp": {}}
        env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "NGINX_VERSION=1.25.3"]
        history = [
            {"CreatedBy": "EXPOSE 80 443 22", "Size": 0},
            {"CreatedBy": "ENV NGINX_VERSION=1.25.3", "Size": 0},
            {"CreatedBy": "CMD [\"nginx\" \"-g\" \"daemon off;\"]", "Size": 0}
        ]
    elif 'vulnerable' in repo or 'test-sec' in repo:
        user = "root"
        ports = {"22/tcp": {}, "23/tcp": {}, "3389/tcp": {}, "8080/tcp": {}}
        env = [
            "PATH=/usr/local/bin",
            "ADMIN_PASSWORD=SuperSecretPass123!",
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
            "DATABASE_URL=postgres://root:secret_token@db:5432/production"
        ]
        history = [
            {"CreatedBy": "ENV ADMIN_PASSWORD=SuperSecretPass123!", "Size": 0},
            {"CreatedBy": "ENV AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "Size": 0},
            {"CreatedBy": "EXPOSE 22 23 3389 8080", "Size": 0},
            {"CreatedBy": "RUN apt-get update && apt-get install -y openssh-server", "Size": 45000000}
        ]
    elif 'alpine' in repo or 'python' in repo or 'node' in repo:
        user = "appuser" if "alpine" not in repo else ""
        ports = {"8080/tcp": {}}
        env = ["PATH=/usr/local/bin:/bin", "NODE_ENV=production"]
        history = [
            {"CreatedBy": "USER appuser", "Size": 0},
            {"CreatedBy": "EXPOSE 8080", "Size": 0},
            {"CreatedBy": "CMD [\"node\" \"server.js\"]", "Size": 0}
        ]
    else:
        user = ""
        ports = {"80/tcp": {}}
        env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
        history = [{"CreatedBy": "CMD [\"sh\"]", "Size": 0}]

    attrs = {
        "Id": "sha256:a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "RepoTags": [image_name],
        "Created": "2024-03-15T12:00:00Z",
        "Size": 142500000,
        "Architecture": "amd64",
        "Os": "linux",
        "DockerVersion": "24.0.7",
        "Config": {
            "User": user,
            "ExposedPorts": ports,
            "Env": env,
            "Image": "debian:bullseye-slim",
            "WorkingDir": "/app",
            "Cmd": ["sh"]
        },
        "ContainerConfig": {
            "User": user
        }
    }

    metadata = {
        'id': 'a1b2c3d4e5f6',
        'full_id': attrs['Id'],
        'target_image': image_name,
        'repo_tags': [image_name],
        'size_mb': 135.89,
        'size_bytes': 142500000,
        'created': '2024-03-15',
        'architecture': 'amd64',
        'os': 'linux',
        'docker_version': '24.0.7',
        'author': '',
        'comment': 'Simulated Docker Inspection Data',
    }

    return {
        'attrs': attrs,
        'history': history,
        'metadata': metadata,
        'is_simulated': True
    }
