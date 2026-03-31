import json
import logging
import subprocess

logger = logging.getLogger(__name__)

ENV_MANAGER_PACKAGE = "anaconda-env-manager"
# Todo: This will change and will be pulled from defaults
ENV_MANAGER_CHANNEL = "anaconda-cloud"


def is_env_manager_installed(conda_path: str) -> bool:
    """Check if anaconda-env-manager is installed in the base environment."""
    args = [conda_path, "list", "-n", "base", ENV_MANAGER_PACKAGE, "--json"]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.debug("Failed to check for %s: %s", ENV_MANAGER_PACKAGE, proc.stderr)
        return False

    try:
        packages = json.loads(proc.stdout)
        return any(pkg.get("name") == ENV_MANAGER_PACKAGE for pkg in packages)
    except (json.JSONDecodeError, TypeError):
        return False


def install_env_manager(conda_path: str) -> tuple[bool, str]:
    """Install anaconda-env-manager into the base environment.

    Returns:
        Tuple of (success, error_message).
    """
    args = [
        conda_path,
        "install",
        "--name",
        "base",
        f"{ENV_MANAGER_CHANNEL}::{ENV_MANAGER_PACKAGE}",
        "-y",
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        error = proc.stderr.strip() or proc.stdout.strip()
        logger.debug("Failed to install %s: %s", ENV_MANAGER_PACKAGE, error)
        return False, error
    return True, ""


def get_client_token(conda_path: str) -> str | None:
    """Retrieve the anaconda-anon-usage client token via subprocess."""
    python_path = conda_path.replace("/bin/conda", "/bin/python")
    args = [
        python_path,
        "-c",
        "from anaconda_anon_usage.tokens import client_token; print(client_token())",
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.debug("Failed to get client token: %s", proc.stderr)
        return None
    return proc.stdout.strip() or None


def is_client_registered(conda_path: str) -> bool:
    """Check if the client token is already registered.

    Retrieves the client token from anaconda-anon-usage and checks with the
    read-only client-token-status endpoint.
    """
    token = get_client_token(conda_path)
    if not token:
        return False

    from anaconda_auth.env_logger import check_client_token_status

    return check_client_token_status(token)


def register_org(conda_path: str) -> bool:
    """Register with an organization via conda env-log.

    Delegates org selection and registration to the plugin command.
    The subprocess inherits stdio so the plugin can interact with the user.
    """
    args = [conda_path, "env-log", "register"]
    proc = subprocess.run(args)
    if proc.returncode != 0:
        logger.debug("Failed to register org (exit code %d)", proc.returncode)
        return False
    return True
