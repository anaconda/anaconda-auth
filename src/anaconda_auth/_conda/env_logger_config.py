import json
import logging
import subprocess

from anaconda_auth._conda.conda_api import Commands
from anaconda_auth._conda.conda_api import run_command

logger = logging.getLogger(__name__)

ENV_MANAGER_PACKAGE = "anaconda-env-manager"
# Todo: This will change and will be pulled from defaults
ENV_MANAGER_CHANNEL = "anaconda-cloud"


def is_env_manager_installed() -> bool:
    """Check if anaconda-env-manager is installed in the base environment."""
    stdout, stderr, returncode = run_command(
        Commands.LIST, "-n", "base", ENV_MANAGER_PACKAGE, "--json"
    )
    if returncode != 0:
        logger.debug("Failed to check for %s: %s", ENV_MANAGER_PACKAGE, stderr)
        return False

    try:
        packages = json.loads(stdout)
        return any(pkg.get("name") == ENV_MANAGER_PACKAGE for pkg in packages)
    except (json.JSONDecodeError, TypeError):
        return False


def install_env_manager() -> tuple[bool, str]:
    """Install anaconda-env-manager into the base environment.

    Returns:
        Tuple of (success, error_message).
    """
    args = [
        "conda",
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


def register_org() -> bool:
    """Register with an organization via conda env-log.

    Delegates org selection and registration to the plugin command.
    """
    args = ["conda", "env-log", "register"]
    proc = subprocess.run(args)
    if proc.returncode != 0:
        logger.debug("Failed to register org: %s", proc.stderr)
        return False
    return True
