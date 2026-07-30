import json
import logging
import subprocess

from anaconda_auth.config import AnacondaAuthConfig

logger = logging.getLogger(__name__)


def is_env_manager_installed(conda_path: str) -> bool:
    """Check if anaconda-env-manager is installed in the base environment."""
    config = AnacondaAuthConfig()
    args = [conda_path, "list", "-n", "base", config.env_manager_package, "--json"]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.debug(
            "Failed to check for %s: %s", config.env_manager_package, proc.stderr
        )
        return False

    try:
        packages = json.loads(proc.stdout)
        return any(pkg.get("name") == config.env_manager_package for pkg in packages)
    except (json.JSONDecodeError, TypeError):
        return False


def _tos_plugin_available(conda_path: str) -> bool:
    """Check whether conda-anaconda-tos provides the `conda tos` subcommand."""
    proc = subprocess.run(
        [conda_path, "tos", "--json", "info"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        # Non-zero could mean many things (missing plugin, renamed
        # subcommand, bad args); log it so failures stay traceable.
        logger.debug(
            "conda tos probe failed (exit code %d): %s",
            proc.returncode,
            proc.stderr.strip() or proc.stdout.strip(),
        )
    return proc.returncode == 0


def install_env_manager(conda_path: str) -> tuple[bool, str]:
    """Install anaconda-env-manager into the base environment.

    Note:
        ToS acceptance is best-effort: `conda tos interactive` only runs
        (with inherited stdio) when the plugin is available, and its result
        never blocks the install. `conda install` enforces the real ToS
        gate itself, with a proper `--json` error message if rejected.
    """
    config = AnacondaAuthConfig()

    if _tos_plugin_available(conda_path):
        subprocess.run([conda_path, "tos", "interactive"])

    pkg = f"{config.env_manager_channel}::{config.env_manager_package}{config.env_manager_version or ''}"
    args = [conda_path, "install", "--name", "base", pkg, "--yes", "--json"]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        error = f"conda install exited with code {proc.returncode}."
        message = None
        try:
            message = json.loads(proc.stdout).get("message")
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        # Fall back to stderr if conda crashed before writing JSON output.
        detail = message or proc.stderr.strip()
        if detail:
            error = f"{error} {detail}"
        logger.debug("Failed to install %s: %s\nstderr: %s", pkg, error, proc.stderr)
        return False, error
    return True, ""


def get_client_token(conda_path: str) -> str | None:
    """Retrieve the anaconda-anon-usage client token via conda run."""
    args = [
        conda_path,
        "run",
        "-n",
        "base",
        "--no-capture-output",
        "python",
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
