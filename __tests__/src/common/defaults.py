# src/common/defaults.py
# ─── Constants for anaconda‐auth testing ───────────────────────────────
PACKAGE_NAME              = "anaconda-auth"     # the conda package name
CLI_SUBCOMMAND            = "anaconda auth"     # what you actually run on the CLI
ANACONDA_AUTH_VERSION     = "0.8.6"             # what we expect for --version/-V
CONDA_VERSION             = "25.5.1"            # conda version to test against

# ─── Conda Installation ──────────────────────────────────────────────
LINUX_INSTALLER_URL       = "https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh"

# ─── Version flags to verify ──────────────────────────────────────────
VERSION_FLAGS        = ["--version", "-V"]

# ─── Timeouts (in milliseconds for playwright, seconds for subprocess) ─
PAGE_LOAD_TIMEOUT    = 45_000   # timeout for page.goto / expect
NETWORK_IDLE_TIMEOUT = 45_000   # timeout for networkidle waits
OAUTH_CAPTURE_TIMEOUT= 30       # seconds to capture the CLI's oauth URL
CLI_COMPLETION_TIME  = 40       # seconds to wait for CLI to exit

# ─── Expected UI text ─────────────────────────────────────────────────
EXPECTED_TEXT = {
    "welcome": "Welcome Back",
    "success": "Success! You are now logged in."
}

# ─── URL‐fragments to look for ────────────────────────────────────────
URL_PATTERNS = {
    "oauth":   "/api/auth/oauth2/authorize",
    "success": "/local-login-success",
}

# ─── Timeouts for conda commands (in seconds) ────────────────────────
INSTALL_TIMEOUT      = 300
LIST_TIMEOUT         = 30

# ─── Retry policy ────────────────────────────────────────────────────
MAX_RETRIES          = 3

# ─── Conda configuration constants ───────────────────────────────────
DEFAULT_CHANNEL      = "defaults"
EXPECTED_CHANNEL     = "pkgs/main"
SEARCH_PACKAGE       = "flask"
SEARCH_HEADER_PREFIX = "# name"