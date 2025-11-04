# Linux-only utilities to ensure Miniconda3 is silently installed and `conda info` works.

import os
import tempfile
import requests
import logging
import sys
import shutil
from src.common.cli_utils import capture
from src.common.defaults import LINUX_INSTALLER_URL

logger = logging.getLogger(__name__)

# Target installation directory under HOME
INSTALL_DIR = os.path.expanduser("~/miniconda3")

def download_miniconda_installer() -> str:
    """
    Download the Miniconda installer script into a temporary file.
    Returns the local file path.
    """
    installer_url = LINUX_INSTALLER_URL
    local_file = os.path.join(tempfile.gettempdir(), os.path.basename(installer_url))
   
    logger.info("Downloading Miniconda installer from %s", installer_url)
    resp = requests.get(installer_url, stream=True)
    resp.raise_for_status()
   
    with open(local_file, "wb") as f:
        for chunk in resp.iter_content(8192):
            f.write(chunk)
   
    logger.info("Downloaded installer to %s", local_file)
    return local_file

def install_miniconda(installer_path: str) -> tuple[bytes, int]:
    """
    Silently install Miniconda under INSTALL_DIR.
    Returns (stdout, returncode).
    """
    logger.info("Installing Miniconda from %s into %s", installer_path, INSTALL_DIR)
   
    # ensure basic PATH so internal tools (grep, mv) are found
    env = os.environ.copy()
    if not env.get("PATH"):
        env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
   
    cmd = f"/bin/bash {installer_path} -b -p {INSTALL_DIR}"
    out_install, install_code = capture(cmd, timeout=600)
    logger.info("Miniconda install returncode=%d", install_code)
   
    assert install_code == 0, f"Miniconda failed to install (code={install_code}): {out_install.decode(errors='ignore')}"
   
    return out_install, install_code

def conda_executable_path() -> str:
    """
    Determine which conda to use: existing on PATH or installed one under INSTALL_DIR.
    """
    path = shutil.which('conda')
    if path:
        return 'conda'
    return os.path.join(INSTALL_DIR, 'bin', 'conda')

def ensure_conda_installed() -> tuple[bytes, int]:
    """
    Ensure `conda info` works on Linux:
      - Try `conda info` on PATH first
      - If that fails, try installed conda under INSTALL_DIR
      - If neither exists, download+install Miniconda3, then run it
    Returns (stdout, returncode) that should be successful.
    """
    # 1) Try any conda on PATH
    out, code = capture("conda info")
    logger.info(f"`conda info` on PATH returned code: {code}")
    
    if code == 0:
        logger.info("`conda info` succeeded on PATH")
        return out, code
   
    # 2) Fallback: if already installed under INSTALL_DIR
    conda_bin = os.path.join(INSTALL_DIR, 'bin', 'conda')
    if os.path.exists(conda_bin) and os.access(conda_bin, os.X_OK):
        logger.info("Using existing install at %s", conda_bin)
        out, code = capture(f"{conda_bin} info")
        if code == 0:
            return out, code
   
    # 3) Need to download & install
    logger.warning("`conda` not found; installing Miniconda3…")
    installer = download_miniconda_installer()
    out_install, install_code = install_miniconda(installer)
   
    # 4) Run the newly installed conda
    logger.info("Running conda info from installed binary")
    out, code = capture(f"{conda_bin} info")
    
    # Final assert - conda should work after installation
    assert code == 0, f"conda info failed even after installation. Exit code: {code}, Output: {out.decode(errors='ignore')}"
    
    logger.info("✅ conda info succeeded after installation")
    return out, code