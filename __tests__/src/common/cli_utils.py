import subprocess
import logging

logger = logging.getLogger(__name__)

def capture(cmd: str, timeout: int = 60):
    """
    Run a CLI command and return (stdout_bytes, returncode),
    while logging both stdout and stderr.
    """
    logger.info(f"⟶ Running command: {cmd!r}")
    proc = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )

    out = proc.stdout or b""
    err = proc.stderr or b""

    # Log the actual output
    try:
        text_out = out.decode(errors="ignore")
        logger.info(f"🔹 Stdout ({cmd!r}):\n{text_out}")
    except Exception:
        logger.info(f"🔹 Stdout ({cmd!r}, binary): {out!r}")

    if err:
        try:
            text_err = err.decode(errors="ignore")
            logger.info(f"🔴 Stderr ({cmd!r}):\n{text_err}")
        except Exception:
            logger.info(f"🔴 Stderr ({cmd!r}, binary): {err!r}")

    return out, proc.returncode


def launch_subprocess(command, env):
    """
    Launch subprocess with pipes for interaction.
    Wrapper for subprocess.Popen similar to capture() but for interactive processes.
    """
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        bufsize=0
    )


def terminate_process(proc):
    """Safely terminate a subprocess."""
    if proc.poll() is None:
        proc.terminate()
        proc.wait(timeout=5)