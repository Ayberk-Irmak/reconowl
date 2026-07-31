"""Discovery and invocation of the external CLI tools Strix orchestrates."""

from __future__ import annotations

import shutil
import subprocess

#: name -> role. Every one is optional; Strix degrades to native checks.
EXTERNAL_TOOLS: dict[str, str] = {
    "nmap": "Port/service/version scanning",
    "httpx": "Fast HTTP probing and tech detection",
    "nuclei": "Template-based vulnerability scanning",
    "sqlmap": "SQL injection confirmation",
    "nikto": "Web server misconfiguration scanning",
    "whatweb": "Web technology fingerprinting",
    "wafw00f": "WAF detection",
    "subfinder": "Passive subdomain enumeration",
    "whois": "WHOIS lookups",
}


def find_tool(name: str) -> str | None:
    """Absolute path to ``name`` on PATH, or None."""
    return shutil.which(name)


def header_flags(headers: dict[str, str], flag: str = "-H") -> list[str]:
    """Turn a headers dict into repeated CLI header flags, e.g. -H 'K: V'."""
    args: list[str] = []
    for key, value in (headers or {}).items():
        args += [flag, f"{key}: {value}"]
    return args


def available_tools() -> dict[str, str | None]:
    """Map every known external tool to its path (or None)."""
    return {name: find_tool(name) for name in EXTERNAL_TOOLS}


def run(
    program: str,
    args: list[str],
    *,
    timeout: float = 300.0,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    """Run a command to completion, capturing output.

    Returns ``(returncode, stdout, stderr)``. On timeout or failure to start,
    returns a non-zero code with the error text in stderr rather than raising.
    """
    path = find_tool(program) or program
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{program}: not found"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out, f"{program}: timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001 - never let a tool crash the run
        return 1, "", f"{program}: {exc}"
