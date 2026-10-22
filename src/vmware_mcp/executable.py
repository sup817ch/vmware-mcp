"""Locate VMware Workstation command line tools on Windows."""

import os
from pathlib import Path


def resolve_vmware_executable(
    executable: str, env_var: str, configured_path: str | None = None
) -> str:
    """Prefer an override, then check the 64-bit and legacy install directories."""
    override = configured_path or os.getenv(env_var)
    if override:
        return override

    program_files_dirs = (
        os.getenv("ProgramFiles") or r"C:\Program Files",
        os.getenv("ProgramFiles(x86)") or r"C:\Program Files (x86)",
    )
    candidates = [
        Path(directory) / "VMware" / "VMware Workstation" / executable
        for directory in program_files_dirs
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    checked_paths = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(
        f"Could not find {executable}. Checked: {checked_paths}. "
        f"Set {env_var} to the full path to {executable}."
    )
