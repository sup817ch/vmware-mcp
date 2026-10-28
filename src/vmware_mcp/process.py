"""Run VMware CLIs without inheriting the MCP protocol's standard input."""

import asyncio
import math
import os
import re
import signal
import subprocess


_ANSI_ESCAPE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]"
)
_PASSWORD_PROMPT = re.compile(r"Encrypted virtual machine password:\s*", re.I)


def redact(text: str, *secrets: str) -> str:
    for secret in sorted(set(secrets) - {""}, key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def _console_text(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text).replace("\r", "")


def _command_timeout() -> float:
    try:
        timeout = float(os.getenv("VMWARE_COMMAND_TIMEOUT", "300"))
    except ValueError:
        raise ValueError("VMWARE_COMMAND_TIMEOUT must be a positive number") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("VMWARE_COMMAND_TIMEOUT must be a positive number")
    return timeout


async def _run_piped(cmd: list[str]) -> tuple[int, str]:
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )
    try:
        stdout, stderr = await proc.communicate()
        output = stdout if proc.returncode == 0 else stderr.strip() or stdout
        return proc.returncode, output.decode("utf-8", errors="replace").strip()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def _run_console(cmd: list[str], password: str) -> tuple[int, str]:
    """vmcli reads its encryption password with Windows console APIs, not a pipe."""
    if os.name != "nt":
        raise RuntimeError("Encrypted vmcli commands require a Windows console")
    if "\r" in password or "\n" in password:
        raise ValueError("vm_password cannot contain a newline for vmcli")
    try:
        from winpty import Backend, PTY
    except ImportError:
        raise RuntimeError(
            "Encrypted vmcli commands require pywinpty; reinstall vmware-mcp's dependencies"
        ) from None

    terminal = PTY(1024, 40, backend=Backend.ConPTY)
    output = ""
    password_sent = False
    prompt_offset = 0
    try:
        # list2cmdline follows Windows argument quoting; no command shell is used.
        terminal.spawn(cmd[0], cmdline=subprocess.list2cmdline(cmd[1:]))
        while True:
            try:
                chunk = terminal.read(blocking=False)
            except Exception:
                if terminal.isalive():
                    raise
                break
            if chunk:
                output += chunk
                plain_output = _console_text(output)
                prompt = _PASSWORD_PROMPT.search(plain_output, prompt_offset)
                if prompt:
                    if password_sent:
                        raise RuntimeError("VM encryption password was rejected")
                    terminal.write(password + "\r")
                    password_sent = True
                    prompt_offset = prompt.end()
            elif not terminal.isalive():
                break
            await asyncio.sleep(0.02)
        returncode = terminal.get_exitstatus()
        if returncode is None:
            raise RuntimeError("vmcli exited without a process exit status")
        return returncode, _PASSWORD_PROMPT.sub("", _console_text(output)).strip()
    finally:
        try:
            if terminal.isalive():
                # This PID belongs to the command spawned above, never the VM process.
                os.kill(terminal.pid, signal.SIGTERM)
        except OSError:
            pass
        terminal.cancel_io()


async def run_command(
    cmd: list[str],
    *,
    tool: str,
    console_password: str | None = None,
    secrets: tuple[str, ...] = (),
) -> str:
    timeout = _command_timeout()
    secrets = (*secrets, console_password or "")
    try:
        operation = (
            _run_console(cmd, console_password)
            if console_password
            else _run_piped(cmd)
        )
        returncode, output = await asyncio.wait_for(operation, timeout)
    except asyncio.TimeoutError:
        raise RuntimeError(f"{tool} timed out after {timeout:g} seconds") from None
    except (FileNotFoundError, asyncio.CancelledError):
        raise
    except Exception as exc:
        raise RuntimeError(f"{tool} failed: {redact(str(exc), *secrets)}") from None

    output = redact(output, *secrets)
    if returncode != 0:
        if (
            "password is required for this operation" in output.lower()
            or "getting password from stdin" in output.lower()
        ):
            output += " Pass vm_password or set VMWARE_VM_PASSWORD for the VM encryption password."
        raise RuntimeError(f"{tool} failed: {output}")
    return output
