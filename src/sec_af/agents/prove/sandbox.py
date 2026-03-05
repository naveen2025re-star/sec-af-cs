from __future__ import annotations

import asyncio
import resource
import shutil
import sys
from dataclasses import dataclass


@dataclass(slots=True)
class SandboxConfig:
    timeout_seconds: int = 30
    network_disabled: bool = True
    max_memory_mb: int = 256
    max_file_size_mb: int = 2
    max_processes: int = 8
    max_cpu_seconds: int = 5


def _network_sandbox_prefix(config: SandboxConfig) -> list[str]:
    if not config.network_disabled:
        return []

    if sys.platform == "darwin":
        if shutil.which("sandbox-exec"):
            profile = "(version 1) (deny default) (allow process*) (allow file-read*) (allow file-write*)"
            return ["sandbox-exec", "-p", profile]
        msg = "network isolation unavailable: sandbox-exec not found"
        raise RuntimeError(msg)

    if shutil.which("unshare"):
        return ["unshare", "-n", "--"]

    msg = "network isolation unavailable: unshare not found"
    raise RuntimeError(msg)


def _set_limits(config: SandboxConfig) -> None:
    memory_bytes = max(1, config.max_memory_mb) * 1024 * 1024
    file_size_bytes = max(1, config.max_file_size_mb) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CPU, (config.max_cpu_seconds, config.max_cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
    resource.setrlimit(resource.RLIMIT_NPROC, (config.max_processes, config.max_processes))


async def run_in_sandbox(command: str, cwd: str, config: SandboxConfig) -> tuple[str, str, int]:
    try:
        prefix = _network_sandbox_prefix(config)
    except RuntimeError as exc:
        return "", str(exc), 126

    process = await asyncio.create_subprocess_exec(
        *prefix,
        "/bin/sh",
        "-lc",
        command,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        preexec_fn=lambda: _set_limits(config),
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=config.timeout_seconds)
    except TimeoutError:
        process.kill()
        _ = await process.wait()
        return "", f"Command timed out after {config.timeout_seconds}s", 124

    return (
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
        int(process.returncode or 0),
    )
