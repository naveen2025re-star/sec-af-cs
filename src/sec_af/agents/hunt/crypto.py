from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from sec_af.agents._utils import extract_harness_result

from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "crypto.txt"

_SECURITY_CRITICAL_TERMS = (
    "password",
    "passwd",
    "credential",
    "auth",
    "token",
    "session",
    "encrypt",
    "decrypt",
    "signature",
    "sign",
    "verify",
    "jwt",
    "tls",
    "ssl",
    "key",
)

_NON_SECURITY_TERMS = (
    "checksum",
    "etag",
    "cache",
    "fingerprint",
    "dedup",
    "integrity",
)


def should_run_crypto_hunter(recon: ReconResult) -> bool:
    return bool(recon.security_context.crypto_usage)


def _crypto_usage_context_block(recon: ReconResult) -> str:
    return json.dumps([usage.model_dump() for usage in recon.security_context.crypto_usage], indent=2)


def _is_security_critical_usage(usage_context: str | None) -> bool:
    if not usage_context:
        return False

    lowered = usage_context.lower()
    if any(term in lowered for term in _NON_SECURITY_TERMS):
        return False
    return any(term in lowered for term in _SECURITY_CRITICAL_TERMS)


def _crypto_usage_context_summary(recon: ReconResult) -> str:
    security_critical: list[str] = []
    non_security: list[str] = []
    unknown: list[str] = []

    for usage in recon.security_context.crypto_usage:
        usage_context = usage.usage_context or "unspecified"
        mode = f"/{usage.mode}" if usage.mode else ""
        key_size = f" key_size={usage.key_size}" if usage.key_size is not None else ""
        weak = " weak=true" if usage.is_weak else ""
        summary = f"- {usage.algorithm}{mode}: context={usage_context}{key_size}{weak}"
        if _is_security_critical_usage(usage.usage_context):
            security_critical.append(summary)
        elif usage.usage_context and any(term in usage.usage_context.lower() for term in _NON_SECURITY_TERMS):
            non_security.append(summary)
        else:
            unknown.append(summary)

    blocks: list[str] = []
    if security_critical:
        blocks.append("Security-critical usage candidates:\n" + "\n".join(security_critical))
    if non_security:
        blocks.append("Non-security usage candidates:\n" + "\n".join(non_security))
    if unknown:
        blocks.append("Unclear context usage candidates:\n" + "\n".join(unknown))

    if not blocks:
        return "No crypto usage patterns were detected by recon."

    return "\n\n".join(blocks)


async def run_crypto_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    if not should_run_crypto_hunter(recon):
        return HuntResult()

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{CRYPTO_USAGE_JSON}}", _crypto_usage_context_block(recon)).replace(
            "{crypto_context}", _crypto_usage_context_summary(recon)
        )
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Hunt strategy: crypto\n"
        + f"- Early stop rule: if you inspect {max_files_without_signal} files without credible crypto misuse, stop and return empty findings.\n"
        + "- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916, CWE-259, CWE-321, CWE-798\n"
        + "- Prioritize weak crypto findings only when used in security-sensitive contexts; avoid checksum/cache-only noise.\n"
        + "- Take multiple turns to explore relevant files before finalizing findings.\n"
        + "- Write final JSON only when analysis is complete."
    )
    agent_name = "hunt-crypto"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        parsed = extract_harness_result(result, HuntResult, "Crypto hunter")

        if not parsed.strategies_run:
            parsed.strategies_run = [HuntStrategy.CRYPTO.value]
        if parsed.total_raw == 0 and parsed.findings:
            parsed.total_raw = len(parsed.findings)
        if parsed.deduplicated_count == 0 and parsed.findings:
            parsed.deduplicated_count = len(parsed.findings)
        if parsed.chain_count == 0 and parsed.chains:
            parsed.chain_count = len(parsed.chains)
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
