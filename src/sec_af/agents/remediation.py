from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import RemediationSuggestion, VerifiedFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "remediation.txt"


def _proof_context(finding: VerifiedFinding) -> str:
    if finding.proof is None:
        return "{}"
    return json.dumps(finding.proof.model_dump(mode="json"), indent=2)


def _reproduction_steps(finding: VerifiedFinding) -> str:
    if not finding.reproduction_steps:
        return "[]"
    rows = [step.model_dump(mode="json") for step in finding.reproduction_steps]
    return json.dumps(rows, indent=2)


def _related_locations(finding: VerifiedFinding) -> str:
    if not finding.related_locations:
        return "[]"
    rows = [location.model_dump(mode="json") for location in finding.related_locations]
    return json.dumps(rows, indent=2)


def _build_prompt(template: str, finding: VerifiedFinding, repo_path: str) -> str:
    location = finding.location
    replacements = {
        "{{REPO_PATH}}": repo_path,
        "{{VERDICT}}": finding.verdict.value,
        "{{FINDING_TYPE}}": finding.finding_type.value,
        "{{CWE_ID}}": finding.cwe_id,
        "{{CWE_NAME}}": finding.cwe_name,
        "{{FILE_PATH}}": location.file_path,
        "{{START_LINE}}": str(location.start_line),
        "{{END_LINE}}": str(location.end_line),
        "{{FUNCTION_NAME}}": location.function_name or "unknown",
        "{{RATIONALE}}": finding.rationale,
        "{{RELATED_LOCATIONS}}": _related_locations(finding),
        "{{REPRODUCTION_STEPS}}": _reproduction_steps(finding),
        "{{PROOF_CONTEXT}}": _proof_context(finding),
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)

    code_snippet = location.code_snippet or ""
    return prompt.replace("{{CODE_SNIPPET}}", code_snippet)


async def generate_remediation(app: HarnessCapable, repo_path: str, finding: VerifiedFinding) -> RemediationSuggestion:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(prompt_template, finding, repo_path)
    agent_name = "prove-remediation"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=RemediationSuggestion, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, RemediationSuggestion, "RemediationAgent")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
