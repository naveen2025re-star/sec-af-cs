# SEC-AF — AI-Native Security Analysis Platform on AgentField

> **Status**: Design Proposal  
> **Author**: Architecture brainstorm  
> **Scope**: Standalone product built on AgentField harness  
> **Date**: 2026-03-04

---

## 1. Overview

SEC-AF is an open-source, AI-native security analysis and red-teaming platform built on AgentField's harness infrastructure. It performs deep security audits of codebases through a three-phase **Signal Cascade** pipeline: reconnaissance, vulnerability hunting, and adversarial exploit verification.

**What SEC-AF is**: An AI-powered security analysis tool that produces verified findings with evidence — acting like a team of parallel security researchers analyzing your codebase simultaneously.

**What SEC-AF is not**: An auto-fix tool. SEC-AF identifies, verifies, and reports security issues. It does not generate patches or open fix PRs. The output is a set of verified findings with severity, evidence, reproduction steps, and compliance mapping — similar to a professional penetration test report.

**Key principle**: Every finding carries a **verdict** (confirmed / likely / inconclusive / not exploitable) with transparent evidence. Theoretical vulnerabilities are explicitly distinguished from verified exploitable ones.

---

## 2. Product Positioning

### 2.1 Competitive Landscape

The AI security tooling market (2026) breaks into three tiers:

| Tier | Players | Approach | Limitation |
|------|---------|----------|------------|
| **Traditional SAST/DAST** | Snyk, Semgrep, CodeQL | Pattern matching + dataflow rules | 68-95% false positive rates |
| **AI-Enhanced** | Endor Labs, Aikido, CodeAnt | AI triage on top of static analysis | No exploit verification — still theoretical |
| **Agentic Security** | Nullify ($6K/mo), Konvu | Multi-agent exploit hypothesis + verification | Proprietary, sequential, token-gated |

### 2.2 SEC-AF Differentiation

SEC-AF is the first tool to combine **all three** of these capabilities in a single open-source product:

| Capability | Industry Status | SEC-AF |
|---|---|---|
| **Exploit-verified SARIF** | Nobody combines both | ✅ First tool with verified findings in SARIF 2.1.0 |
| **Attack chains** | All tools output isolated findings | ✅ Multi-step exploit chains as linked findings |
| **Parallel verification** | Nullify: sequential, token-gated | ✅ N parallel provers via AgentField harness |
| **4-level verdicts** | Binary (finding / no-finding) | ✅ CONFIRMED / LIKELY / INCONCLUSIVE / NOT_EXPLOITABLE |
| **6-level evidence** | Most stop at code location | ✅ Static match → full exploit chain |
| **Transparent scoring** | Opaque proprietary formulas | ✅ Published composite formula |
| **Open source** | All agentic tools are proprietary | ✅ Open source, provider-agnostic |

### 2.3 Why AgentField Harness

AgentField's harness infrastructure provides the foundation that makes SEC-AF possible:

- **Provider-agnostic**: Run security agents on Claude Code, Codex, Gemini CLI, or OpenCode — swap providers without code changes
- **Parallel execution**: Harness natively supports concurrent agent invocations — essential for running 20+ hunt agents and N provers simultaneously
- **Schema-constrained output**: Harness enforces structured output via Pydantic/Zod schemas — every agent returns typed, validated data
- **Retry and recovery**: Built-in retry logic with backoff handles transient failures in long-running security scans
- **Cost tracking**: Per-invocation metrics enable cost attribution and budget enforcement across phases
- **Cryptographic audit trail**: AgentField's VC chain provides tamper-proof evidence of what each agent did — critical for compliance reporting

---

## 3. Architecture: Signal Cascade Pipeline

SEC-AF uses a three-phase **Signal Cascade** architecture. Each phase narrows the signal: RECON builds context, HUNT discovers potential vulnerabilities, PROVE verifies exploitability. Only verified findings reach the output.

```
Input: Repository path + configuration
  │
  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 1: RECON                                                       │
│ 5 parallel agents — build security-relevant understanding            │
│                                                                      │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐      │
│ │ Arch    │ │ Data    │ │ Dep     │ │ Config  │ │ Security │      │
│ │ Mapper  │ │ Flow    │ │ Auditor │ │ Scanner │ │ Context  │      │
│ │         │ │ Mapper  │ │         │ │         │ │ Profiler │      │
│ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └─────┬────┘      │
│      └──────────┬┴──────────┬┴──────────┬┴────────────┘            │
│                 ▼                                                     │
│           ReconResult (shared context for all subsequent agents)      │
└──────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 2: HUNT                                                        │
│ 8-20+ parallel agents — multi-strategy vulnerability discovery       │
│                                                                      │
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │
│ │Inject│ │Auth/ │ │Crypto│ │Logic │ │Data  │ │Supply│ │Config│   │
│ │Hunter│ │AuthZ │ │Hunter│ │Bug   │ │Expose│ │Chain │ │/Sec  │   │
│ │      │ │Hunter│ │      │ │Hunter│ │Hunter│ │Hunter│ │Hunter│   │
│ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘   │
│    └────────┴────────┴────────┴────────┴────────┴────────┘         │
│                              ▼                                       │
│                    ┌──────────────────┐                               │
│                    │   Deduplicator   │                               │
│                    │   + Correlator   │                               │
│                    └────────┬─────────┘                               │
│                             ▼                                        │
│                    RawFinding[] (deduplicated, correlated)            │
└──────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ PHASE 3: PROVE                                                       │
│ N parallel agents — one per finding, adversarial verification        │
│                                                                      │
│ ┌────────┐ ┌────────┐ ┌────────┐         ┌────────┐                │
│ │Prover  │ │Prover  │ │Prover  │   ...   │Prover  │                │
│ │Finding1│ │Finding2│ │Finding3│         │FindingN│                │
│ └───┬────┘ └───┬────┘ └───┬────┘         └───┬────┘                │
│     └──────────┴──────────┴──────────────────┘                      │
│                         ▼                                            │
│              VerifiedFinding[] with Verdicts + Proof                  │
└──────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────────────────────────────┐
│ OUTPUT GENERATION                                                    │
│                                                                      │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────────┐   │
│ │ SARIF 2.1.0 │ │ Rich JSON   │ │ GitHub      │ │ Summary      │   │
│ │ (GitHub     │ │ (full       │ │ Issues      │ │ Report       │   │
│ │  Security)  │ │  evidence)  │ │ (severity   │ │ (executive + │   │
│ │             │ │             │ │  labels)    │ │  compliance) │   │
│ └─────────────┘ └─────────────┘ └─────────────┘ └──────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.1 Why Not SWE-AF's Architecture?

SWE-AF uses a 3-loop control system (Strategic → Tactical → Execution) with an Issue DAG and 22 specialized agent roles. We deliberately chose a simpler architecture because:

1. **Security analysis is embarrassingly parallel.** Unlike SWE (where issues have dependency graphs and must be resolved in order), most security findings are independent. 10 hunters can scan for 10 vulnerability classes simultaneously without coordination.

2. **No state mutation.** SWE-AF agents edit code, run tests, and iterate. SEC-AF agents are read-only analysts — they examine code and produce reports. No merge conflicts, no test flakes.

3. **Linear pipeline, not a DAG.** RECON → HUNT → PROVE is a strict stage-gate. Each phase's output is the next phase's input. No cycles, no backtracking (though PROVE may spawn additional HUNT agents for depth-first investigation — see §6.3).

4. **Scale axis is different.** SWE-AF scales by issue count (resolve N issues in parallel). SEC-AF scales by strategy count (run N hunt strategies in parallel) and finding count (verify N findings in parallel).

---

## 4. Phase 1: RECON — Codebase Understanding

### 4.1 Purpose

Build a comprehensive security-relevant understanding of the codebase before any vulnerability hunting begins. This context is shared with all HUNT and PROVE agents, dramatically improving finding quality and reducing false positives.

### 4.2 Agents

| Agent | Input | Output | What It Does |
|---|---|---|---|
| **Architecture Mapper** | Repo path | `ArchitectureMap` | Identifies modules, services, entry points, trust boundaries, inter-service communication patterns, API surfaces |
| **Data Flow Mapper** | Repo path + ArchitectureMap | `DataFlowMap` | Traces user input paths from entry points through processing to storage/output. Identifies sanitization points, validation layers, serialization boundaries |
| **Dependency Auditor** | Repo path | `DependencyReport` | Produces SBOM, identifies direct vs. transitive dependencies, flags known CVEs (via NVD/OSV), identifies outdated packages, checks license risks |
| **Config Scanner** | Repo path | `ConfigReport` | Finds hardcoded secrets, weak crypto configs, debug flags, permissive CORS, insecure defaults, missing security headers, exposed admin endpoints |
| **Security Context Profiler** | Repo path + ArchitectureMap | `SecurityContext` | Identifies auth model (JWT, session, OAuth), crypto usage patterns, framework-specific security features (CSRF tokens, parameterized queries), deployment environment signals |

### 4.3 Output Schema

```python
class ReconResult(BaseModel):
    """Comprehensive security context for the target codebase."""
    architecture: ArchitectureMap
    data_flows: DataFlowMap
    dependencies: DependencyReport
    config: ConfigReport
    security_context: SecurityContext
    
    # Metadata
    languages: list[str]            # Detected languages
    frameworks: list[str]           # Detected frameworks (Django, Express, Spring, etc.)
    lines_of_code: int
    file_count: int
    recon_duration_seconds: float

class ArchitectureMap(BaseModel):
    modules: list[Module]           # Top-level modules/packages
    entry_points: list[EntryPoint]  # HTTP routes, CLI commands, event handlers
    trust_boundaries: list[TrustBoundary]  # Where trust levels change
    services: list[Service]         # Microservices / external service calls
    api_surface: list[APIEndpoint]  # All exposed API endpoints

class DataFlowMap(BaseModel):
    flows: list[DataFlow]           # Input → processing → output paths
    sanitization_points: list[SanitizationPoint]  # Where input is sanitized
    sinks: list[Sink]               # Where data reaches security-critical operations
    
class DataFlow(BaseModel):
    source: str                     # Where user input enters (e.g., "req.body.username")
    path: list[str]                 # Intermediate processing steps
    sink: str                       # Where it's used (e.g., "db.query()")
    sanitized: bool                 # Whether sanitization was detected on this path
    files: list[str]                # Files involved

class DependencyReport(BaseModel):
    sbom: list[Dependency]          # Full dependency tree
    known_cves: list[KnownCVE]     # CVEs in dependencies
    outdated: list[OutdatedDep]    # Packages behind latest version
    direct_count: int
    transitive_count: int

class KnownCVE(BaseModel):
    cve_id: str
    package: str
    installed_version: str
    fixed_version: str | None
    cvss_v4_score: float | None
    epss_score: float | None
    direct: bool                   # Direct or transitive dependency
    reachable: bool | None         # Whether the vulnerable function is called

class ConfigReport(BaseModel):
    secrets: list[SecretFinding]    # Hardcoded credentials, API keys
    misconfigs: list[MisconfigFinding]  # Insecure configurations
    
class SecurityContext(BaseModel):
    auth_model: str                 # "jwt", "session", "oauth2", "api_key", "none"
    auth_details: str               # Human-readable description
    crypto_usage: list[CryptoUsage]  # Algorithms, key sizes, modes
    framework_security: list[str]   # Framework-specific security features in use
    security_headers: list[str]     # Detected security headers
    deployment_signals: list[str]   # Docker, K8s, serverless, etc.
```

### 4.4 Execution

All 5 RECON agents run in parallel via harness. The Architecture Mapper runs first (others can start concurrently but benefit from its output). Total RECON phase should complete in 30-90 seconds depending on codebase size.

```python
# Pseudocode — actual implementation uses harness
async def recon(repo_path: str, config: SecAFConfig) -> ReconResult:
    # Architecture Mapper runs first (or concurrently — agents handle partial context)
    arch, deps, config_report = await asyncio.gather(
        harness("Map the architecture...", schema=ArchitectureMap, cwd=repo_path),
        harness("Audit all dependencies...", schema=DependencyReport, cwd=repo_path),
        harness("Scan all configuration...", schema=ConfigReport, cwd=repo_path),
    )
    
    # Data Flow and Security Context benefit from Architecture Map
    data_flows, sec_ctx = await asyncio.gather(
        harness(f"Given this architecture: {arch}\nTrace all data flows...", 
                schema=DataFlowMap, cwd=repo_path),
        harness(f"Given this architecture: {arch}\nProfile security context...", 
                schema=SecurityContext, cwd=repo_path),
    )
    
    return ReconResult(
        architecture=arch,
        data_flows=data_flows,
        dependencies=deps,
        config=config_report,
        security_context=sec_ctx,
    )
```

---

## 5. Phase 2: HUNT — Vulnerability Discovery

### 5.1 Purpose

Systematically discover potential vulnerabilities across multiple attack vectors simultaneously. Each hunter is a specialized agent with deep expertise in one vulnerability class.

### 5.2 Hunt Strategies

| Strategy | Agent Name | CWE Coverage | What It Hunts |
|---|---|---|---|
| **Injection** | Injection Hunter | CWE-78, 79, 89, 90, 91, 94, 917 | SQL injection, XSS, command injection, LDAP injection, XPath injection, code injection, expression language injection |
| **Auth/AuthZ** | Auth Hunter | CWE-287, 306, 862, 863, 352 | Broken authentication, missing auth checks, IDOR, privilege escalation, CSRF, JWT misuse |
| **Cryptography** | Crypto Hunter | CWE-326, 327, 328, 330, 916 | Weak algorithms, insufficient key length, broken hashing, predictable random, weak password storage |
| **Business Logic** | Logic Bug Hunter | CWE-840, 841 | Race conditions, TOCTOU, state machine flaws, business rule bypass, order-of-operations errors |
| **Data Exposure** | Data Exposure Hunter | CWE-200, 209, 532, 312, 319 | Information disclosure, error message leakage, sensitive data in logs, cleartext storage, cleartext transmission |
| **Supply Chain** | Supply Chain Hunter | CWE-1104, 829 | Dependency confusion, typosquatting, compromised packages, pinning issues, lock file integrity |
| **Configuration** | Config/Secrets Hunter | CWE-798, 259, 321, 16 | Hardcoded credentials, default passwords, embedded keys, permissive configs, debug modes in production |
| **API Security** | API Hunter | CWE-285, 346, 918, 601 | Broken object-level auth, SSRF, open redirects, mass assignment, rate limiting gaps, missing input validation |

### 5.3 Adaptive Strategy Selection

Not all strategies apply to every codebase. The RECON results determine which hunters to activate:

```python
def select_strategies(recon: ReconResult, depth: DepthProfile) -> list[HuntStrategy]:
    strategies = []
    
    # Always run these
    strategies.extend([
        HuntStrategy.INJECTION,
        HuntStrategy.AUTH,
        HuntStrategy.DATA_EXPOSURE,
        HuntStrategy.CONFIG_SECRETS,
    ])
    
    # Conditional strategies based on RECON signals
    if recon.security_context.crypto_usage:
        strategies.append(HuntStrategy.CRYPTO)
    
    if recon.dependencies.direct_count > 0:
        strategies.append(HuntStrategy.SUPPLY_CHAIN)
    
    if recon.architecture.api_surface:
        strategies.append(HuntStrategy.API_SECURITY)
    
    if depth >= DepthProfile.STANDARD:
        strategies.append(HuntStrategy.LOGIC_BUGS)
    
    # Depth-based expansion: THOROUGH adds sub-strategies
    if depth == DepthProfile.THOROUGH:
        # Add language-specific hunters
        if "python" in recon.languages:
            strategies.append(HuntStrategy.PYTHON_SPECIFIC)  # pickle, eval, __import__
        if "javascript" in recon.languages:
            strategies.append(HuntStrategy.JS_SPECIFIC)  # prototype pollution, ReDoS
        if "go" in recon.languages:
            strategies.append(HuntStrategy.GO_SPECIFIC)  # goroutine leaks, unsafe pointer
    
    return strategies
```

### 5.4 Hunter Output Schema

```python
class RawFinding(BaseModel):
    """A potential vulnerability discovered by a hunter agent."""
    # Identity
    id: str = Field(default_factory=lambda: str(uuid4()))
    hunter_strategy: str            # Which hunter found this
    
    # Classification
    title: str                      # Short, descriptive title
    description: str                # What was found and why it's a potential vulnerability
    finding_type: FindingType       # sast, sca, secrets, config, logic, api
    cwe_id: str                     # Most specific applicable CWE
    cwe_name: str
    owasp_category: str | None      # OWASP Top 10 category
    
    # Location
    file_path: str
    start_line: int
    end_line: int
    function_name: str | None
    code_snippet: str               # Relevant code excerpt
    
    # Initial severity estimate (refined by PROVE phase)
    estimated_severity: Severity    # critical, high, medium, low, info
    confidence: Confidence          # high, medium, low
    
    # Context
    data_flow: list[DataFlowStep] | None  # Source-to-sink path if applicable
    related_files: list[str]        # Other files involved
    
    # Deduplication
    fingerprint: str                # Stable hash for dedup across scans

class FindingType(str, Enum):
    SAST = "sast"
    SCA = "sca"  
    SECRETS = "secrets"
    CONFIG = "config"
    LOGIC = "logic"
    API = "api"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
```

### 5.5 Deduplication and Correlation

After all hunters complete, a **Deduplicator/Correlator** agent processes the raw findings:

1. **Deduplication**: Multiple hunters may find the same vulnerability from different angles. The deduplicator merges findings with the same `file_path + start_line + cwe_id` fingerprint, preserving the most detailed description.

2. **Correlation**: Identifies findings that form multi-step attack chains. Example: an SSRF (API Hunter) + cloud metadata endpoint exposure (Config Hunter) + hardcoded cloud credentials (Secrets Hunter) may form a single attack chain.

3. **Priority sorting**: Ranks findings by `estimated_severity × confidence` for efficient PROVE phase ordering — verify the most severe/confident findings first.

```python
class HuntResult(BaseModel):
    """Deduplicated, correlated findings from all hunters."""
    findings: list[RawFinding]      # Deduplicated findings
    chains: list[PotentialChain]    # Correlated multi-step attack possibilities
    
    # Statistics
    total_raw: int                  # Before dedup
    deduplicated_count: int         # After dedup
    chain_count: int                # Potential attack chains identified
    strategies_run: list[str]       # Which hunters were activated
    hunt_duration_seconds: float

class PotentialChain(BaseModel):
    """A potential multi-step attack linking multiple findings."""
    chain_id: str
    title: str                      # e.g., "SSRF → Cloud Metadata → Credential Theft"
    finding_ids: list[str]          # Ordered list of finding IDs in the chain
    combined_impact: str            # Impact if the full chain is exploitable
    estimated_severity: Severity
```

### 5.6 Execution

All selected hunters run in parallel via harness. Each hunter receives the full `ReconResult` as context.

```python
async def hunt(recon: ReconResult, config: SecAFConfig) -> HuntResult:
    strategies = select_strategies(recon, config.depth)
    
    # Run all hunters in parallel
    hunter_results = await asyncio.gather(*[
        harness(
            build_hunter_prompt(strategy, recon),
            schema=list[RawFinding],
            cwd=config.repo_path,
        )
        for strategy in strategies
    ])
    
    # Flatten all findings
    all_findings = [f for result in hunter_results for f in result]
    
    # Deduplicate and correlate
    deduped = await harness(
        f"Deduplicate and correlate these {len(all_findings)} findings...",
        schema=HuntResult,
        cwd=config.repo_path,
    )
    
    return deduped
```

---

## 6. Phase 3: PROVE — Adversarial Verification

### 6.1 Purpose

The **key differentiator**. For each raw finding, a Prover agent attempts to verify whether the vulnerability is actually exploitable. This transforms theoretical findings into evidence-backed verdicts.

### 6.2 Verification Methods

Provers use different verification methods depending on the finding type:

| Finding Type | Verification Method | Evidence Produced |
|---|---|---|
| **Injection (SQLi, XSS, Cmd)** | Trace data flow from source to sink. Check for sanitization/parameterization. Construct exploit payload mentally or in test code | Data flow trace, payload analysis, sanitization check result |
| **Auth/AuthZ** | Analyze auth middleware chain. Check for missing guards. Trace request lifecycle through auth layers | Auth chain analysis, missing check identification, bypass scenario |
| **Crypto** | Verify algorithm, key size, mode against current standards. Check for known weaknesses | Algorithm assessment, standards comparison, weakness documentation |
| **Logic Bugs** | Reason through state machine, identify race conditions, trace business rule enforcement | State machine analysis, race condition scenario, business rule bypass steps |
| **SCA (CVE)** | Check if vulnerable function is reachable via call graph. Verify version match. Check EPSS score | Reachability analysis, version confirmation, EPSS/CVSS data |
| **Secrets** | Verify credential format. Check if it appears to be a real credential vs. example/test | Format validation, context analysis (test file? .env.example?) |
| **Config** | Verify the configuration is active (not overridden). Check deployment context | Config inheritance analysis, environment check |

### 6.3 Verdict Model

```python
class Verdict(str, Enum):
    """4-level verdict with transparent semantics."""
    CONFIRMED = "confirmed"
    # The finding has been verified with concrete evidence.
    # At minimum: data flow traced source-to-sink with no sanitization found,
    # OR vulnerable version confirmed reachable,
    # OR exploit payload constructed that would succeed.
    
    LIKELY = "likely"
    # Strong signals suggest exploitability but full verification was not possible.
    # Example: data flow reaches sink but sanitization analysis was inconclusive,
    # OR vulnerable pattern detected but runtime behavior is uncertain.
    
    INCONCLUSIVE = "inconclusive"
    # Insufficient evidence to determine exploitability.
    # The finding is plausible but the prover could not confirm or deny.
    # Requires human review.
    
    NOT_EXPLOITABLE = "not_exploitable"
    # Evidence shows the finding is NOT exploitable in this context.
    # Example: vulnerable function is unreachable, input is sanitized before sink,
    # OR configuration is overridden by a more secure setting.
    # Every NOT_EXPLOITABLE verdict MUST include a rationale explaining why.

class EvidenceLevel(int, Enum):
    """6-level evidence hierarchy — weakest to strongest."""
    STATIC_MATCH = 1
    # Pattern match only. The code matches a known vulnerable pattern.
    
    VERSION_CONFIRMED = 2
    # A vulnerable version of a dependency was confirmed present.
    
    REACHABILITY_CONFIRMED = 3
    # The vulnerable code path is reachable from an entry point.
    # Data flow traced from user input to the vulnerable sink.
    
    BEHAVIOR_CONFIRMED = 4
    # A behavioral signal confirms the vulnerability.
    # Example: timing differences, error messages, or observable side effects
    # that indicate the vulnerable code path executes.
    
    DATA_CONFIRMED = 5
    # Concrete data demonstrates exploitation.
    # Example: attacker-controlled output returned, unauthorized data accessed,
    # or security boundary crossed.
    
    FULL_EXPLOIT = 6
    # Complete exploit chain executed with proof.
    # Example: PoC code written and run, full request/response captured,
    # attacker-controlled action performed.
```

### 6.4 Proof Schema

```python
class Proof(BaseModel):
    """Evidence supporting a verdict. The core output artifact."""
    
    # What was hypothesized and how it was tested
    exploit_hypothesis: str          # What we theorized could be exploited
    verification_method: str         # How we attempted to verify it
    evidence_level: EvidenceLevel    # Strength of evidence obtained
    
    # Data flow evidence (for SAST findings)
    data_flow_trace: list[DataFlowStep] | None
    # Each step: file, line, description of what happens to the data
    
    sanitization_analysis: SanitizationAnalysis | None
    # Whether sanitization was found, what kind, and whether it's sufficient
    
    # Code evidence
    vulnerable_code: str | None      # The specific vulnerable code snippet
    exploit_payload: str | None      # The input that would trigger the vulnerability
    expected_outcome: str | None     # What would happen if the payload were delivered
    
    # PoC evidence (for FULL_EXPLOIT level)
    poc_code: str | None             # The PoC code that was written
    poc_execution_output: str | None # stdout/stderr from PoC execution
    
    # HTTP evidence (for web/API vulnerabilities)
    http_request: HttpEvidence | None
    http_response: HttpEvidence | None
    
    # Reachability evidence (for SCA findings)
    reachability: ReachabilityEvidence | None
    
    # Chain evidence (for multi-step exploits)
    chain_steps: list[ChainStep] | None

class DataFlowStep(BaseModel):
    file: str
    line: int
    description: str                 # What happens to the data at this step
    tainted: bool                    # Is the data still attacker-controlled?

class SanitizationAnalysis(BaseModel):
    sanitization_found: bool
    sanitization_type: str | None    # e.g., "parameterized query", "HTML encoding", "regex filter"
    sanitization_sufficient: bool | None  # Is it effective against the attack vector?
    bypass_possible: bool | None     # Can the sanitization be bypassed?
    bypass_method: str | None        # How it could be bypassed

class HttpEvidence(BaseModel):
    method: str | None
    url: str | None
    headers: dict[str, str] | None
    body: str | None
    highlighted_segment: str | None  # The specific part that demonstrates the vulnerability

class ReachabilityEvidence(BaseModel):
    vulnerable_function: str         # The function in the dependency that has the CVE
    call_chain: list[str]            # Call chain from entry point to vulnerable function
    reachable: bool
    direct_dependency: bool

class ChainStep(BaseModel):
    step_number: int
    finding_id: str                  # Links to another finding
    description: str                 # What this step achieves
    enables: str                     # What this step unlocks for the next step
```

### 6.5 Prover Execution

Each prover runs independently and in parallel. High-severity findings are verified first.

```python
async def prove(
    hunt_result: HuntResult, 
    recon: ReconResult, 
    config: SecAFConfig,
) -> list[VerifiedFinding]:
    # Sort by severity × confidence (verify most important first)
    sorted_findings = sort_by_priority(hunt_result.findings)
    
    # Apply budget cap if configured
    if config.max_provers:
        sorted_findings = sorted_findings[:config.max_provers]
    
    # Run all provers in parallel
    verified = await asyncio.gather(*[
        harness(
            build_prover_prompt(finding, recon),
            schema=VerifiedFinding,
            cwd=config.repo_path,
        )
        for finding in sorted_findings
    ])
    
    # Also verify potential chains
    if hunt_result.chains:
        chain_results = await asyncio.gather(*[
            harness(
                build_chain_prover_prompt(chain, hunt_result.findings, recon),
                schema=VerifiedChain,
                cwd=config.repo_path,
            )
            for chain in hunt_result.chains
        ])
        # Merge chain results into verified findings
    
    return verified
```

### 6.6 Depth-First Expansion

When a prover discovers that a finding enables further exploitation (e.g., SSRF that can reach internal services), it can signal the orchestrator to spawn additional targeted hunters:

```python
class ProverSignal(BaseModel):
    """Signal from a prover requesting deeper investigation."""
    expand: bool = False
    expansion_reason: str | None = None
    expansion_strategy: str | None = None  # e.g., "internal_service_scan"
    expansion_target: str | None = None    # e.g., specific file or endpoint
```

This enables depth-first investigation where warranted, without pre-committing to exhaustive scanning of the entire codebase.

---

## 7. Output Formats

### 7.1 The Verified Finding (Core Output Object)

```python
class VerifiedFinding(BaseModel):
    """A finding that has been through the PROVE phase. The core output unit."""
    
    # ── Identity ──
    id: str                         # Stable UUID for deduplication
    fingerprint: str                # Stable across refactors (location-independent)
    title: str
    description: str
    
    # ── Classification ──
    finding_type: FindingType       # sast, sca, secrets, config, logic, api
    cwe_id: str                     # Most specific applicable CWE (e.g., "CWE-89")
    cwe_name: str                   # Human-readable (e.g., "SQL Injection")
    owasp_category: str | None      # e.g., "A03:2021 Injection"
    tags: set[str]                  # Extensible tags: {"REACHABLE", "DIRECT_DEP", "INTERNET_FACING"}
    
    # ── Verdict (THE differentiator) ──
    verdict: Verdict                # confirmed, likely, inconclusive, not_exploitable
    evidence_level: EvidenceLevel   # 1-6 evidence hierarchy
    rationale: str                  # Human-readable reasoning for the verdict
    
    # ── Scoring (transparent, multi-signal) ──
    severity: Severity              # critical, high, medium, low, info
    cvss_v4: CvssV4Score | None     # Full CVSS v4.0 vector + score
    epss: EpssScore | None          # Probability + percentile (for CVE-based findings)
    exploitability_score: float     # 0.0-10.0 composite score (see §7.4)
    
    # ── Evidence ──
    proof: Proof | None             # Full evidence (only for verdict != not_exploitable)
    
    # ── Location ──
    location: Location              # Primary location (file, line, column, function)
    related_locations: list[Location]  # Secondary locations (taint source, config file)
    
    # ── Attack Chain ──
    chain_id: str | None            # Groups linked findings into an attack chain
    chain_step: int | None          # Position in the chain
    enables: list[str] | None       # Finding IDs this enables
    
    # ── Compliance ──
    compliance: list[ComplianceMapping]  # Auto-mapped from CWE
    
    # ── Reproduction ──
    reproduction_steps: list[ReproductionStep]
    
    # ── SARIF Metadata ──
    sarif_rule_id: str              # Stable rule ID for SARIF dedup
    sarif_security_severity: float  # 0.0-10.0 for GitHub severity badge

class Location(BaseModel):
    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    function_name: str | None = None
    code_snippet: str | None = None

class CvssV4Score(BaseModel):
    vector: str                     # Full CVSS v4.0 vector string
    base_score: float               # 0.0-10.0
    severity: str                   # Critical/High/Medium/Low/None
    automatable: bool               # Can this be scripted at scale?
    subsequent_impact: bool         # Enables lateral movement?

class EpssScore(BaseModel):
    score: float                    # 0.0-1.0 probability of exploitation in 30 days
    percentile: float               # 0.0-1.0 relative to all CVEs
    date: str                       # EPSS scores change daily

class ComplianceMapping(BaseModel):
    framework: str                  # PCI-DSS, SOC2, HIPAA, ISO27001, OWASP
    control_id: str                 # e.g., "Req 6.2.4"
    control_name: str               # e.g., "Prevent injection attacks"

class ReproductionStep(BaseModel):
    step: int
    description: str
    command: str | None = None      # Exact command/payload if applicable
    expected_output: str | None = None
```

### 7.2 Attack Chain

```python
class AttackChain(BaseModel):
    """A verified multi-step exploit chain linking multiple findings."""
    chain_id: str
    title: str                      # e.g., "SSRF → Cloud Metadata → Admin Access"
    description: str                # Full chain narrative
    findings: list[str]             # Ordered finding IDs
    combined_severity: Severity     # Severity of the FULL chain (often higher than individual findings)
    combined_impact: str            # What an attacker achieves with the full chain
    mitre_attack_mapping: list[MitreMapping] | None
    
class MitreMapping(BaseModel):
    tactic: str                     # e.g., "Initial Access"
    technique_id: str               # e.g., "T1190"
    technique_name: str             # e.g., "Exploit Public-Facing Application"
```

### 7.3 Top-Level Audit Result

```python
class SecurityAuditResult(BaseModel):
    """Top-level output of a SEC-AF audit."""
    
    # ── Target ──
    repository: str
    commit_sha: str
    branch: str | None
    timestamp: datetime
    
    # ── Configuration ──
    depth_profile: str              # quick, standard, thorough
    strategies_used: list[str]      # Which hunt strategies were activated
    provider: str                   # Harness provider used (claude-code, codex, etc.)
    
    # ── Findings ──
    findings: list[VerifiedFinding]
    attack_chains: list[AttackChain]
    
    # ── Summary Statistics ──
    total_raw_findings: int         # Before dedup + verification
    confirmed: int                  # Verdict = CONFIRMED
    likely: int                     # Verdict = LIKELY
    inconclusive: int               # Verdict = INCONCLUSIVE
    not_exploitable: int            # Verdict = NOT_EXPLOITABLE (noise removed)
    noise_reduction_pct: float      # % of raw findings eliminated
    
    # ── Severity Breakdown ──
    by_severity: dict[str, int]     # {"critical": 2, "high": 5, ...}
    
    # ── Compliance Gaps ──
    compliance_gaps: list[ComplianceGap]
    
    # ── Performance ──
    duration_seconds: float
    agent_invocations: int
    cost_usd: float
    cost_breakdown: dict[str, float]  # Per-phase cost
    
    # ── Exports ──
    sarif: str                      # SARIF 2.1.0 JSON string (for GitHub Security tab)

class ComplianceGap(BaseModel):
    framework: str                  # e.g., "PCI-DSS"
    control_id: str                 # e.g., "Req 6.2.4"
    control_name: str
    finding_count: int              # How many confirmed findings map to this control
    severity: Severity              # Highest severity finding in this gap
```

### 7.4 Exploitability Score Formula (Transparent)

Unlike Nullify's opaque 0-100 or Snyk's opaque Priority Score, SEC-AF's exploitability score is a published, reproducible formula:

```python
def compute_exploitability_score(finding: VerifiedFinding) -> float:
    """
    Composite score 0.0-10.0.
    
    Formula:
      score = (severity_weight * 0.3) + (evidence_weight * 0.3) + 
              (reachability_weight * 0.2) + (epss_weight * 0.1) + 
              (chain_weight * 0.1)
    
    All weights are 0.0-10.0, final score is 0.0-10.0.
    """
    # Severity: CVSS v4 score or estimated severity
    severity_weight = finding.cvss_v4.base_score if finding.cvss_v4 else SEVERITY_MAP[finding.severity]
    
    # Evidence: Higher evidence level = higher confidence in exploitability
    evidence_weight = finding.evidence_level.value * (10.0 / 6.0)
    
    # Reachability: Is the vulnerable code reachable from user input?
    reachability_weight = 10.0 if "REACHABLE" in finding.tags else 5.0 if "POTENTIALLY_REACHABLE" in finding.tags else 2.0
    
    # EPSS: Probability of exploitation in the wild (for CVE-based findings)
    epss_weight = (finding.epss.score * 10.0) if finding.epss else 5.0  # Neutral if no EPSS
    
    # Chain bonus: Findings that enable multi-step attacks are more severe
    chain_weight = 10.0 if finding.chain_id else 0.0
    
    return (
        severity_weight * 0.3 +
        evidence_weight * 0.3 +
        reachability_weight * 0.2 +
        epss_weight * 0.1 +
        chain_weight * 0.1
    )
```

### 7.5 SARIF 2.1.0 Output

SEC-AF produces SARIF 2.1.0 compatible with GitHub Code Scanning. Key fields:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "SEC-AF",
        "semanticVersion": "0.1.0",
        "informationUri": "https://github.com/Agent-Field/sec-af",
        "rules": [{
          "id": "sec-af/sast/sql-injection",
          "name": "SQLInjection",
          "shortDescription": { "text": "SQL Injection vulnerability" },
          "fullDescription": { "text": "Unsanitized user input flows into SQL query..." },
          "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
          "defaultConfiguration": { "level": "error" },
          "properties": {
            "precision": "high",
            "security-severity": "9.0",
            "tags": ["security", "CWE-89", "OWASP-A03:2021", "sql-injection"]
          }
        }]
      }
    },
    "results": [{
      "ruleId": "sec-af/sast/sql-injection",
      "level": "error",
      "message": { 
        "text": "[CONFIRMED] SQL Injection: Unsanitized user input from req.body.id flows into db.query() at src/users.py:42. Evidence level: REACHABILITY_CONFIRMED."
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/users.py", "uriBaseId": "%SRCROOT%" },
          "region": { 
            "startLine": 42, "startColumn": 5,
            "endLine": 42, "endColumn": 65,
            "snippet": { "text": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")" }
          }
        }
      }],
      "partialFingerprints": {
        "primaryLocationLineHash": "abc123def456..."
      },
      "codeFlows": [{
        "threadFlows": [{
          "locations": [
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/routes.py" },
                  "region": { "startLine": 15 }
                },
                "message": { "text": "User input enters via request body" }
              }
            },
            {
              "location": {
                "physicalLocation": {
                  "artifactLocation": { "uri": "src/users.py" },
                  "region": { "startLine": 42 }
                },
                "message": { "text": "Reaches SQL query without sanitization" }
              }
            }
          ]
        }]
      }],
      "relatedLocations": [{
        "id": 1,
        "physicalLocation": {
          "artifactLocation": { "uri": "src/routes.py" },
          "region": { "startLine": 15 }
        },
        "message": { "text": "Taint source: user input" }
      }],
      "properties": {
        "sec-af/verdict": "confirmed",
        "sec-af/evidence_level": 3,
        "sec-af/exploitability_score": 8.7,
        "sec-af/chain_id": null,
        "sec-af/compliance": ["PCI-DSS:Req-6.2.4", "SOC2:CC6.1"]
      }
    }],
    "automationDetails": {
      "id": "sec-af/audit/abc123/2026-03-04T10:30:00Z"
    }
  }]
}
```

**Key SARIF features**:
- `codeFlows` — enables path visualization in GitHub UI (source → sink)
- `partialFingerprints` — stable deduplication across scans
- `properties.security-severity` — numeric severity for GitHub badge
- `properties.sec-af/*` — custom fields for verdict, evidence level, exploitability score
- `automationDetails.id` — prevents duplicate uploads

### 7.6 GitHub Issues Output

For each finding with verdict `CONFIRMED` or `LIKELY` (configurable), SEC-AF can create GitHub Issues:

```markdown
## 🔴 [CONFIRMED] SQL Injection in src/users.py:42

**Severity**: Critical (CVSS 9.0 | Exploitability 8.7/10)
**CWE**: CWE-89 — SQL Injection
**OWASP**: A03:2021 — Injection
**Verdict**: CONFIRMED (Evidence Level: Reachability Confirmed)

### Description
Unsanitized user input from `req.body.id` flows directly into a SQL query 
at `src/users.py:42`. No parameterization or input sanitization was found 
on this data flow path.

### Data Flow
1. **Source**: `src/routes.py:15` — User input enters via request body (`req.body.id`)
2. **Sink**: `src/users.py:42` — Used in `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
3. **Sanitization**: None found on this path

### Reproduction Steps
1. Send a POST request to `/api/users/lookup` with body `{"id": "1 OR 1=1"}`
2. Observe that the SQL query executes without parameterization
3. The attacker can extract arbitrary data from the database

### Exploit Hypothesis
An attacker can inject arbitrary SQL via the `id` parameter. The input flows
from `req.body.id` through `get_user()` to `cursor.execute()` with no 
sanitization. A payload of `1; DROP TABLE users--` would execute arbitrary SQL.

### Compliance Impact
- **PCI-DSS**: Req 6.2.4 — Prevent injection attacks
- **SOC2**: CC6.1 — Logical access controls

---
*Found by SEC-AF v0.1.0 | Audit ID: abc123 | 2026-03-04*
```

---

## 8. Developer Experience

### 8.1 CLI

```bash
# Basic audit
sec-af audit /path/to/repo

# With depth profile
sec-af audit /path/to/repo --depth thorough

# Output SARIF only
sec-af audit /path/to/repo --output sarif --output-file results.sarif

# Create GitHub Issues for confirmed findings
sec-af audit /path/to/repo --github-issues --severity-threshold high

# Use specific provider
sec-af audit /path/to/repo --provider claude-code --model opus

# JSON output
sec-af audit /path/to/repo --output json --output-file results.json

# Budget cap (stop after N dollars)
sec-af audit /path/to/repo --max-cost 10.00

# Max provers (limit parallel verification)
sec-af audit /path/to/repo --max-provers 20
```

### 8.2 Python SDK

```python
from sec_af import SecurityAudit, AuditConfig, DepthProfile

# Simple usage
result = await SecurityAudit.run(
    repo_path="/path/to/repo",
    provider="claude-code",
)

# Full configuration
config = AuditConfig(
    repo_path="/path/to/repo",
    depth=DepthProfile.THOROUGH,
    provider="claude-code",
    model="opus",
    max_cost_usd=10.0,
    max_provers=20,
    severity_threshold="medium",
    output_formats=["sarif", "json"],
    github_issues=True,
    github_token="ghp_...",
    compliance_frameworks=["pci-dss", "soc2"],
)

result: SecurityAuditResult = await SecurityAudit.run(config)

# Access findings
for finding in result.findings:
    if finding.verdict == "confirmed":
        print(f"[{finding.severity}] {finding.title}")
        print(f"  Evidence: {finding.proof.exploit_hypothesis}")
        print(f"  Score: {finding.exploitability_score}/10")

# Export SARIF
with open("results.sarif", "w") as f:
    f.write(result.sarif)

# Summary
print(f"Scanned in {result.duration_seconds:.1f}s")
print(f"Found {result.confirmed} confirmed, {result.likely} likely issues")
print(f"Noise reduction: {result.noise_reduction_pct:.0f}%")
print(f"Cost: ${result.cost_usd:.2f}")
```

### 8.3 GitHub Actions Integration

```yaml
name: Security Audit
on: [pull_request]

jobs:
  sec-af:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      - name: Run SEC-AF Audit
        uses: agentfield/sec-af-action@v1
        with:
          depth: standard
          provider: claude-code
          severity-threshold: medium
          max-cost: 5.00
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sec-af-results.sarif
```

---

## 9. Depth Profiles

Three predefined profiles control the trade-off between thoroughness and cost:

| Profile | RECON | HUNT Strategies | PROVE | Estimated Time | Estimated Cost |
|---|---|---|---|---|---|
| **Quick** | 3 agents (Arch, Deps, Config) | 4 core strategies (Injection, Auth, Data Exposure, Config) | Top 10 findings only | 2-5 min | $0.50-2.00 |
| **Standard** | 5 agents (all) | 6-8 strategies (core + Crypto, Supply Chain, API) | Top 30 findings | 5-15 min | $2.00-10.00 |
| **Thorough** | 5 agents + language-specific profilers | All strategies + language-specific hunters | All findings | 15-45 min | $10.00-50.00 |

### 9.1 Budget Enforcement

```python
class BudgetConfig(BaseModel):
    max_cost_usd: float | None = None   # Hard cap
    max_provers: int | None = None      # Limit parallel provers
    max_duration_seconds: int | None = None  # Time cap
    
    # Phase budgets (as percentage of total)
    recon_budget_pct: float = 0.15      # 15% of budget for RECON
    hunt_budget_pct: float = 0.35       # 35% for HUNT
    prove_budget_pct: float = 0.50      # 50% for PROVE (most expensive)
```

The orchestrator tracks cumulative cost across all harness invocations. If the budget is exhausted mid-phase, it completes the current agents but does not spawn new ones. Partial results are still valid — the output includes a `budget_exhausted: bool` flag and `findings_not_verified: int` count.

---

## 10. Compliance Mapping

### 10.1 Automated CWE → Compliance Mapping

SEC-AF maintains a lookup table that automatically maps CWE IDs to compliance framework controls:

```python
COMPLIANCE_MAP: dict[str, list[ComplianceMapping]] = {
    "CWE-89": [  # SQL Injection
        ComplianceMapping(framework="PCI-DSS", control_id="Req 6.2.4", control_name="Prevent injection attacks"),
        ComplianceMapping(framework="SOC2", control_id="CC6.1", control_name="Logical access controls"),
        ComplianceMapping(framework="OWASP", control_id="A03:2021", control_name="Injection"),
        ComplianceMapping(framework="HIPAA", control_id="§164.312(a)(1)", control_name="Access control"),
        ComplianceMapping(framework="ISO27001", control_id="A.14.2.5", control_name="Secure system engineering"),
    ],
    "CWE-287": [  # Broken Authentication
        ComplianceMapping(framework="PCI-DSS", control_id="Req 8.3", control_name="Secure authentication"),
        ComplianceMapping(framework="SOC2", control_id="CC6.1", control_name="Logical access controls"),
        ComplianceMapping(framework="OWASP", control_id="A07:2021", control_name="Identification and Authentication Failures"),
        ComplianceMapping(framework="HIPAA", control_id="§164.312(d)", control_name="Person or entity authentication"),
    ],
    # ... 50+ CWE mappings
}
```

### 10.2 Compliance Gap Report

The output includes a summary of compliance gaps — which framework controls have confirmed findings:

```
PCI-DSS Compliance Gaps:
  ⚠ Req 6.2.4 — Prevent injection attacks: 2 confirmed findings
  ⚠ Req 8.3 — Secure authentication: 1 confirmed finding
  ✓ Req 6.5.3 — Secure cryptographic storage: No findings

SOC2 Compliance Gaps:
  ⚠ CC6.1 — Logical access controls: 3 confirmed findings
  ⚠ CC7.1 — System monitoring: 1 confirmed finding
```

---

## 11. Sandbox Model for PoC Execution

### 11.1 Scope

Provers primarily perform **static reasoning** about exploitability — tracing data flows, analyzing sanitization, and constructing hypothetical exploit payloads. However, for `FULL_EXPLOIT` evidence level, provers may need to execute PoC code.

### 11.2 Execution Environments

| Method | When Used | Isolation | Risk Level |
|---|---|---|---|
| **Static reasoning only** | Default for all findings | None needed | Zero risk |
| **Test file execution** | Writing and running a test that demonstrates the vulnerability | Git worktree clone | Low risk — only touches test files |
| **Docker sandbox** | PoC that requires running the application | Ephemeral container, no network, no host mounts | Medium risk — fully isolated |

### 11.3 Safety Rules

1. **Provers are read-only by default.** They analyze code, they don't modify it.
2. **PoC execution requires explicit opt-in** via `--enable-poc-execution` flag.
3. **PoC code is reviewed by the orchestrator** before execution for dangerous patterns (rm -rf, network access, privilege escalation).
4. **All PoC execution happens in ephemeral environments** — git worktree clones or Docker containers that are destroyed after the scan.
5. **Network access is denied** in sandbox mode. PoCs that require external calls are flagged as `LIKELY` (not `CONFIRMED`) since they can't be fully verified offline.
6. **PoC execution has a timeout** (30 seconds default). Runaway processes are killed.

### 11.4 Evidence Without Execution

The majority of findings can be verified to `REACHABILITY_CONFIRMED` (level 3) or `BEHAVIOR_CONFIRMED` (level 4) through static reasoning alone:

- **Data flow tracing**: Following user input from source to sink through the code
- **Sanitization analysis**: Checking whether effective sanitization exists on the path
- **Configuration analysis**: Verifying whether security settings are active
- **Version matching**: Confirming a vulnerable dependency version is present and reachable

`FULL_EXPLOIT` (level 6) requires PoC execution and is opt-in. Most users will get actionable results without it.

---

## 12. Orchestration Details

### 12.1 Phase Transitions

```python
class AuditOrchestrator:
    async def run(self, config: AuditConfig) -> SecurityAuditResult:
        # Phase 1: RECON
        recon = await self.recon_phase(config)
        self.checkpoint("recon", recon)
        
        # Phase 2: HUNT
        hunt = await self.hunt_phase(recon, config)
        self.checkpoint("hunt", hunt)
        
        # Phase 3: PROVE
        verified = await self.prove_phase(hunt, recon, config)
        self.checkpoint("prove", verified)
        
        # Output generation
        return self.generate_output(verified, recon, hunt, config)
```

### 12.2 Checkpointing

Each phase boundary is a checkpoint. If a scan is interrupted, it can resume from the last completed phase:

```bash
# Resume from checkpoint
sec-af audit /path/to/repo --resume .sec-af/checkpoint-hunt.json
```

Checkpoint files contain the serialized phase output (`ReconResult`, `HuntResult`, etc.).

### 12.3 Progress Reporting

The orchestrator emits structured progress events:

```python
class AuditProgress(BaseModel):
    phase: str                      # "recon", "hunt", "prove"
    phase_progress: float           # 0.0-1.0
    agents_total: int
    agents_completed: int
    agents_running: int
    findings_so_far: int
    elapsed_seconds: float
    estimated_remaining_seconds: float
    cost_so_far_usd: float
```

### 12.4 Cross-Phase Context Propagation

All agents in HUNT and PROVE phases receive the `ReconResult` as context. This is the mechanism that reduces false positives — hunters and provers know:

- What authentication model the app uses (don't flag missing CSRF on an API-only app)
- What frameworks are in use (Django auto-escapes templates — different from raw Jinja)
- What data flows exist (which entry points reach which sinks)
- What dependencies are present (don't flag supply chain issues for pinned, audited deps)

---

## 13. Agent Prompt Engineering

### 13.1 Prompt Structure

Every agent receives a structured prompt with:

```
ROLE: You are a {role} security analyst.
CONTEXT: {ReconResult summary — architecture, frameworks, auth model}
TASK: {Specific task — e.g., "Hunt for injection vulnerabilities"}
SCOPE: {Files/modules to focus on}
OUTPUT: {Schema description — what fields to produce}
CONSTRAINTS: {What NOT to flag — e.g., "Do not flag SQL injection in Django ORM calls with parameterized queries"}
```

### 13.2 Hunter Prompt Example

```
ROLE: You are an expert injection vulnerability analyst specializing in {language}/{framework}.

CONTEXT:
- Application type: {recon.architecture.app_type}
- Auth model: {recon.security_context.auth_model}
- Frameworks: {recon.frameworks}
- Entry points: {recon.architecture.entry_points[:10]}
- Known data flows: {recon.data_flows.flows[:5]}

TASK: Systematically hunt for injection vulnerabilities in this codebase.

COVERAGE:
- SQL Injection (CWE-89): String concatenation in queries, raw SQL, ORM bypasses
- Command Injection (CWE-78): shell=True, subprocess with unsanitized input, os.system()
- XSS (CWE-79): Unescaped output in templates, innerHTML, dangerouslySetInnerHTML
- LDAP Injection (CWE-90): Unsanitized input in LDAP queries
- Expression Language Injection (CWE-917): Template injection, SSTI

FOR EACH FINDING, provide:
- Title, description, CWE ID
- Exact file path, line number, code snippet
- Data flow from user input to vulnerable sink
- Estimated severity (critical/high/medium/low)
- Confidence (high/medium/low) — high only if you traced the full data flow

DO NOT FLAG:
- Parameterized queries (e.g., cursor.execute("SELECT * FROM users WHERE id = %s", [user_id]))
- ORM calls that handle escaping (Django ORM, SQLAlchemy with bound parameters)
- Output in contexts where the framework auto-escapes (Django templates, React JSX)
- Test files unless they contain real credentials
```

### 13.3 Prover Prompt Example

```
ROLE: You are an adversarial security researcher. Your job is to determine 
whether this potential vulnerability is actually exploitable.

FINDING:
{raw_finding.title}
{raw_finding.description}
CWE: {raw_finding.cwe_id} — {raw_finding.cwe_name}
File: {raw_finding.file_path}:{raw_finding.start_line}
Code: {raw_finding.code_snippet}

CODEBASE CONTEXT:
- Auth model: {recon.security_context.auth_model}
- Framework security features: {recon.security_context.framework_security}
- Relevant data flows: {relevant_flows}

YOUR TASK:
1. Read the code at the specified location and surrounding context
2. Trace the data flow from the nearest user input source to this sink
3. Check for sanitization, validation, or other mitigations along the path
4. Determine a VERDICT:
   - CONFIRMED: You found concrete evidence this is exploitable (specify evidence)
   - LIKELY: Strong signals suggest exploitability but you couldn't fully prove it
   - INCONCLUSIVE: Not enough evidence to decide
   - NOT_EXPLOITABLE: You found evidence this is NOT exploitable (specify what protects it)

5. Provide EVIDENCE for your verdict:
   - Data flow trace (each file + line + what happens to the data)
   - Sanitization analysis (was sanitization found? is it sufficient?)
   - An exploit hypothesis (what payload would an attacker use?)
   - Reproduction steps (how would someone verify this?)

BE ADVERSARIAL: Try to find ways to exploit it. Consider edge cases, 
encoding bypasses, framework quirks, and configuration overrides.

BE HONEST: If you can't determine exploitability, say INCONCLUSIVE. 
Don't inflate findings. Don't suppress real vulnerabilities.
```

---

## 14. v1 Scope

### 14.1 In Scope for v1

- [x] 3-phase pipeline: RECON → HUNT → PROVE
- [x] 5 RECON agents
- [x] 8 HUNT strategies (core vulnerability classes)
- [x] Parallel prover execution
- [x] 4-level verdict model
- [x] 6-level evidence hierarchy
- [x] SARIF 2.1.0 output (GitHub Code Scanning compatible)
- [x] Rich JSON output
- [x] CLI interface (`sec-af audit`)
- [x] Python SDK
- [x] Depth profiles (quick, standard, thorough)
- [x] Budget enforcement (cost cap, prover cap)
- [x] Compliance mapping (PCI-DSS, SOC2, OWASP Top 10)
- [x] Transparent exploitability scoring
- [x] Provider-agnostic via harness (Claude Code, Codex, Gemini, OpenCode)
- [x] Languages: Python, JavaScript/TypeScript, Go (most common in target market)

### 14.2 Out of Scope for v1 (Future)

- [ ] GitHub Issues creation (v1.1)
- [ ] GitHub Actions action (v1.1)
- [ ] PoC execution in sandbox (v1.2 — v1 uses static reasoning only)
- [ ] Attack chain detection and verification (v1.2)
- [ ] Additional languages: Java, C/C++, Rust, Ruby, PHP (v1.1+)
- [ ] DAST / runtime testing (v2)
- [ ] Container scanning (v2)
- [ ] Cloud posture scanning (v2)
- [ ] Memory/Vault system (learning from past scans) (v2)
- [ ] MCP server integration (v2)
- [ ] Dashboard / Web UI (v2)
- [ ] CI/CD pipeline integration beyond GitHub Actions (v2)
- [ ] HIPAA, ISO 27001, CMMC compliance mapping (v1.1)
- [ ] Multi-repo / monorepo scanning (v2)
- [ ] Incremental scanning (only scan changed files) (v1.1)
- [ ] Auto-fix / PR generation (explicitly out of scope — may never be added)

### 14.3 Success Criteria for v1

1. **Noise reduction ≥ 70%**: At least 70% of raw findings should be classified as NOT_EXPLOITABLE with documented rationale
2. **Confirmed findings accuracy ≥ 90%**: At least 90% of CONFIRMED verdicts should be verified as true positives by manual review
3. **SARIF compatibility**: Output renders correctly in GitHub Security tab with code flow visualization
4. **Cost per audit < $10**: Standard depth profile on a 50K LOC codebase should cost < $10
5. **Time per audit < 15 min**: Standard depth profile on a 50K LOC codebase should complete in < 15 minutes
6. **Competitive parity on detection**: Find at least the same vulnerability classes as Semgrep OSS on test benchmarks (OWASP Benchmark, Juliet Test Suite)

---

## 15. Project Structure

```
sec-af/
├── docs/
│   └── DESIGN.md                  # This document
├── src/
│   └── sec_af/
│       ├── __init__.py
│       ├── audit.py               # Top-level SecurityAudit class
│       ├── config.py              # AuditConfig, DepthProfile, BudgetConfig
│       ├── orchestrator.py        # AuditOrchestrator — phase management
│       ├── schemas/
│       │   ├── __init__.py
│       │   ├── recon.py           # ReconResult, ArchitectureMap, etc.
│       │   ├── hunt.py            # RawFinding, HuntResult, etc.
│       │   ├── prove.py           # VerifiedFinding, Verdict, Proof, etc.
│       │   ├── output.py          # SecurityAuditResult, AttackChain, etc.
│       │   └── compliance.py      # ComplianceMapping, ComplianceGap, etc.
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── recon/             # RECON agent prompts and logic
│       │   ├── hunt/              # HUNT strategy prompts and logic
│       │   ├── prove/             # PROVE prover prompts and logic
│       │   └── dedup.py           # Deduplicator/Correlator
│       ├── output/
│       │   ├── __init__.py
│       │   ├── sarif.py           # SARIF 2.1.0 generator
│       │   ├── json_output.py     # Rich JSON output
│       │   ├── github_issues.py   # GitHub Issues creator
│       │   └── report.py          # Summary report generator
│       ├── compliance/
│       │   ├── __init__.py
│       │   └── mapping.py         # CWE → compliance framework lookup
│       └── cli/
│           ├── __init__.py
│           └── main.py            # CLI entry point
├── tests/
│   ├── test_recon.py
│   ├── test_hunt.py
│   ├── test_prove.py
│   ├── test_sarif.py
│   ├── test_scoring.py
│   └── benchmarks/                # OWASP Benchmark, Juliet Test Suite
├── pyproject.toml
├── README.md
└── LICENSE                        # Apache 2.0
```

---

## 16. Open Questions

1. **Name**: SEC-AF vs SECURE-AF vs other? (SEC-AF is concise and follows the af-swe pattern)
2. **Monorepo vs standalone**: Should this live in `int-agentfield-examples/sec-af/` or its own repo?
3. **Harness v1 vs v2**: Should v1 target the current harness or wait for harness v2?
4. **CVSS v4 computation**: Should provers compute CVSS v4 vectors, or should we use a simpler severity model and add CVSS later?
5. **PoC execution in v1**: Should static reasoning only be the v1 default, or should we include basic test execution?
6. **Pricing model**: If offered as a hosted service, per-audit pricing? Per-repo subscription? Pay-per-finding?

---

## 17. References

- [AgentField Harness v2 Design](../../code/agentfield/docs/design/harness-v2-design.md)
- [SWE-AF Architecture](../af-swe/docs/ARCHITECTURE.md)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub SARIF Support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- [EPSS Model](https://www.first.org/epss/)
- [CWE Top 25 (2024)](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Nullify AI](https://nullify.ai/) — Primary competitive reference
- [Endor Labs AI SAST](https://www.endorlabs.com/learn/ai-sast-combining-agents-program-analysis-and-rules-for-high-confidence-code-security)
- [Semgrep](https://semgrep.dev/) — Rule-based SAST reference
- [Konvu](https://konvu.com/) — Agentic triage reference
