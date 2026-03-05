---
name: owasp-asvs-audit
description: Performs a comprehensive security audit of a web application codebase against all ~350 requirements of the OWASP Application Security Verification Standard (ASVS) v5.0.0. Covers 17 chapters including injection prevention, authentication, authorization, cryptography, session management, and API security. Produces a structured report with findings, evidence, confidence scores, and remediation guidance.
---

# OWASP ASVS Audit Skill

## Overview

This skill performs a comprehensive security audit of a web application codebase against the **OWASP Application Security Verification Standard (ASVS) v5.0.0** at **Level 3 (Advanced / High Assurance)**.

ASVS Level 3 is cumulative — it includes all Level 1 and Level 2 requirements. Every finding is tagged with its ASVS level so results can be filtered for L1-only or L2-only compliance if desired.

The audit is performed through static analysis of the application source code, configuration files, dependency manifests, and related artifacts. Requirements that cannot be verified through static analysis alone are flagged for manual review.

## Source Material

This skill is based on OWASP ASVS v5.0.0, released May 2025, licensed under Creative Commons Attribution-Share Alike v4.0.

- **GitHub repository:** https://github.com/OWASP/ASVS (tag: v5.0.0)
- **Source files:** `5.0/en/0x10-V1-Encoding-Sanitization.md` through `5.0/en/0x26-V17-WebRTC.md`
- **Machine-readable data:** CSV available at GitHub releases
- **Official website:** https://asvs.dev/v5.0.0/

### First-Run Setup

Before the first audit, verify the ASVS reference files are populated:

1. Check if the section files in `sections/` (see Chapter Map below) contain full requirement details.
2. If any section file contains only stub content or `<!-- POPULATE FROM SOURCE -->` markers, download the corresponding ASVS 5.0 source file from `https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/` (see the "ASVS Source File" column in the Chapter Map) and populate the section file with the complete requirement text, section descriptions, and guidance.
3. Also download the CSV from GitHub releases (`OWASP_Application_Security_Verification_Standard_5.0.0_en.csv`) for cross-reference during auditing.

## Skill File Structure

```
.claude/skills/owasp-asvs-audit/
├── SKILL.md                  # This file — orchestrator instructions
├── README.md                 # Human-facing documentation
└── sections/
    ├── V01-encoding-and-sanitization.md
    ├── V02-validation-and-business-logic.md
    ├── V03-web-frontend-security.md
    ├── V04-api-and-web-services.md
    ├── V05-file-processing.md
    ├── V06-authentication.md
    ├── V07-session-management.md
    ├── V08-authorization.md
    ├── V09-self-contained-tokens.md
    ├── V10-oauth-and-oidc.md
    ├── V11-cryptography.md
    ├── V12-secure-communication.md
    ├── V13-configuration.md
    ├── V14-data-protection.md
    ├── V15-secure-coding-and-architecture.md
    ├── V16-security-logging-and-error-handling.md
    └── V17-webrtc.md
```

## ASVS v5.0.0 Chapter Map

| Chapter | Title | Skill Section File | ASVS Source File |
|---------|-------|--------------------|------------------|
| V1 | Encoding and Sanitization | `V01-encoding-and-sanitization.md` | `0x10-V1-Encoding-Sanitization.md` |
| V2 | Validation and Business Logic | `V02-validation-and-business-logic.md` | `0x11-V2-Validation-Business-Logic.md` |
| V3 | Web Frontend Security | `V03-web-frontend-security.md` | `0x12-V3-Web-Frontend-Security.md` |
| V4 | API and Web Services | `V04-api-and-web-services.md` | `0x13-V4-API-Web-Services.md` |
| V5 | File Processing | `V05-file-processing.md` | `0x14-V5-File-Processing.md` |
| V6 | Authentication | `V06-authentication.md` | `0x15-V6-Authentication.md` |
| V7 | Session Management | `V07-session-management.md` | `0x16-V7-Session-Management.md` |
| V8 | Authorization | `V08-authorization.md` | `0x17-V8-Authorization.md` |
| V9 | Self-Contained Tokens | `V09-self-contained-tokens.md` | `0x18-V9-Self-Contained-Tokens.md` |
| V10 | OAuth and OIDC | `V10-oauth-and-oidc.md` | `0x19-V10-OAuth-OIDC.md` |
| V11 | Cryptography | `V11-cryptography.md` | `0x1A-V11-Cryptography.md` |
| V12 | Secure Communication | `V12-secure-communication.md` | `0x1B-V12-Secure-Communication.md` |
| V13 | Configuration | `V13-configuration.md` | `0x1C-V13-Configuration.md` |
| V14 | Data Protection | `V14-data-protection.md` | `0x1D-V14-Data-Protection.md` |
| V15 | Secure Coding and Architecture | `V15-secure-coding-and-architecture.md` | `0x1E-V15-Secure-Coding-Architecture.md` |
| V16 | Security Logging and Error Handling | `V16-security-logging-and-error-handling.md` | `0x1F-V16-Security-Logging-Error-Handling.md` |
| V17 | WebRTC | `V17-webrtc.md` | `0x26-V17-WebRTC.md` |

The "ASVS Source File" column references the filename in the [OWASP ASVS v5.0.0 repository](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/) from which each section's requirements were sourced.

**Appendices referenced:** A (Glossary), B (References), C (Cryptographic Standards), D (Recommendations)

## Audit Workflow

### Phase 1: Discovery (Orchestrator)

The orchestrator performs project discovery before dispatching any section audits. This context is passed to every sub-agent.

**Discovery steps:**

1. **Language and framework detection:** Identify primary language(s), web framework(s), templating engine(s), and build system.
2. **Dependency analysis:** Read package manifests (`package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `go.mod`, `Cargo.toml`, etc.) to understand the dependency tree.
3. **Directory structure mapping:** Map source directories, configuration files, test directories, deployment configs (Dockerfiles, k8s manifests, CI/CD configs).
4. **Authentication and session architecture:** Identify how auth is handled — framework-provided, custom, OAuth/OIDC provider, JWT-based, session-based, etc.
5. **Database layer:** Identify ORM usage, raw query patterns, database type(s).
6. **API surface:** Identify API style (REST, GraphQL, gRPC, WebSocket), route definitions, middleware chains.
7. **Frontend architecture:** SPA, SSR, static, or hybrid. Templating engine(s) in use.
8. **File handling:** Whether the application handles file uploads, file processing, or serves user-provided files.
9. **Communication patterns:** Outbound HTTP calls, message queues, inter-service communication.
10. **Existing security measures:** Identify any existing security middleware, CSP headers, rate limiting, WAF integration, CORS configuration, etc.

**Discovery output format:**

```json
{
  "project": {
    "name": "<detected or directory name>",
    "languages": ["<language>"],
    "frameworks": ["<framework>"],
    "build_system": "<build system>",
    "package_managers": ["<package manager>"]
  },
  "architecture": {
    "type": "<monolith|microservice|serverless|etc>",
    "frontend": "<SPA|SSR|static|hybrid|API-only>",
    "templating_engines": ["<engine>"],
    "database": {
      "type": "<type>",
      "orm": "<orm or 'raw queries'>",
      "connection_method": "<description>"
    },
    "api_style": ["<REST|GraphQL|gRPC|WebSocket>"],
    "auth_mechanism": "<description>",
    "session_management": "<description>"
  },
  "security_posture": {
    "existing_measures": ["<identified measures>"],
    "dependency_count": "<number>",
    "has_security_tests": "<boolean>",
    "has_ci_cd": "<boolean>"
  },
  "file_structure": {
    "source_dirs": ["<paths>"],
    "config_files": ["<paths>"],
    "test_dirs": ["<paths>"],
    "deployment_configs": ["<paths>"]
  },
  "applicable_chapters": {
    "V1": true,
    "V2": true,
    "V3": "<true if frontend exists>",
    "V4": "<true if API endpoints exist>",
    "V5": "<true if file handling exists>",
    "V6": "<true if authentication exists>",
    "V7": "<true if session management exists>",
    "V8": "<true if authorization logic exists>",
    "V9": "<true if JWTs or self-contained tokens used>",
    "V10": "<true if OAuth/OIDC used>",
    "V11": "<true if cryptographic operations exist>",
    "V12": "<true if outbound/inbound communication exists>",
    "V13": true,
    "V14": true,
    "V15": true,
    "V16": true,
    "V17": "<true if WebRTC used>"
  }
}
```

### Phase 2: Section Audits (Sub-Agents)

After discovery, the orchestrator dispatches sub-agents **sequentially** for each applicable chapter. Each sub-agent:

1. Reads its section file from `sections/` (e.g., `sections/V01-encoding-and-sanitization.md`) to load the full ASVS requirements and audit guidance.
2. Receives the discovery context.
3. Evaluates **every** requirement at all levels (L1, L2, L3) against the codebase.
4. For each requirement, first determines **applicability** — if the requirement doesn't apply to this project (e.g., WebRTC requirements for a REST API), marks it `N/A` with justification.
5. For applicable requirements, examines the relevant source files and produces a finding.
6. Writes intermediate results to `asvs-audit-results/<chapter>.json` as it completes.

**Sub-agent model selection:** Sub-agents MUST use the latest Opus model for all code analysis and assessment work. Only truly menial tasks (reading a single file path, listing directory contents) may use a smaller model.

**Execution order:** Chapters should be audited in order V1 through V17 (skipping non-applicable chapters). Some chapters inform later ones — for example:
- V6 (Authentication) findings inform V7 (Session Management) and V8 (Authorization)
- V1 (Encoding/Sanitization) findings inform V3 (Web Frontend Security)
- V11 (Cryptography) findings inform V12 (Secure Communication)

The orchestrator should pass relevant findings from earlier chapters to later sub-agents when dependencies exist.

### Phase 3: Report Generation (Orchestrator)

After all section audits complete, the orchestrator:

1. Aggregates all `asvs-audit-results/<chapter>.json` files.
2. Generates two output files:
   - `asvs-audit-results/report.json` — structured machine-readable report
   - `asvs-audit-results/report.md` — human-readable Markdown report

## Finding Structure

Every ASVS requirement evaluation produces a finding with this structure:

```json
{
  "requirement_id": "v5.0.0-1.2.5",
  "chapter": "V1",
  "chapter_title": "Encoding and Sanitization",
  "section": "1.2",
  "section_title": "Injection Prevention",
  "requirement_text": "Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding.",
  "level": 1,
  "status": "FAIL",
  "confidence": 0.92,
  "evidence": [
    {
      "file": "src/utils/deploy.py",
      "line": 47,
      "code_snippet": "os.system(f'git clone {user_provided_url}')",
      "description": "User-provided URL is passed directly to os.system() without sanitization or parameterization."
    }
  ],
  "remediation": "Replace os.system() with subprocess.run() using a list of arguments (parameterized form): subprocess.run(['git', 'clone', user_provided_url], check=True). Additionally, validate the URL against an allowlist of expected patterns.",
  "references": [
    "OWASP Cheat Sheet: OS Command Injection Defense",
    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
  ]
}
```

### Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Requirement is satisfied. Evidence shows correct implementation. |
| `FAIL` | Requirement is not satisfied. Evidence shows a deficiency or vulnerability. |
| `N/A` | Requirement does not apply to this project. Justification is provided. |
| `MANUAL_REVIEW` | Requirement cannot be fully verified through static analysis alone. Describes what was checked and what remains to be verified. |

### Confidence Scores

Every finding includes a `confidence` score from 0.0 to 1.0:

- **0.9–1.0:** Very high confidence. Clear, unambiguous evidence (e.g., raw SQL string concatenation with user input).
- **0.7–0.89:** High confidence. Strong indicators but some ambiguity (e.g., dynamic query construction that may or may not include user input).
- **0.5–0.69:** Moderate confidence. Circumstantial evidence or complex control flow makes determination uncertain.
- **0.0–0.49:** Low confidence. Largely inferential; requires human verification.

## Report Format

### Markdown Report Structure (`report.md`)

```markdown
# OWASP ASVS v5.0.0 Audit Report

**Project:** <name>
**Date:** <date>
**Target Level:** 3 (Advanced / High Assurance)
**Audited by:** Claude Code (owasp-asvs-audit skill)

## Executive Summary

- **Total requirements evaluated:** <N>
- **Applicable requirements:** <N>
- **PASS:** <N> (<percentage>)
- **FAIL:** <N> (<percentage>)
- **N/A:** <N>
- **MANUAL_REVIEW:** <N>

### Compliance by Level
- **Level 1:** <N>/<total L1> (<percentage>)
- **Level 2:** <N>/<total L2> (<percentage>)
- **Level 3:** <N>/<total L3> (<percentage>)

## Critical Findings (High Confidence ≥ 0.8)

<findings sorted by severity, grouped by chapter>

## Additional Findings (Confidence < 0.8)

<findings sorted by confidence descending, grouped by chapter>

## Items Requiring Manual Review

<MANUAL_REVIEW findings grouped by chapter, with description of what was checked and what remains>

## Detailed Results by Chapter

### V1: Encoding and Sanitization
<all findings for V1>

### V2: Validation and Business Logic
<all findings for V2>

... (V3 through V17)

## Appendix: Project Discovery Context

<discovery output JSON>

## Appendix: Methodology

This audit was performed through static analysis of the application source code
using the OWASP ASVS v5.0.0 framework. Findings represent point-in-time
assessment of the codebase and do not constitute a full penetration test or
dynamic application security test (DAST). Requirements marked MANUAL_REVIEW
require runtime testing, infrastructure inspection, or access to deployment
configuration not available through source code analysis alone.
```

## Intermediate Results and Resumability

Each sub-agent writes its results to `asvs-audit-results/<chapter>.json` upon completion. If the audit is interrupted:

1. The orchestrator checks for existing `<chapter>.json` files in `asvs-audit-results/`.
2. Chapters with existing result files are skipped (their results are loaded as-is).
3. The audit resumes from the first chapter without a result file.

To force a full re-audit, delete the `asvs-audit-results/` directory before running.

## Key Principles from ASVS v5.0.0

### Documented Security Decisions

ASVS 5.0 introduces requirements for documenting key security decisions. Each chapter starts with documentation requirements that capture how controls are applied and why. When auditing, the sub-agent should look for evidence of these documented decisions (e.g., in architecture docs, README files, code comments, ADRs) and note their presence or absence.

### Goal-Oriented Requirements

ASVS 5.0 requirements emphasize security outcomes rather than mandating specific technical implementations. When evaluating a requirement, the sub-agent should assess whether the *security goal* is achieved, even if the specific implementation approach differs from the most common pattern.

### Level Definitions

- **Level 1 (Opportunistic):** First layer of defense. Targets easily detectable vulnerabilities. Suitable for initial adoption. Protects against OWASP Top 10, basic automated attacks, common configuration errors.
- **Level 2 (Standard):** Comprehensive standard security practices. Recommended for most applications handling sensitive data. Protects against targeted attacks, insider threats, business logic flaws.
- **Level 3 (Advanced):** High-assurance requirements for critical systems. Banking, payment processors, healthcare, military, critical infrastructure. Protects against nation-state actors, sophisticated organized crime, zero-day exploits, supply chain attacks.

### Non-Applicability

Certain chapters or requirements may not apply to a given application. ASVS explicitly supports this: "Certain verification requirements may not be applicable to the application under test." When marking a requirement as N/A, always provide a clear justification. For example:
- V17 (WebRTC) → N/A if the application does not use WebRTC
- V9 (Self-Contained Tokens) → N/A if the application uses server-side sessions exclusively
- V10 (OAuth and OIDC) → N/A if the application does not implement or consume OAuth/OIDC

## Guidance from ASVS Appendices

### Appendix C: Cryptographic Standards

When evaluating cryptographic requirements (V11, V12), refer to the ASVS Appendix C which specifies approved algorithms, key sizes, and deprecated mechanisms. Key points:
- Approved symmetric algorithms: AES-128, AES-256 (GCM mode preferred)
- Approved hash functions: SHA-256, SHA-384, SHA-512, SHA-3
- Deprecated: MD5, SHA-1, DES, 3DES, RC4, ECB mode
- RSA minimum key size: 2048 bits (3072+ recommended)
- ECDSA minimum: P-256 curve
- Password hashing: Argon2id preferred, bcrypt and scrypt acceptable
- Post-quantum considerations are noted in v5.0 but not yet mandatory

### Appendix D: Recommendations

Contains additional guidance beyond the core requirements. Sub-agents should reference these recommendations when providing remediation advice but should not treat them as mandatory requirements.

## Important Caveats

1. **This is static analysis only.** Many ASVS requirements are best verified through dynamic testing, penetration testing, or infrastructure review. The `MANUAL_REVIEW` status exists for these cases.

2. **Confidence scores reflect the auditor's certainty, not severity.** A low-confidence FAIL finding may still represent a critical vulnerability if confirmed.

3. **False positives are possible.** Complex control flow, framework-provided protections that aren't obvious from source inspection, and dynamic dispatch patterns can all lead to incorrect findings. The confidence score should reflect this uncertainty.

4. **This audit does not replace professional security assessment.** It provides a structured, thorough first pass that significantly reduces the work needed for a formal ASVS verification.

5. **ASVS v5.0 removed direct CWE mappings.** While v4.0.3 included CWE IDs, v5.0 delegates cross-referencing to the OWASP Common Requirement Enumeration (CRE) project. Sub-agents may still reference relevant CWE IDs in remediation guidance where they are well-known and helpful.