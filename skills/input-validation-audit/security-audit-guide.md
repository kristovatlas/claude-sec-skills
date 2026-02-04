# Security Audit Skill - User Guide

## Overview

The Security Audit skill enables Claude Code to perform comprehensive security assessments of web applications, focusing on input validation, sanitization, and encoding vulnerabilities. The skill identifies potential security issues including XSS, SQL injection, command injection, path traversal, SSRF, and other input-related attacks.

## Key Features

### Broad Input Interpretation
The skill uses a "broad interpretation" approach to identifying untrusted inputs, treating the following as potentially dangerous:

**Untrusted Inputs:**
- User-supplied data (query params, POST data, cookies, headers)
- File uploads
- Third-party API responses
- External service data

**Semi-Trusted Inputs:**
- Database content (could be compromised)
- Cache/session storage
- Configuration files
- Internal APIs outside project scope
- Logs and audit trails

This broad interpretation helps identify vulnerabilities that might arise if an attacker compromises one component of the application.

### Bidirectional Analysis
The skill performs both:
- **Forward Analysis:** Traces data from inputs → sinks
- **Backward Analysis:** Traces sinks → inputs

This dual approach ensures comprehensive coverage and catches vulnerabilities that might be missed by single-direction analysis.

### Sub-Agent Validation
Each potential finding is validated by a sub-agent that:
1. Verifies the vulnerability path exists
2. Assesses exploitability
3. Checks for framework protections
4. Assigns a confidence score (0-100)

**Confidence Levels:**
- **High (80-100):** Clear exploitable vulnerability
- **Medium (50-79):** Likely vulnerable with some conditions
- **Low (20-49):** Potential issue requiring manual review
- **False Positive (0-19):** Properly protected

Findings with confidence ≥ 50 are reported as primary findings, while lower scores are listed separately.

### Vulnerability Coverage

The skill identifies these common vulnerability types:

- **XSS (Cross-Site Scripting):** DOM manipulation, template injection, unsafe JavaScript execution
- **SQL Injection:** String concatenation in queries, unparameterized queries
- **Command Injection:** Shell execution with user input
- **Path Traversal:** User-controlled file paths
- **SSRF:** User-controlled URLs in HTTP requests
- **Insecure Deserialization:** Unsafe pickle/marshal/YAML loading
- **And more**

## Skill Components

### SKILL.md
Main instructions containing:
- Audit workflow
- Input/sink classification
- Bidirectional analysis approach
- Sub-agent validation framework
- Report format

### Scripts (`scripts/`)

1. **find_sinks.py** - Pattern matching for security sinks
   ```bash
   python3 find_sinks.py /path/to/project --output sinks.json
   ```

2. **trace_dataflow.py** - Data flow analysis utilities
   ```bash
   python3 trace_dataflow.py /path/to/file --output flows.json
   ```

3. **validate_finding.py** - Sub-agent validation with confidence scoring
   ```bash
   python3 validate_finding.py findings.json --output validated.json --threshold 50
   ```

### References (`references/`)

1. **vulnerability-patterns.md** - Detailed patterns for each vulnerability type with examples of vulnerable vs. safe code

2. **secure-coding-practices.md** - Framework-specific security guidance for:
   - React/JSX
   - Express.js/Node.js
   - Django/Python
   - Laravel/PHP
   - Ruby on Rails
   - Flask
   - Vue.js
   - ASP.NET
   - Spring Boot/Java

3. **encoding-reference.md** - Context-appropriate encoding methods:
   - HTML context
   - JavaScript context
   - URL context
   - CSS context
   - SQL context (parameterization)
   - LDAP, XML, JSON contexts

4. **report-templates.md** - Professional audit report templates:
   - Executive summary templates
   - Finding description templates
   - Validation steps templates
   - Remediation templates with before/after code
   - Impact assessment templates
   - Architecture diagram examples (Mermaid)
   - Recommendations section templates
   - Remediation tracking tables
   - Quality checklist

## Example Usage

When you ask Claude Code to perform a security audit:

```
Audit this web application for security vulnerabilities, focusing on input validation issues.
```

Claude will:
1. Load the security-audit skill
2. Map the application structure
3. **Create architecture diagrams** showing data flow and trust boundaries
4. Enumerate all inputs (broad interpretation)
5. Identify security sinks
6. Perform bidirectional flow analysis
7. Validate findings with confidence scoring
8. Generate **TWO reports**:
   - **Technical Analysis Report:** Complete findings for internal use
   - **Audit Report:** Polished, high-confidence findings ready for formal documentation

## Report Structure

The skill generates two complementary reports:

### 1. Technical Analysis Report (Complete)

For internal security team use - includes ALL findings:

**Executive Summary**
- Audit scope and methodology
- Application architecture overview  
- Total findings by confidence level
- Critical risk summary

**Architecture Diagrams**
- Data flow diagram (input → sink paths)
- Trust boundary diagram (validation points)
- Attack surface map (entry points and risk levels)

**All Findings by Confidence**
- High confidence (≥80): Clear vulnerabilities
- Medium confidence (50-79): Likely issues  
- Low confidence (20-49): Requires investigation
- False positives (<20): Protected/not vulnerable

**Complete Inventories**
- All inputs identified
- All security sinks
- Validation coverage mapping

### 2. Audit Report (High-Confidence Only)

Professional report ready for stakeholders, compliance, or public disclosure:

**Executive Summary**
- Business-friendly overview
- Risk summary
- Immediate actions required

**Architecture Overview**
- Visual diagrams
- Component descriptions
- Trust boundaries

**Detailed Findings** (≥80 confidence only)
Each finding includes:
- Clear description in business terms
- Technical details with code snippets
- Proof of concept exploit
- Impact assessment (business + technical)
- **Validation steps** for independent verification
- **Remediation guide** with before/after code
- Implementation steps with timeline
- References to OWASP, CWE, etc.

**Recommendations**
- Critical/High/Medium priority actions
- Timelines and effort estimates
- Long-term security improvements
- Defense in depth strategies

**Validation and Testing Guide**
- How to verify each type of finding
- Tools for testing
- Expected results

**Remediation Tracking Table**
- Status tracking for all findings
- Assignment and deadlines
- Verification checkboxes

**Appendices**
- Input inventory
- Sink inventory
- Validation coverage matrix
- Framework security features

## Best Practices

When using this skill:

1. **Provide context** - Let Claude know about any security documentation or trusted input sources
2. **Review findings** - Manual verification is always recommended for security issues
3. **Iterative analysis** - For large codebases, consider analyzing in sections
4. **Framework knowledge** - Mention which frameworks/libraries are in use for better analysis
5. **False positive review** - Review low-confidence findings as they may reveal architectural issues

## Limitations

- Static analysis cannot detect all runtime vulnerabilities
- Framework-specific protections may not be fully recognized
- Complex data flows may be difficult to trace automatically
- Manual verification is recommended for all findings
- Does not replace professional security auditing

## Integration with Development Workflow

This skill is ideal for:
- Pre-commit security reviews
- Pull request security checks
- Periodic security audits
- Security training and education
- Compliance verification
- Vulnerability disclosure preparation

## Support

For issues or questions about the security-audit skill, consider:
- Reviewing the reference documentation included in the skill
- Testing findings manually to verify exploitability
- Consulting OWASP guidelines for additional context
- Engaging security professionals for critical applications
