---
name: dynamic-js-audit
description: Auditing dynamically loaded JavaScript
---

# Claude Code Prompt: JavaScript Dependency & Dynamic Loading Security Audit

## Purpose
Perform a comprehensive security audit of dynamically loaded JavaScript dependencies in this web application. Identify security risks, check adherence to best practices, and propose non-breaking patches or alternatives.

---

## Instructions

### Phase 1: Discovery - Find All Dynamic JavaScript Loading

Scan the entire codebase for dynamically loaded JavaScript. Look for:

**1. Script Tag Injection Patterns:**
```
- <script src="..."> tags in HTML files
- document.createElement('script')
- element.innerHTML containing <script>
- document.write() with script content
- insertAdjacentHTML() with scripts
```

**2. Dynamic Import Mechanisms:**
```
- import() dynamic imports
- require() with variable paths
- System.import()
- AMD define() and require()
- Webpack's require.ensure()
- Code splitting chunks
```

**3. External Resource Loading:**
```
- CDN-hosted libraries (cdnjs, jsdelivr, unpkg, etc.)
- Third-party analytics scripts (Google Analytics, Mixpanel, etc.)
- Advertising scripts
- Social media widgets
- Payment processors (Stripe, PayPal SDKs)
- Chat widgets (Intercom, Drift, etc.)
- A/B testing tools
```

**4. Iframe Sources:**
```
- <iframe src="..."> tags
- Dynamically created iframes
- postMessage() communication patterns
```

**5. Web Workers & Service Workers:**
```
- new Worker() instantiations
- Service worker registrations
- Shared workers
```

For each discovered instance, record:
- File path and line number
- The URL/source being loaded
- Whether it's first-party or third-party
- Loading context (inline, deferred, async, module)
- Any existing security measures in place

---

### Phase 2: Security Risk Assessment

Evaluate each dynamically loaded resource against these risk categories:

**A. Supply Chain Risks:**
- [ ] Is Subresource Integrity (SRI) used for external scripts?
- [ ] Are specific versions pinned or using `latest`/unpinned versions?
- [ ] Is the CDN/source reputable and unlikely to be compromised?
- [ ] Could the external resource be self-hosted instead?

**B. Cross-Site Scripting (XSS) Vectors:**
- [ ] Is user input ever used in script URLs or content?
- [ ] Are there proper Content Security Policy (CSP) headers?
- [ ] Is innerHTML/outerHTML used with untrusted content?
- [ ] Are template literals interpolating external data into scripts?

**C. Iframe Security:**
- [ ] Do iframes use the `sandbox` attribute?
- [ ] Is `allow-scripts` granted only when necessary?
- [ ] Is `allow-same-origin` combined dangerously with `allow-scripts`?
- [ ] Are proper `allow` feature policies set?
- [ ] Is the `referrerpolicy` attribute set appropriately?

**D. Protocol & Transport Security:**
- [ ] Are all external resources loaded over HTTPS?
- [ ] Are there any protocol-relative URLs (`//example.com`)?
- [ ] Is mixed content possible?

**E. Data Exposure Risks:**
- [ ] Do third-party scripts have access to sensitive DOM content?
- [ ] Are cookies properly scoped (HttpOnly, Secure, SameSite)?
- [ ] Is localStorage/sessionStorage accessible to third-party scripts?
- [ ] Are postMessage handlers validating origin?

---

### Phase 3: Best Practices Checklist

For each category, check implementation status:

**Content Security Policy (CSP):**
```
- script-src directive configured
- No 'unsafe-inline' without nonces/hashes
- No 'unsafe-eval' unless absolutely required
- Specific domains whitelisted (no wildcards)
- report-uri configured for monitoring
```

**Subresource Integrity (SRI):**
```
- integrity attribute on all external scripts
- crossorigin="anonymous" set when using SRI
- SRI hashes match current library versions
```

**Iframe Sandboxing:**
```
- sandbox attribute present on all third-party iframes
- Minimal permissions granted (principle of least privilege)
- Feature policy/Permissions-Policy configured
```

**Script Loading Security:**
```
- async/defer used appropriately
- Scripts loaded from trusted origins only
- Fallback mechanisms for CDN failures
- Error handling for failed script loads
```

**postMessage Security:**
```
- Origin validation in all message handlers
- Structured data validation
- No eval() of received messages
```

---

### Phase 4: Generate Report & Patches

For each identified issue, provide:

**1. Issue Description:**
- What the vulnerability/risk is
- Where it's located (file:line)
- Severity rating (Critical/High/Medium/Low/Info)
- Potential impact if exploited

**2. Proposed Patch:**
Provide a code diff showing the fix. Consider:
- The application's architecture and patterns
- Existing build tools and workflows
- Browser compatibility requirements
- Performance implications
- Whether the fix might break existing functionality

Format patches as:
```diff
// File: path/to/file.js
// Line: XX-YY
// Risk: [severity]

- <original code>
+ <patched code>
```

**3. Explanation:**
- Why the patch works
- Any trade-offs or considerations
- Testing recommendations

**4. Alternatives (when direct fix isn't possible):**
If a best practice cannot be directly implemented, suggest:
- Compensating controls
- Alternative libraries or approaches
- Configuration changes
- Architecture modifications
- Monitoring/detection strategies as interim measures

---

### Phase 5: Prioritized Remediation Plan

Organize findings into an actionable remediation plan:

1. **Immediate Actions (Critical/High):**
   - Issues that could lead to RCE or data exfiltration
   - Missing SRI on widely-used external scripts
   - XSS vectors in script loading

2. **Short-term Improvements (Medium):**
   - CSP implementation or hardening
   - Iframe sandboxing gaps
   - Protocol upgrades

3. **Long-term Enhancements (Low/Info):**
   - Self-hosting external dependencies
   - Build process improvements
   - Monitoring and alerting setup

---

## Output Format

Structure your response as:

```markdown
# JavaScript Dependency Security Audit Report

## Executive Summary
[Brief overview of findings and risk posture]

## Discovery Results
[Table of all dynamically loaded scripts/resources found]

## Findings

### [SEVERITY] Finding #1: [Title]
**Location:** `path/to/file.js:XX`
**Description:** [What's wrong]
**Risk:** [Potential impact]

#### Current Code:
\`\`\`javascript
// problematic code
\`\`\`

#### Proposed Patch:
\`\`\`diff
- problematic code
+ fixed code
\`\`\`

#### Explanation:
[Why this fix works and considerations]

#### Alternatives (if applicable):
[Other approaches if the primary fix isn't viable]

---

[Repeat for each finding]

## Remediation Roadmap
[Prioritized list of actions]

## Additional Recommendations
[General hardening suggestions]
```

---

## Special Considerations

**Do NOT:**
- Modify any files directly
- Propose changes that would break core functionality
- Suggest removing necessary third-party integrations without alternatives
- Recommend security measures incompatible with the app's tech stack

**DO:**
- Consider the full context of how each script is used
- Check for existing security measures before flagging issues
- Provide fallback options for essential functionality
- Note when manual review is needed for complex cases
- Consider framework-specific solutions (React, Vue, Angular, etc.)

---

## Begin Audit

Start by exploring the project structure to understand the application architecture, then systematically scan for dynamically loaded JavaScript following the phases above.