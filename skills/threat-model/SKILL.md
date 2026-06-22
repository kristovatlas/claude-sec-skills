---
name: threat-model
description: Generate, refresh, or evaluate a STRIDE/LINDDUN threat model for an application or system in the current codebase. Produces a THREAT_MODEL.md covering assets (including intangible assets), trust boundaries, threat actors, threats, countermeasures, an Aggregate Risk Index (ARI) grade, and a prioritized remediation backlog. Use when the user asks to "threat model", "generate a security analysis", "STRIDE analysis", refresh or update an existing threat model, evaluate a proposed redesign's security impact, or compute a risk-index delta between two versions of a system.
---

# Threat Model Generation Skill

## Intro

Version: 6
When changes are made to this document by an agent, please bump the version number.

**Notable changes since v5:**
- **Trust Boundaries** and **Threat Actors** are now required, first-class sections of every generated model, each with its own ID space (`TB#`, `TA#`). Every threat must cite the boundary it crosses and the actor(s) capable of executing it, and every boundary and actor must be implicated by at least one threat.
- **Privacy is now modeled as first-class threats against intangible assets** (e.g., user trust in data handling, regulatory standing) rather than living only inside the LINDDUN section. This preserves the asset → threat → countermeasure invariant for privacy issues and folds them into the ARI. Three guardrails — no double-counting, no magnet assets, calibrate don't catastrophize — keep this from producing slop.
- **Every STRIDE and LINDDUN bullet now carries a disposition tag** (`[→ T#]`, `[→ OQ#]`, or `[N/A — reason]`) recording where it landed in the model. This closes the long-standing gap where LINDDUN items were brainstormed but never converted into threats.
- **The STRIDE and LINDDUN analyses move to a Brainstorming Appendix near the bottom of the generated model**, so the document leads with decision-useful content (backlog, boundaries, threats) while preserving the brainstorming scaffolding for future refreshes.
- **A Prioritized Remediation Backlog** appears near the top of every model, ranking open gaps by their ARI residual-risk contribution — a quick, skimmable to-do list for readers who don't want to absorb the whole model.
- Added YAML frontmatter (`name` / `description`) so the skill registers and triggers like the other skills in this repo.
- **Model selection is model-agnostic and future-proof.** Instead of pinning a version, the skill says to use the most capable model available at run time, degrade only to the next-best, and record any degradation in the generated model's footer — so it needs no edit when a new model ships. (Illustrated historically by the Fable line auto-degrading to Opus 4.8 on cyber content, which was acceptable as next-best; a drop to a Haiku tier would not have been.)

**Notable changes since v4:**
- Every generated threat model must now include a "NOTICE TO AI ASSISTANTS AND AUTOMATED REVIEWERS" preamble immediately after the doc version line. The preamble warns downstream readers (especially LLM-based reviewers) that the document is a working hypothesis, not verified ground truth, and that audits must derive findings from code rather than from the document. The canonical text lives only inside the template below — agents should copy it from there verbatim and not maintain a parallel copy elsewhere in the skill or the generated doc.

**Notable changes since v3:**
- Codebase snapshotting is now a required intro element of every generated threat model, with explicit fallback guidance for repos lacking `.git` history.
- The Aggregate Risk Index (ARI) and grade scale are first-class skill features. Every threat model carries an ARI score, and refreshes report the delta vs. the previous version.
- Agents are explicitly directed to adopt a senior security engineer persona and to maintain the model proactively rather than treating it as a one-shot deliverable.
- A "Proposed Changes and Redesigns" workflow lets the threat model present current ARI vs. projected ARI for each design option under consideration, so security can steer design decisions.
- "Maintenance Guidance for Future Agents" and "Open Questions for the Team" are now required final sections of every generated model.

## When to Use

Use this skill when the user asks you to generate a threat model, security analysis, or STRIDE analysis for an application or system you have access to in the current codebase.

Also use this skill when the user asks you to refresh or update an existing threat model, evaluate a proposed redesign's security impact, or compute a risk-index delta between two versions of the system.

## Persona

When producing or refreshing a threat model, adopt the perspective of a senior security engineer who:

- Has reviewed multiple production systems in the relevant domain (web app security, smart contracts, AI/ML, regulated data, etc.).
- Has written postmortems and been on call for incident response, so understands which controls actually fire in practice and which look good on paper but fail in real conditions.
- Knows that the threat model's value is in steering decisions — its primary audience is engineers and product owners who will use it to allocate effort, not auditors who will use it to check a box.
- Calibrates ratings conservatively. A "Critical" rating means something specific (see Calibration Anchors below) and should not be used as a synonym for "important."
- Treats ambiguity honestly. When a control's status can't be verified from the code alone, the model says so; it does not guess.

Match the tone to the audience. Engineers reading this should be able to act on it. Avoid filler, generic platitudes, and threats that aren't grounded in something you actually observed.

## Prerequisites

Before generating the threat model, you MUST thoroughly explore the codebase to understand:

1. **Architecture**: Runtime environment, hosting, databases, external services, deployment pipeline.
2. **Entry points**: APIs, webhooks, user interfaces, CLI commands, scheduled jobs, on-chain transactions.
3. **Data flows**: What data enters the system, where it's stored, where it's sent, what transformations occur.
4. **Authentication & authorization**: How users/services authenticate, permission models, token handling, on-chain role hierarchies (where applicable).
5. **Integrations**: Third-party APIs, SDKs, platform-specific handlers, OAuth flows, oracles, indexers.
6. **Dependencies**: Package manifests (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `foundry.toml`, etc.), notable transitive dependencies.
7. **Secrets management**: How API keys, signing keys, and credentials are stored, scoped, and rotated.
8. **Configuration**: Environment variables, config files, feature flags, deploy scripts.
9. **Trust boundaries**: Where data or control crosses between zones of differing trust — process ↔ network, client ↔ server, configuration ↔ process, supply chain ↔ shipped artifact, untrusted user ↔ privileged operation. Note especially any crossing that converts attacker-influenceable data into action.
10. **Threat actors**: Who could attack the system and the capability each holds — anonymous internet caller, authenticated user, malicious content contributor, compromised dependency or origin, config attacker, on-path network attacker, insider.

Read all relevant source files. Do not guess or assume — base your analysis on actual code.

## Codebase Snapshot

Every threat model must be anchored to a specific snapshot of the code it analyzes. Without this anchor, future readers cannot tell what has changed since the model was written.

**Preferred form** — record the canonical commit hash:

```
Codebase snapshot: <full-commit-hash> on branch <branch-name> (<date>).
Repository: <repo URL or local path>.
```

If a tag or release is available, record it alongside the hash.

**Fallback when git history is unavailable** (e.g., zip-extracted snapshots, vendored copies, build artifacts without `.git`):

- Record the source archive name and its filesystem mtime (e.g., `clout-main.zip`, mtime `2026-05-14 10:19`).
- If a wrapper repo has its own commit hash, record it explicitly as "wrapper-repo trace only — not the code being analyzed."
- Note that the canonical commit hash should be filled in by the next refresh once the source repository is properly imported.

**Required statement** — every threat model's intro must include a sentence in this form:

> This threat model was produced against [snapshot identifier]. Future updates should re-anchor to the then-current commit hash and record the date of the refresh.

This snapshot anchor makes it trivial for the next reviewer to (a) confirm what they're auditing, (b) `git diff` against the current code to find drift, and (c) know whether a refresh is warranted.

## Model to Use

Use the **most capable model available for security reasoning at the time you run this skill** — never pin a version. New models ship regularly, so this guidance states a *principle*, not a permanent winner; it should not need editing each time the lineup changes.

- **Take the top of the current lineup.** Pick the strongest available reasoning model (the Opus tier today; whatever supersedes it later). As of this writing that is Opus 4.8 (`claude-opus-4-8`) — treat that as a snapshot, not a rule.
- **Degrade only to the next-best.** If your first choice is unavailable, or auto-degrades (some models trip safety filters on cyber / offensive-security content and fall back to a lower model), accept the *next-most-capable* model only. Never silently drop several tiers to a small/fast model — if nothing near the top is available, say so and let the user decide rather than ship a weak analysis.
- **Record any degradation** in the generated model's "Model and Methodology" footer: the intended model, the model actually used, and why.

*Illustrative (historical) example:* when the Fable line was available it scored higher than Opus on cyber benchmarks but routinely tripped safety filters on cyber content and auto-degraded to Opus 4.8 — an acceptable fall-back, because Opus was the next-best model. Degrading instead to a Haiku-tier model would **not** have been acceptable: that skips past the next-best to something far weaker. The model names here will age; the durable part is the rule — next-best only, and record it.

## Maintenance Disposition

A threat model is a living document, not a one-shot deliverable. Agents who interact with a repository containing a `THREAT_MODEL.md` (or equivalent) should:

1. **Read the existing threat model when you encounter one**, even if the user's current request is unrelated. It is the fastest way to learn the system's threat surface and avoid introducing regressions.
2. **Notice drift**. If you observe that the codebase has changed materially since the model was written (new endpoints, new integrations, new keys, new contracts, removed features), propose an update to the user. Do not silently let the model rot.
3. **Refresh proactively at natural breakpoints**: when a major feature merges, when a redesign decision lands, when a security incident occurs, when the system moves between environments (staging → production, testnet → mainnet).
4. **Update the ARI on every refresh** so the trajectory of risk over time is visible.
5. **Preserve audit history**. Never delete entries — retire them with strikethrough and a dated annotation. The Change Log section at the bottom must record every update.

If you are asked to do something else but you notice the threat model is stale, raise it: "I noticed `THREAT_MODEL.md` was last updated [date] and the codebase has since added [X, Y, Z]. Want me to refresh it before / after this task?"

## Handling Existing Threat Models

If a `THREAT_MODEL.md` (or equivalent) already exists in the repo, **never assume it is complete**. Whether the file was written by a human or generated by a previous agent run, treat it as potentially incomplete and review it against the current codebase.

1. **Read the existing file in full.** Understand what's already documented — assets, threats, countermeasures, STRIDE/LINDDUN analyses, the recorded codebase snapshot, the ARI score, and their cross-references.
2. **Compare against the codebase.** Perform the same thorough codebase exploration described in Prerequisites. Identify any gaps: assets not covered, threats not considered, countermeasures missing or with outdated status, STRIDE/LINDDUN categories left empty or stale, trust boundaries or threat actors not enumerated or not wired to threats, the prioritized remediation backlog missing or out of sync with the ARI, codebase snapshot no longer current.
3. **Fill gaps where they exist.** Add missing assets, threats, countermeasures, or analysis. Follow the same ID conventions already in use in the file (e.g., if the last asset is A7, new assets start at A8). Apply **(New — [Month Year])** markers to additions.
4. **Do not add content for the sake of completeness.** If the existing model already adequately covers an area, leave it alone. Every addition must be justified by a genuine gap.
5. **Do not remove or rewrite existing content** unless it is factually incorrect based on the current codebase. If content is outdated, follow the incremental update conventions (strikethrough for retired items, update annotations with dates).
6. **Re-compute the ARI** and report the delta in the Change Log entry.
7. **Validate coverage constraints** after your review (see Cross-Reference Validation, below).

If the existing model pre-dates v6, bring it forward incrementally: add the Trust Boundaries, Threat Actors, and Prioritized Remediation Backlog sections; tag every STRIDE/LINDDUN bullet with its disposition; and move the STRIDE/LINDDUN analyses to the Brainstorming Appendix. Record each structural addition as a single Change Log line rather than rewriting the model wholesale.

## Working Notes File

For large or complex models, maintain a sibling working-notes file (e.g., `docs/threat-model-notes.md`) where you can capture meeting notes, raw observations, research findings, and pending questions before they are synthesized into the formal threat model. This separation lets you preserve the user's voice and intermediate context without polluting the formal doc.

The working-notes file is not a deliverable — it's a scratchpad. The formal `THREAT_MODEL.md` synthesizes from it. When asked to update the threat model, check the working notes first.

## Risk Index and Grading

Every threat model must include an **Aggregate Risk Index (ARI)** so that risk can be compared across versions of the model and across proposed redesigns.

**Formula:**

```
ARI = Σ (severity_weight(T) × coverage_gap(T))   over all threats T

severity_weight:
  Low      = 1
  Medium   = 3
  High     = 5

coverage_gap:
  if any mitigating countermeasure is Applied  (✅)  → 0.10
  elif any is Partial                          (⚠️)  → 0.50
  else (only Not Applied / ⬜)                       → 1.00
```

Rationale: an applied countermeasure does not eliminate residual risk (defects exist, monitoring lags); 0.10 leaves a small floor. A partial countermeasure halves the gap. An unmitigated threat contributes its full severity weight.

**Grade mapping:**

| ARI    | Grade | Interpretation                                                           |
| ------ | ----- | ------------------------------------------------------------------------ |
| ≤ 15   | A     | Mature; only residual risk in fully-mitigated threats.                   |
| 16–35  | B     | A small number of partial or open gaps; no high-severity open threats.   |
| 36–65  | C     | Acceptable for staging; one or two unmitigated high-severity threats.    |
| 66–100 | D     | Material exposure; multiple high-severity threats are open or partial.   |
| > 100  | F     | Many high-severity threats are open; do not deploy to production.        |

**Worked example.** Suppose a system has three threats:

- T1: High severity, one countermeasure Applied → contributes `5 × 0.10 = 0.5`.
- T2: High severity, one countermeasure Partial → contributes `5 × 0.50 = 2.5`.
- T3: Medium severity, no countermeasure Applied → contributes `3 × 1.00 = 3.0`.

ARI = 6.0, Grade A.

**Worked example 2.** A larger system with 30 threats — mix of severities, several Highs unmitigated — typically yields ARI in the 60–100 range, Grade D. The score makes the qualitative state explicit.

**How to present the ARI:**

1. State the current ARI and grade in the Intro section.
2. Show the rough breakdown of contribution by severity (e.g., "14 High threats × avg coverage gap 0.55 ≈ 38.5; 12 Mediums × 0.45 ≈ 16.2; 5 Lows × 0.35 ≈ 4.0; plus applied-residual ≈ 12 = ARI 71").
3. In the Change Log, record the ARI delta on every refresh.
4. When proposed redesigns are listed, show their projected ARI deltas (see "Proposed Changes and Redesigns" below).

**Per-threat contribution drives the backlog.** Each threat's contribution to the ARI — `severity_weight(T) × coverage_gap(T)` — is also its residual-risk ranking. The Prioritized Remediation Backlog (below) sorts open gaps by exactly this value, so the backlog and the ARI can never disagree. Privacy threats modeled against intangible assets (see "Modeling Privacy") contribute to the ARI exactly like any other threat.

**Note on the ARI's standing.** This is a skill-defined metric, not an industry standard (CVSS, OWASP Risk Rating, DREAD all exist and may be more appropriate in some contexts). Its purpose is comparability across versions of the same threat model, not interop with external scoring systems. If the user prefers a standard framework, switch — but keep ONE consistent metric across versions.

## Prioritized Remediation Backlog

Readers who need to *act* — not study — should be able to open the model, read the grade, and get a ranked to-do list without absorbing the whole document. Every generated model therefore includes a **Prioritized Remediation Backlog** immediately after the Risk Index, so this list is the second substantive thing a reader sees.

**How to build it:**

1. For every threat whose best-available countermeasure status is **⬜ Not Applied** or **⚠️ Partial** (i.e., `coverage_gap > 0.10`), take its residual-risk contribution `severity_weight(T) × coverage_gap(T)` — the same per-threat term used in the ARI.
2. Sort descending by that contribution. This is the fix order: the work that most reduces the ARI comes first.
3. For each row, name the specific countermeasure(s) that would close the gap, the threat(s) addressed, the max severity, the current status, the residual contribution, and a rough effort estimate.
4. Flag **quick wins** — high contribution paired with low effort — explicitly; they are the highest-value work and easy to miss when scanning in ID order.

Because the ranking is derived from the ARI, the backlog cannot drift out of sync with the grade. Fully-mitigated threats (status ✅, `coverage_gap = 0.10`) are residual-only and are normally omitted from the backlog unless the user asks for the long tail.

## Trust Boundaries and Threat Actors

Before enumerating threats, state explicitly **where trust changes hands** and **who you are defending against**. These two sections frame every threat — a threat is some *actor* exercising a *capability* across a *boundary* against an *asset*. Skipping them is how models drift into a generic checklist.

### Trust Boundaries (`TB#`)

A trust boundary is any point where data or control passes between zones of differing trust — process ↔ network, client ↔ server, configuration ↔ process, supply chain ↔ shipped artifact, untrusted user ↔ privileged operation. The boundary that converts attacker-*influenceable* data into *action* (or into instruction-grade context for an agent/LLM) is usually the most important one in the model.

Use IDs `TB1, TB2, …`, prefixed to avoid collision with asset IDs (`A1`). Record them as a table with columns: ID, Boundary, Direction of trust, Notes.

### Threat Actors (`TA#`)

Enumerate the distinct actors who could attack the system and the capability each holds — from anonymous internet callers to malicious content contributors, compromised origins/dependencies, config attackers, on-path network attackers, and insiders. An actor with no capability against any boundary cannot execute a threat that crosses it; making actors explicit keeps Likelihood ratings honest.

Use IDs `TA1, TA2, …`. Map each actor to the boundary/boundaries it operates against and the assets thereby reachable (e.g., `TB2 → A1, A4`).

### Wiring (required)

- Every threat (`T#`) names the boundary it crosses (`TB#`) and the actor(s) able to execute it (`TA#`).
- Every boundary and every actor is implicated by **at least one** threat. A boundary or actor no threat references is either decorative (cut it) or signals a missing threat (add it).
- These constraints are enforced in Cross-Reference Validation.

## Modeling Privacy: Intangible Assets and Privacy Threats

Privacy harms often have no attacker and don't fit the "an intruder does X" mold of a classic threat — so in practice LINDDUN findings get brainstormed and then stranded, never becoming part of the model. The fix is to widen the model's ontology rather than to bypass it: model privacy harms as **threats against intangible assets**, which keeps the asset → threat → countermeasure invariant intact and folds privacy into the ARI. (Do not invent a countermeasure with no threat to satisfy a privacy concern — give it a threat and an asset instead.)

- **Intangible assets** are real assets: *user trust / confidence in data handling*, *regulatory standing / license to operate*, *legal defensibility*, *brand reputation*. Give them IDs and value ratings like any other asset.
- **Privacy threats** are real threats against those assets: *regulatory enforcement or fines for unlawful processing* (e.g., GDPR Art. 6 lawful basis, Art. 5(1)(e) retention limits), *loss of user trust from an undisclosed or creepy data practice*, *civil liability / class action*. The "attacker" may be a regulator, a journalist, or the erosion of trust itself.

A LINDDUN item then resolves cleanly. For example, *"queries retained indefinitely with no lawful basis"* → asset **A_n (intangible): user trust & regulatory standing**, threat **T_n: regulatory enforcement for unlawful retention**, countermeasure **C_n: retention policy + lawful-basis documentation + deletion job**. The chain is whole, it contributes to the ARI, and it surfaces in the backlog.

**Three guardrails** keep this from degenerating into slop:

1. **No double-counting.** Where a privacy harm rides on a *technical* attack (a breach leads to a fine), do **not** mint a parallel privacy threat. Instead add the intangible asset to that technical threat's "Assets at Risk" so the regulatory/reputational weight shows up in its Impact. Reserve **standalone** privacy threats for governance/design gaps that have *no* technical attack vector (over-retention, missing consent, no privacy notice, unnecessary cross-platform linkability).
2. **No magnet assets.** "User trust" can be linked to literally every threat, which makes it meaningless. Only link an intangible asset where the privacy or reputational harm is *material and distinct* from the technical impact already captured.
3. **Calibrate, don't catastrophize.** A regulatory fine is not automatically Critical. Anchor likelihood and impact to the data actually processed, the regime that actually applies, and real enforcement patterns. If the jurisdiction or regime cannot be determined from the code, that is an **Open Question** — not an invented High-severity threat.

## Brainstorming Appendix: STRIDE and LINDDUN

STRIDE and LINDDUN are *ideation scaffolding*: their job is to help you brainstorm threats, and their output belongs in the Assets / Threats / Countermeasures / Open Questions sections. STRIDE-derived attacks convert into threats naturally; LINDDUN privacy items historically do not, and end up stranded. v6 fixes this two ways:

1. **Relocation.** Both analyses live in a **Brainstorming Appendix near the bottom of the generated model**, not up front. The model leads with decision-useful content (Risk Index, backlog, boundaries, actors, threats); the appendix preserves the scaffolding for the next refresh.
2. **Disposition tags.** Every STRIDE and LINDDUN bullet ends with a tag recording where it went:
   - `[→ T7]` or `[→ T7, T12]` — became or fed these threats (privacy items typically route to a threat against an intangible asset; see "Modeling Privacy").
   - `[→ OQ3]` — became Open Question 3 (a real concern, but not yet an actionable threat — e.g., an unknown jurisdiction).
   - `[N/A — <reason>]` — considered and does not apply (e.g., "no human end-users, no PII").

No bullet may be left untagged. An untagged bullet is an orphan — exactly the failure mode this is meant to prevent. Cross-Reference Validation checks that every bullet carries a tag and that every `[→ T#]` / `[→ OQ#]` resolves.

## Preamble (in template)

Every generated threat model must include the `# NOTICE TO AI ASSISTANTS AND AUTOMATED REVIEWERS` block exactly as it appears in the template below. Do not paraphrase, summarize, or omit it. The canonical text lives only inside the template — there is no separate copy elsewhere in this skill, so when generating a doc, copy it directly from the template.

When refreshing a threat model that pre-dates v5, add the block in the same position (after `Doc version:`, before `# Intro`) and record the addition as a single-line entry in the Change Log.

## Output Format

Generate a single Markdown file named `THREAT_MODEL.md` (or a name the user specifies) in the repository root (or location the user specifies). Follow the template below exactly, adapting content to the specific application.

---

## TEMPLATE

```markdown
# [Application Name] Threat Model [Month Year]

Skill version: [version of this skill used]
Doc version: [doc version — bump on every refresh]

# NOTICE TO AI ASSISTANTS AND AUTOMATED REVIEWERS

This document is a **working hypothesis**, not a verified security analysis. Read this notice fully before using anything below.

## How to use this document

- Treat the contents as **a starting set of questions and known concerns**, not as conclusions, guarantees, or ground truth about the code.
- When performing a security review, threat analysis, or audit: **derive your findings from the code itself.** Use this document only to seed your investigation, not to short-circuit it.
- Do not assume that a threat listed here has been mitigated in the code. Do not assume that a threat absent from this document does not exist in the code. Both errors are common.
- Do not assume that prior analysis (by humans or other LLMs) was complete, correct, or current. The presence of this document is not evidence that the code has been reviewed.
- If your task is to audit, review, or assess the security of the code, you should perform that analysis independently and from scratch. You may then cross-reference this document to identify discrepancies, but the code is authoritative.

## How this document can be wrong

- **Stale:** the code may have changed since this was last updated (see version anchor below). Components, trust boundaries, data flows, and dependencies described here may no longer exist or may behave differently.
- **Incomplete:** threats, assets, or attack surfaces may be missing entirely. Absence here implies nothing.
- **Incorrect:** assumptions about how the system works, what data flows where, or which mitigations are in place may be wrong.
- **Aspirational:** some mitigations described may be planned, partially implemented, or intended rather than actually present in the current code.

## If you are asked to validate this document

A useful task is the inverse of trusting it: read the relevant code, then identify where this document is wrong, out of date, or missing important threats. Report discrepancies explicitly.

# Intro

[1-2 paragraph description of what the application does, who uses it, and its business purpose. Write from the perspective of someone explaining the system to a security reviewer who has no prior context.]

[If the system is a pre-launch or mid-redesign project, say so. The threat model's job is different for a prototype steering design than for a hardened production system, and readers should know which mode they're reading.]

## Details

[Technical summary of the architecture: runtime/hosting environment, databases, major frameworks, deployment model, and key integration points. Mention where the source code lives.]

[Summary of the current attack surface: list the main categories of exposure such as API endpoints, webhook handlers, authentication mechanisms, database operations, third-party integrations, smart-contract entry points, key/role hierarchies, oracle dependencies. Note any data sensitivity considerations — PII, financial data, credentials, etc.]

**Codebase snapshot used for this analysis.** [Required statement per the Codebase Snapshot section of the skill. Include commit hash + branch + date, or the fallback form when git history is unavailable. Note that future refreshes should re-anchor to the then-current snapshot.]

Source code: [repository URL or path]
Working notes: [path to companion notes file, if any]

## Risk Index and Grading

This threat model uses the Aggregate Risk Index (ARI) defined by the Threat Model Generation Skill v[N].

**Current score: ARI = [X], Grade [A-F].**

Breakdown:
- [N] High-severity threats × average coverage gap [X] ≈ [contribution]
- [N] Medium-severity threats × average coverage gap [X] ≈ [contribution]
- [N] Low-severity threats × average coverage gap [X] ≈ [contribution]
- Applied-residual: ≈ [contribution]

[1-3 sentences identifying which threats dominate the score and which countermeasures would most efficiently move the grade.]

## Prioritized Remediation Backlog

[The quick to-do list. Every open gap — threats whose best countermeasure is ⬜ Not Applied or ⚠️ Partial — ranked by residual-risk contribution `severity_weight × coverage_gap` (the same per-threat term that feeds the ARI), highest first. Fully-mitigated (✅) threats are omitted unless the long tail is requested.]

| **Rank** | **Fix (Countermeasure)** | **Closes** | **Max Severity** | **Status** | **Residual Contribution** | **Effort** |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | (C#) [Countermeasure] | • (T#) [Threat] | High | ⬜ Not Applied | 5.0 | [S / M / L] |
| 2 | (C#) [Countermeasure] | • (T#) [Threat]<br>• (T#) [Threat] | High | ⚠️ Partial | 2.5 | [S / M / L] |
| ... | ... | ... | ... | ... | ... | ... |

[1-2 sentences calling out the quick wins (high contribution, low effort) and the single highest-leverage fix.]

## UI

[If the application has a user interface, describe how different user roles interact with it. Include descriptions of key workflows. If no UI exists (e.g., a backend service), describe the primary interfaces (API consumers, CLI users, etc.).]

## Trust Boundaries

[Enumerate where trust changes hands. The boundary that converts attacker-influenceable data into action (or into instruction-grade context for an agent/LLM) is usually the most important. Every boundary must be crossed by at least one threat below.]

| **ID** | **Boundary** | **Direction of Trust** | **Notes** |
| --- | --- | --- | --- |
| TB1 | [Zone A ↔ Zone B] | [What each side trusts the other to provide] | [Why it matters; what is or isn't enforced at the crossing] |
| TB2 | ... | ... | ... |

## Threat Actors

[Enumerate who could attack the system and the capability each holds. An actor with no capability against any boundary should not appear. Every actor must drive at least one threat below.]

| **ID** | **Actor** | **Capability** | **Primary Boundary → Assets** |
| --- | --- | --- | --- |
| TA1 | [Actor] | [What they can do] | [TB# → A#, A#] |
| TA2 | ... | ... | ... |

## Proposed Changes and Redesigns

[If the user has mentioned upcoming changes or open redesigns, list them here. For each redesign, describe:
- What is changing
- Which assets, threats, or countermeasures it affects
- The projected ARI delta if the redesign is adopted (current ARI vs. post-redesign projected ARI)

This section is how the threat model steers design decisions. When multiple redesigns are under consideration, presenting their projected ARI deltas lets the team see the security trade-offs side by side.

If no proposed changes are known, write "No proposed changes are currently under consideration."]

# Assets

[Introductory sentence explaining the rating methodology. Reference the Calibration Anchors from the skill. Include intangible assets — user trust in data handling, regulatory standing — where privacy or reputational harm is in scope; see "Modeling Privacy".]

| **Identifier** | **Title** | **Value** |
| --- | --- | --- |
| A1 | [Asset Name] | [Low / Medium / High / Critical] |
| A2 | [Asset Name] | [Value] |
| A3 | [Intangible — e.g., User Trust & Regulatory Standing] | [Value] |
| ... | ... | ... |

## (A1) [Asset Title]

[2-4 sentences describing what this asset is, why an attacker would target it, and any special considerations (e.g., data sensitivity, blast radius of compromise). End with the value rating and a one-sentence justification. Intangible assets follow the same format — describe the harm their loss causes.]

As [justification], the value is rated **[Value]**.

[Repeat for each asset.]

# Threats

[Introductory text explaining the methodology. Every threat names the trust boundary it crosses (TB#) and the actor(s) capable of executing it (TA#).]

Severity matrix:
- Low × Low = Low
- Low × Medium = Medium
- Medium × Medium = Medium
- Medium × High = Medium or High (use judgment)
- High × High = High

| **ID** | **Description** | **Boundary · Actor(s)** | **Assets at Risk** | **Likelihood** | **Impact** | **Severity** |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | [Threat description] | TB1 · TA1 | • (A1) [Name] | [Low/Med/High] | [Low/Med/High] | [Low/Med/High] |
| T2 | [Threat description] | TB2 · TA1, TA3 | • (A2) [Name]<br>• (A3) [Name] | [L/M/H] | [L/M/H] | [L/M/H] |
| ... | ... | ... | ... | ... | ... | ... |

## (T1) [Threat Title]

[2-4 sentences explaining the attack vector, how it would be carried out against THIS specific application, and what the attacker gains. Reference specific code patterns, endpoints, or configurations you observed. If this threat is introduced by proposed changes, mark it with "(New)".]

Crosses: (TB1) [Boundary name]
Actor(s): (TA1) [Actor name]

Assets Impacted:
- (A1) [Asset Name]
- [...]

[Repeat for each threat.]

# Countermeasures

[The countermeasures section begins with a status table showing which countermeasures have been implemented in the current codebase and which remain outstanding. To populate this table, examine the codebase for evidence of each countermeasure — look for relevant code patterns, library usage, configuration settings, and infrastructure-as-code definitions. Mark a countermeasure as applied only if you find concrete evidence in the code; if uncertain, mark it as not applied.]

| **ID** | **Title** | **Threats Mitigated** | **Status** |
| --- | --- | --- | --- |
| C1 | [Countermeasure Name] | • (T1) [Threat Name] | ✅ Applied |
| C2 | [Countermeasure Name] | • (T1) [Threat Name]<br>• (T3) [Threat Name] | ⬜ Not Applied |
| C3 | [Countermeasure Name] | • (T2) [Threat Name] | ⚠️ Partial |
| ... | ... | ... | ... |

Status values:
- **✅ Applied**: Evidence found in the codebase. Cite the relevant file(s) or configuration in the subsection.
- **⬜ Not Applied**: No evidence found. The subsection should include implementation guidance.
- **⚠️ Partial**: Some aspects are implemented but gaps remain. The subsection should describe what's in place and what's missing.

## (C1) [Countermeasure Title]

**Status**: [✅ Applied / ⬜ Not Applied / ⚠️ Partial]

[If Applied: 1-2 sentences citing where in the codebase this is implemented.]

[If Not Applied or Partial: 2-5 sentences describing what should be done, why it mitigates the listed threats, and implementation guidance specific to this codebase. Be concrete and actionable.]

[If Partial: Additionally describe what IS in place and what gaps remain.]

Threats Mitigated:
- (T1) [Threat Name]
- [...]

Reference:
- [Optional external URL]

[Repeat for each countermeasure.]

# Appendix: STRIDE and LINDDUN Brainstorming

These analyses are brainstorming scaffolding, not the deliverable. Their actionable output lives above in Assets, Threats, Countermeasures, and Open Questions. Every bullet below carries a disposition tag — `[→ T#]`, `[→ OQ#]`, or `[N/A — reason]` — recording where it landed. No bullet is left untagged.

## Top-Level STRIDE Analysis

[Provide a concise STRIDE breakdown. For each category, list the 2-4 most significant attack scenarios specific to THIS application. Do not include generic boilerplate — every bullet must be grounded in something you observed in the code or architecture, and every bullet must end with a disposition tag.]

- **Spoofing**
    - [Attack scenario grounded in actual code/architecture] `[→ T#]`
    - [...]
- **Tampering**
    - [...] `[→ T#]`
- **Repudiation**
    - [If no significant repudiation threats exist, write "N/A — [brief justification]"] `[N/A — ...]`
    - [...]
- **Information Disclosure**
    - [...] `[→ T#]`
- **Denial of Service**
    - [...] `[→ T#]`
- **Elevation of Privilege**
    - [...] `[→ T#]`

## Top-Level LINDDUN Analysis

LINDDUN is a privacy-focused threat modeling framework that complements STRIDE's security focus. While STRIDE addresses what an attacker can do to the system, LINDDUN addresses what the system (or its operators, integrations, and data flows) can do to the privacy of individuals whose data it processes.

[Provide a concise LINDDUN breakdown. For each category, list the 1-3 most significant privacy threat scenarios specific to THIS application. If a category does not apply, write "N/A — [brief justification]". Every bullet must be grounded in actual data flows, storage patterns, or integrations you observed in the code, and every bullet must end with a disposition tag. Actionable items typically route to a threat against an intangible asset (see "Modeling Privacy"); governance questions with no code-derivable answer route to an Open Question.]

- **Linkability**
    - [...] `[→ T#]`
- **Identifiability**
    - [...] `[→ T#]`
- **Non-repudiation (Privacy Context)**
    - [...] `[→ T#]`
- **Detectability**
    - [...] `[→ T#]`
- **Disclosure of Information (Privacy Context)**
    - [...] `[→ T#]`
- **Unawareness**
    - [...] `[→ OQ#]`
- **Non-compliance**
    - [...] `[→ T#]`

# Maintenance Guidance for Future Agents

This document is intended to be refreshed iteratively rather than rewritten. Before substantive edits, follow these conventions:

1. **Re-anchor to a code commit.** Update the Codebase Snapshot in the intro to the then-current commit hash and record the date of the refresh.
2. **Re-compute the ARI** and report the delta vs. the previous version in the Change Log.
3. **Re-rank the Prioritized Remediation Backlog** from the updated per-threat ARI contributions, so the to-do list stays consistent with the grade.
4. **Re-check Trust Boundaries and Threat Actors.** New integrations or entry points usually add a boundary or an actor; ensure each remains wired to ≥1 threat, and each threat still cites its boundary and actor.
5. **Re-tag the Brainstorming Appendix.** Every STRIDE/LINDDUN bullet must still carry a resolving disposition tag.
6. **Add `(New — Month Year)` markers** to every new asset, threat, and countermeasure per the incremental update workflow. Strike through retired entries; never delete.
7. **Cross-check redesign impact.** When the user mentions a redesign, evaluate which threats it changes status on and which it introduces, and update the ARI accordingly. Present projected ARI alongside current ARI in the Proposed Changes and Redesigns section.
8. **Validate cross-references** before delivering (see Cross-Reference Validation in the skill).
9. **Bump the doc version** in the header on every substantive edit. Skill version is separate from doc version.

# Open Questions for the Team

[Unresolved questions whose answers will materially affect this threat model. These should be questions the threat-modeling agent could not answer from the code alone — typically about future intent, operational policy, or contractual commitments. Reproduce them here so follow-up reviews have a focused list. LINDDUN bullets tagged `[→ OQ#]` land here.]

1. [Question 1]
2. [Question 2]
3. ...

# Change Log

| **Date** | **Author / Trigger** | **ARI Δ** | **Summary of Changes** |
| --- | --- | --- | --- |
| [Month Year] | [What prompted the update] | [ARI before → after] | Added A10, A11. Added T7, T8. Updated T3 severity from Medium to High. Added C14, C15. Retired T2. |
| [Previous date] | [Previous trigger] | [Previous delta] | [Previous summary] |

# Model and Methodology

- Skill: Threat Model Generation Skill v[N]
- Model used: [actual model that produced this analysis, e.g., claude-opus-4-8]
- Model degradation: [None — ran on the intended top choice. | Intended [model] but ran on [model] because [reason, e.g., "Fable 5 degraded to Opus 4.8 on cyber content"].]
- Generated / refreshed: [Month Year]
- Initial issuance: [Month Year]
```

---

## Analysis Guidelines

When filling in the template, follow these principles.

### Assets

- The number of assets should scale with the complexity of the application. A simple single-purpose service might have 5–10 assets; a complex multi-service system with many integrations could have up to 50. Identify as many distinct assets as the system warrants — do not artificially constrain or inflate the count.
- **Every asset must be referenced by at least one threat.** If you identify an asset but cannot articulate a credible threat against it, reconsider whether it belongs in the model.
- Always consider: user data / PII, database contents, source code, authentication credentials / API keys, signing keys, on-chain admin authorities, service identity and trust relationships, availability of critical workflows, third-party integration access, and any domain-specific sensitive data (financial records, health data, user funds, etc.).
- Include **intangible assets** — user trust in data handling, regulatory standing, brand reputation — where privacy or reputational harm is in scope. Model them like any other asset (ID, value, ≥1 threat). See "Modeling Privacy: Intangible Assets and Privacy Threats."
- Rate values honestly. Not everything is High. A well-calibrated model has a mix of Low, Medium, High, and (rarely) Critical ratings with clear justifications.

#### Calibration Anchors for Value Ratings

Use these as anchors when rating an asset. Adapt them to the specific system, but resist drift in either direction.

- **Critical** — compromise of this asset enables irrecoverable, large-scale loss (e.g., draining user funds at the protocol level, full system takeover via key compromise, complete database exfiltration of regulated data). Reserve Critical for assets whose loss would be a top-of-fold news event.
- **High** — compromise causes serious but recoverable harm (e.g., compromise of one tenant's data, theft of a hot key bounded by per-day rate limits, breach of a single service whose blast radius is contained). The kind of incident that requires an executive-level postmortem.
- **Medium** — compromise causes meaningful harm that the system can absorb (e.g., DoS of a single API surface, exposure of low-sensitivity metadata, defacement of a non-critical page). Triggers a standard incident response.
- **Low** — compromise is a nuisance or quality issue rather than a security incident (e.g., stale cached read, missing UI element, minor information leak with no individual harm). Often these assets shouldn't be in the model at all.

Examples of assets include: database records, source code, non-financial PII (email, DOB), financial PII (identifying information combined with bank-account or crypto-address data), session tokens, signing keys (EIP-712 oracle keys, JWT secrets), upgrade authority over upgradable contracts, hot-key budgets, user funds, site availability, encryption keys, DNS infrastructure, indexer/event-pipeline integrity, oracle freshness.

**Rating intangible assets.** Intangible assets are rated the same way — by the harm their loss causes. A privacy enforcement action that forces a product change, or a publicized creepy-data-practice that drives measurable churn, is typically **High**; routine reputational friction is **Medium**. Resist auto-rating "regulatory fine" as Critical: anchor to the data actually processed and the regime that actually applies (see guardrail 3 in "Modeling Privacy").

### Trust Boundaries

- Enumerate boundaries from the data and control flows you traced in Prerequisites, not from a generic list. The useful question is: *at this crossing, what does each side trust the other to provide, and what happens if that trust is misplaced?*
- Single out the boundary that turns attacker-influenceable input into action or into instruction-grade context — it is almost always where the most severe threats concentrate.
- Keep the set small and real. Five well-chosen boundaries beat fifteen nominal ones. Each must be crossed by ≥1 threat.

### Threat Actors

- Derive actors from the boundaries: for each boundary, who sits on the untrusted side, and what can they do? That yields the actor list without inventing movie-villain personas.
- State capability concretely (e.g., "can land a PR into `src/data/content/**`", "controls the origin serving the base URL", "can edit `mcp.json` in a shared devcontainer"), not vaguely ("a hacker").
- An actor with no capability against any boundary does not belong in the model. Each actor must drive ≥1 threat, and its capability should justify the Likelihood of the threats it drives.

### Threats

- **Every threat must have at least one countermeasure.** If you identify a threat with no feasible countermeasure, note it explicitly as an accepted risk and explain why.
- **Every asset must be targeted by at least one threat.** If an asset has no threat, either the asset is not worth listing or you have not considered all attack vectors.
- **Cite the boundary and actor.** Every threat names the trust boundary it crosses (`TB#`) and the actor(s) capable of executing it (`TA#`). A threat no enumerated actor can execute is not a threat — drop it or add the actor.
- Each threat must be specific to the application — generic threats like "an attacker could hack the server" are not acceptable.
- Ground every threat in something concrete: a code pattern, an architectural choice, a dependency, a configuration, or a data flow you actually observed.
- Likelihood should consider: Is the attack surface internet-facing? Is the data valuable? Are there known exploit patterns for the technologies used? Would an attacker be motivated to target this specifically? Does a capable actor (per the Threat Actors table) actually exist?
- Mark threats introduced by proposed changes with **(New)**.
- **Model privacy harms as threats against intangible assets**, observing the three guardrails in "Modeling Privacy." This is the destination for most actionable LINDDUN items; every LINDDUN bullet must resolve to a threat, an Open Question, or N/A via its disposition tag.

### Countermeasures

- **Every threat must have at least one countermeasure.** Most countermeasures mitigate multiple threats.
- Be specific and actionable. Reference actual files, functions, libraries, or configurations in the codebase.
- Include both preventive (stop the attack) and detective (notice the attack) countermeasures where appropriate.
- Suggest specific tools or libraries where relevant (e.g., `socket.dev` for dependency scanning, `helmet` for Express headers, OpenZeppelin `TimelockController` for on-chain admin throttling).
- For privacy threats, countermeasures are often procedural or documentary (a retention policy, a lawful-basis record, a DPIA, a privacy notice, a deletion job) as much as technical. They are tracked and scored exactly like technical countermeasures and appear in the backlog.
- **Verify implementation status.** For each countermeasure, search the codebase for evidence that it has been applied. This is one of the most valuable outputs of the threat model — a clear picture of what's protected and what's exposed.

### LINDDUN Analysis

- LINDDUN is informed by the same codebase exploration as STRIDE, with a privacy lens: where personal data enters, where it's stored, who can access it, where it's sent externally, and how long it's retained.
- LINDDUN lives in the Brainstorming Appendix, and **every bullet must carry a disposition tag** (`[→ T#]`, `[→ OQ#]`, `[N/A — reason]`). The tag exists to force conversion — a LINDDUN finding that informs nothing in the model is an orphan, which is the exact failure this skill is designed to prevent.
- Most actionable LINDDUN items resolve to a **threat against an intangible asset** (see "Modeling Privacy"); governance questions with no answer derivable from the code resolve to **Open Questions**; inapplicable categories are marked **N/A** with a brief justification.
- The two frameworks are complementary, not siloed — a privacy threat may also cross a STRIDE-relevant boundary, and a single finding can be reached from both lenses.

### Domain Considerations

Adapt the threat model to the domain of the system being analyzed. Consult the relevant checklist below in addition to the general STRIDE/LINDDUN flow.

**Web applications:**
- Auth/session model (cookies, JWT, OAuth, refresh tokens, key rotation)
- CSRF, XSS, CORS, security headers (CSP, HSTS, X-Frame-Options)
- Rate limiting and abuse controls
- SSRF in webhook handlers and image fetchers
- DoS amplification via expensive endpoints (SSE, search, full-text queries)
- Dependency supply chain
- Secret management in deployment platform (Vercel, Railway, Render, AWS Secrets Manager, etc.)

**Smart contracts and on-chain systems:**
- Upgrade authority (UUPS, transparent proxy, beacon) — who can call `_authorizeUpgrade`?
- Role hierarchy — `DEFAULT_ADMIN_ROLE` and any custom roles, their grant/revoke paths, and whether timelocks gate sensitive operations
- Oracle dependencies — price feeds, attestations, EIP-712 signers; freshness assumptions; manipulation cost
- MEV exposure — front-running, sandwich attacks, time-bandit / reorg sensitivity
- Flash-loan attacks against pricing or governance
- Bonding-curve / AMM math — rounding direction, overflow paths, reentrancy on token callbacks
- Custody flows — where is user money held; what's the exit path; can it be diverted?
- Pause/emergency-stop chain and whether it has a single point of failure
- Hot signer keys (faucet, oracle, attestation) and their rotation procedures
- Deploy-time race conditions (deployer keys with admin authority before rotation)
- Indexer/event-pipeline integrity (Goldsky/The Graph/Subsquid) — whose credentials write the database?
- Sniping at market opening (first-block extraction)
- Reorg / non-finality handling in workers

**AI / ML systems:**
- Prompt injection (direct, indirect via retrieved context, via tool outputs)
- Data leakage through model outputs (training-data extraction, system-prompt extraction)
- Third-party model provider data handling (OpenAI, Anthropic, OpenRouter retention policies)
- Tool-use authorization — which user can invoke which tools with which arguments
- Hallucination as a security risk (e.g., a hallucinated API endpoint becomes a phishing vector)

**Regulated data (HIPAA, GDPR, PCI, etc.):**
- Lawful basis for processing
- Data minimization and retention
- Cross-border transfer
- Subject access / erasure / portability rights
- Breach notification readiness
- Sub-processor inventory and DPAs

**Money custody (whether on-chain or off):**
- Hot/cold key separation
- Multisig / threshold-signature requirements
- Withdrawal limits and velocity controls
- Recovery procedures for lost keys
- Insurance and reserve transparency

### General Quality Standards

- **No generic filler.** Every sentence should convey information specific to the application being analyzed.
- **Cross-reference consistently.** Asset IDs (A1, A2...), Trust Boundary IDs (TB1, TB2...), Threat Actor IDs (TA1, TA2...), Threat IDs (T1, T2...), and Countermeasure IDs (C1, C2...) must be used consistently across all tables and subsections. Every STRIDE/LINDDUN bullet carries a disposition tag.
- **Justify ratings.** Every Low/Medium/High/Critical rating needs a brief rationale grounded in the actual system.
- **Acknowledge uncertainty.** If you cannot determine something from the code alone (e.g., network configuration, cloud IAM policies), say so explicitly rather than guessing.
- **Consider proposed changes.** If the user mentions planned features or you see feature branches, analyze how they change the threat landscape. Mark new assets, threats, and countermeasures with **(New)** and project the post-redesign ARI in the Proposed Changes section.
- **Ensure complete coverage.** Run the cross-reference validation as a final step.

### Cross-Reference Validation

Before delivering or refreshing a threat model, walk through this checklist:

1. Walk every asset A1..An and confirm it appears in ≥1 threat's "Assets at Risk" list.
2. Walk every threat T1..Tn and confirm it has ≥1 mitigating countermeasure listed.
3. Walk every countermeasure C1..Cn and confirm it lists ≥1 mitigated threat.
4. Confirm no orphaned IDs exist (referenced in tables but missing subsections, or vice versa).
5. Confirm all `(New — [Month Year])` and `(Retired — [Month Year])` markers include the date.
6. Confirm the countermeasure status table is accurate against the current codebase.
7. Confirm the ARI score in the intro matches what the threat/countermeasure tables imply.
8. Confirm the Codebase Snapshot in the intro reflects the actual code analyzed.
9. Walk every trust boundary TB1..TBn and confirm ≥1 threat crosses it; walk every actor TA1..TAn and confirm ≥1 threat names it.
10. Confirm every threat subsection cites a boundary (TB#) and at least one actor (TA#).
11. Confirm every STRIDE and LINDDUN bullet carries a disposition tag, and every `[→ T#]` / `[→ OQ#]` resolves to a real entry.
12. Confirm every intangible asset is targeted by ≥1 threat — privacy assets are not exempt from the asset → threat rule.
13. Confirm the Prioritized Remediation Backlog lists every open (⬜/⚠️) gap, is sorted by residual contribution, and its ordering matches the ARI per-threat contributions.

Skipping this validation produces broken models that lose credibility on the first careful read.

---

## Incremental Update Workflow

When updating an existing threat model (e.g., after new features are merged, architecture changes, or periodic review), follow this workflow instead of regenerating from scratch.

### When to Use Incremental Updates

Use this workflow when:
- The user says something like "update the threat model," "re-run for the new auth service," "we merged the PR, update the threats," or "add [feature] to the threat model"
- An existing `THREAT_MODEL.md` (or equivalent) already exists in the repo
- The changes are scoped — not a full rewrite of the application

If the application has changed so fundamentally that >50% of the assets or threats would need rewriting, generate a fresh threat model instead and note that it supersedes the previous version.

### Step 1: Diff Analysis

Before modifying anything, understand what changed:

1. **Read the existing threat model** in full, including the recorded Codebase Snapshot and prior ARI.
2. **Identify what changed in the codebase** since the model was written:
   - Git history: `git log --since="[date of last threat model]" --oneline` or diff against the recorded snapshot hash
   - User description of changes
   - New / deleted / modified files (handlers, contracts, jobs)
   - Changes to dependency manifests
   - Changes to environment variables, secrets configuration, or deployment configs
3. **Categorize the changes**:
   - **New attack surface** (including any new trust boundary or threat actor introduced)
   - **Removed attack surface**
   - **Modified attack surface**

### Step 2: Update Assets

- **New assets**: Next available identifier. Mark with **(New — [Month Year])**. Add or re-value intangible assets as privacy/reputational scope changes.
- **Removed assets**: Do NOT delete. Strike through and note `**Retired [Month Year]**: [reason]`.
- **Modified assets**: Update description and re-evaluate value. If rating changes, note: `Value changed from **Medium** to **High** ([Month Year]): [reason].`

### Step 3: Update Threats

- **New threats**: Next available ID. Mark with **(New — [Month Year])**. Ensure ≥1 asset, ≥1 countermeasure, and a cited boundary (TB#) and actor (TA#).
- **Retired threats**: Strike through; note retirement reason.
- **Modified threats**: Update description, re-evaluate Likelihood/Impact/Severity, and re-confirm the boundary/actor citation. Note severity changes.
- **Re-evaluate existing threats**: Even threats not directly affected may shift.

### Step 4: Update Countermeasures

- **New countermeasures**: Next available ID. Link to threats they mitigate.
- **Retired countermeasures**: Strike through; note reason.
- **Modified countermeasures**: Update implementation guidance.
- **Re-evaluate status**: Check whether previously unapplied countermeasures have been implemented, or whether applied countermeasures have been removed.

### Step 5: Update Trust Boundaries and Threat Actors

- Add boundaries/actors introduced by new integrations or entry points; retire those removed (strikethrough, dated).
- Confirm every boundary is still crossed by ≥1 threat and every actor still drives ≥1 threat.

### Step 6: Update STRIDE and LINDDUN Summaries

Re-examine both analyses in the Brainstorming Appendix. Add new scenarios, retire stale ones (strikethrough), re-tag every bullet with its disposition (`[→ T#]` / `[→ OQ#]` / `[N/A — reason]`), and ensure every bullet still reflects current state.

### Step 7: Update Codebase Snapshot, Re-compute ARI, Re-rank Backlog

- Update the Codebase Snapshot in the intro to the current commit/date.
- Re-compute ARI from the updated tables.
- Re-rank the Prioritized Remediation Backlog from the updated per-threat contributions.
- Note the ARI delta (old → new) in the Change Log.

### Step 8: Add a Change Log Entry

Append to the `# Change Log` table at the bottom:

```markdown
| [Month Year] | [What prompted the update, e.g., "AI features merged (PR #142)"] | [old ARI] → [new ARI] | Added A10, A11. Added T7, T8. Updated T3 severity from Medium to High. Added C14, C15. Retired T2. |
```

### Step 9: Validate Cross-References

Run the Cross-Reference Validation checklist (above).

### Example: Incremental Update Annotation Style

When updating an existing asset subsection:

```markdown
## (A5) Slack Channel Contents

The bot reads channels like `#my-slack-channel` to generate AI summaries and posts them
to `#my-other-slack-channel`.

**Updated Oct 2025**: The bot now also reads `#some-other-channel` for post-mortem
summaries. This channel contains more sensitive operational detail than the previously
scraped channels. Value changed from **Low** to **Medium** (Oct 2025): incident
response discussions may include infrastructure credentials and vendor contact details.
```

When retiring a threat:

```markdown
## (T2) ~~AI Prompt Injection~~

**Retired Nov 2025**: AI features were removed in v2.4 after cost-benefit review.
The OpenRouter integration and all AI summarization code have been deleted. This
threat no longer applies.
```

---

## Final Notes

A threat model is not a security audit, a penetration test, or a checklist of vulnerabilities. It is a structured account of where the value is, what could go wrong, what's protecting it, and what isn't. Its purpose is to make security trade-offs visible so the team can make informed decisions.

When in doubt, prefer:
- Fewer, more credible threats over many speculative ones
- Specific code references over abstract concerns
- Honest acknowledgment of uncertainty over confident-sounding guesses
- Comparable metrics across refreshes (ARI) over one-shot heroics

If the user is making design decisions, the threat model is the document that should be on their other monitor.
