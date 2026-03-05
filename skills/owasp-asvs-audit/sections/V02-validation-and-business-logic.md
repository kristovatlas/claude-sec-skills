# V2: Validation and Business Logic

**ASVS Version:** 5.0.0
**ASVS Source:** `0x11-V2-Validation-Business-Logic.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

This chapter aims to ensure that a verified application meets the following high-level goals:

* Input received by the application matches business or functional expectations.
* The business logic flow is sequential, processed in order, and cannot be bypassed.
* Business logic includes limits and controls to detect and prevent automated attacks, such as continuous small funds transfers or adding a million friends one at a time.
* High-value business logic flows have considered abuse cases and malicious actors, and have protections against spoofing, tampering, information disclosure, and elevation of privilege attacks.

---

## V2.1: Validation and Business Logic Documentation

Validation and business logic documentation should clearly define business logic limits, validation rules, and contextual consistency of combined data items, so it is clear what needs to be implemented in the application.

| # | Requirement | Level |
|---|-------------|-------|
| **2.1.1** | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | 1 |
| **2.1.2** | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | 2 |
| **2.1.3** | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | 2 |

### Audit Guidance for V2.1

**General approach:** These are documentation requirements. The sub-agent should look for evidence of documented validation rules and business logic constraints in:
- README files, architecture docs, ADRs (Architecture Decision Records)
- API documentation (OpenAPI/Swagger specs, GraphQL schemas with descriptions)
- Inline code comments or docstrings describing validation expectations
- Configuration files that define validation rules (e.g., JSON Schema files, validation rule configs)
- Wiki or docs directories in the repo

**2.1.1 — Documented input validation rules:**

What to look for:
- API specs (OpenAPI/Swagger) with defined parameter formats, patterns, min/max, enums. This counts as documentation of validation rules.
- JSON Schema files used for request validation.
- Validation rule definitions in framework-specific formats (e.g., Laravel form request rules, Django form/serializer validators, Joi schemas, Zod schemas, class-validator decorators).
- Documentation describing expected formats for key data types (email, phone, credit card, dates, identifiers).
- If validation is implemented in code but not documented anywhere, this is a partial finding — the validation exists but the documentation requirement is not met.

**2.1.2 — Cross-field/contextual consistency documentation:**

What to look for:
- Documentation or code that describes validation of related fields together (e.g., start date before end date, ZIP code matching state/region, currency matching country, shipping address consistency).
- Custom validators that check multi-field constraints.
- This is commonly absent even in well-validated applications. Mark MANUAL_REVIEW if no documentation is found but cross-field validation may exist in code that requires business context to evaluate.

**2.1.3 — Documented business logic limits:**

What to look for:
- Documentation of rate limits, transaction limits, quantity limits, account creation limits.
- Configuration files or environment variables defining these limits.
- Comments or docs describing per-user vs. global thresholds (e.g., max transfers per day, max items per order, max API calls per hour).

---

## V2.2: Input Validation

Effective input validation controls enforce business or functional expectations around the type of data the application expects to receive. This ensures good data quality and reduces the attack surface. However, it does not remove or replace the need to use correct encoding, parameterization, or sanitization when using the data in another component or for presenting it for output.

In this context, "input" could come from a wide variety of sources, including HTML form fields, REST requests, URL parameters, HTTP header fields, cookies, files on disk, databases, and external APIs.

A business logic control might check that a particular input is a number less than 100. A functional expectation might check that a number is below a certain threshold, as that number controls how many times a particular loop will take place, and a high number could lead to excessive processing and a potential denial of service condition.

While schema validation is not explicitly mandated, it may be the most effective mechanism for full validation coverage of HTTP APIs or other interfaces that use JSON or XML.

Please note the following points on Schema Validation:

* The "published version" of the JSON Schema validation specification is considered production-ready, but not strictly speaking "stable." When using JSON Schema validation, ensure there are no gaps with the guidance in the requirements below.
* Any JSON Schema validation libraries in use should also be monitored and updated if necessary once the standard is formalized.
* DTD validation should not be used, and framework DTD evaluation should be disabled, to avoid issues with XXE attacks against DTDs.

| # | Requirement | Level |
|---|-------------|-------|
| **2.2.1** | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | 1 |
| **2.2.2** | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | 1 |
| **2.2.3** | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | 2 |

### Audit Guidance for V2.2

**2.2.1 — Positive input validation (allowlist-based):**

What to look for:
- **Good patterns:** Validation libraries/frameworks being used consistently — Joi, Zod, Yup (Node.js); Django forms/serializers, Pydantic, marshmallow, Cerberus (Python); Bean Validation / Hibernate Validator annotations (Java); Laravel form requests (PHP); ActiveModel validations (Rails); FluentValidation, DataAnnotations (C#).
- **Good patterns:** JSON Schema or OpenAPI schema validation on API inputs. GraphQL type system providing structural validation.
- **Denylist approaches (weaker):** Regex patterns checking for dangerous characters instead of validating expected format. Stripping known-bad input rather than accepting only known-good.
- **Missing validation:** Controller/handler methods that read request parameters and use them directly without any validation step.
- **L1 scope:** At Level 1, focus on inputs used in security-relevant decisions — authentication parameters, authorization identifiers, payment amounts, resource identifiers. At L2+, all input should be validated.

Language-specific patterns to check:
- **Express/Node.js:** Are `req.body`, `req.params`, `req.query` values used without validation middleware? Check for `express-validator`, `celebrate`/`joi`, `zod` middleware.
- **Django:** Are `request.POST`, `request.GET`, `request.data` accessed directly in views, or do they go through Forms/Serializers?
- **Rails:** Are `params` used directly, or through `strong_parameters` combined with model validations?
- **Spring:** Are `@RequestBody` objects annotated with `@Valid` and have Bean Validation constraints?
- **Flask:** Are `request.args`, `request.form`, `request.json` validated through marshmallow/Pydantic schemas or used raw?
- **Laravel:** Are requests validated through Form Requests or `$request->validate()`, or are `$request->input()` values used directly?

**2.2.2 — Server-side validation enforcement:**

What to look for:
- Validation logic that exists *only* in client-side JavaScript with no corresponding server-side check. This is a FAIL.
- Common pattern: frontend form validation (HTML5 attributes, JavaScript) that is *duplicated* on the server — this is the correct approach (PASS).
- **Red flags:** Business rules (price calculations, discount logic, access decisions) computed or enforced only in frontend code. API endpoints that accept and process data without server-side validation, trusting the client.
- Check whether API routes can be called directly (e.g., via curl) bypassing any client-side validation.

**2.2.3 — Cross-field / contextual consistency validation:**

What to look for:
- Validation that checks related fields together: date ranges (start < end), address consistency (ZIP/city/state), matching passwords, quantity × price calculations, enum dependencies (if type=A then fieldB is required).
- Custom validators or validation methods that operate on the full object/form rather than individual fields.
- This is often implemented in model-level validation or form-level `clean()` methods (Django), custom `@AssertTrue` validators (Java), or custom Joi/Zod `.refine()` calls (Node.js).
- Mark with moderate confidence — determining whether all *appropriate* cross-field validations exist requires business context.

---

## V2.3: Business Logic Security

This section considers key requirements to ensure that the application enforces business logic processes in the correct way and is not vulnerable to attacks that exploit the logic and flow of the application.

| # | Requirement | Level |
|---|-------------|-------|
| **2.3.1** | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | 1 |
| **2.3.2** | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | 2 |
| **2.3.3** | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | 2 |
| **2.3.4** | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | 2 |
| **2.3.5** | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | 3 |

### Audit Guidance for V2.3

**2.3.1 — Sequential step enforcement (no step-skipping):**

What to look for:
- Multi-step workflows (checkout, registration, onboarding, wizards, approval processes). Check whether the application enforces that step N cannot be reached without completing step N-1.
- **Server-side state tracking:** Does the application track which step a user is on (in session, database, or state machine) and reject requests that skip ahead?
- **Red flags:** Multi-step forms where each step is an independent API call and the final submit endpoint doesn't verify that prior steps were completed. Direct URL navigation to later steps without server-side gating.
- **Good patterns:** State machine libraries (e.g., `xstate`, `aasm`, `django-fsm`, Spring Statemachine), workflow engines, server-side step tracking with validation.

**2.3.2 — Business logic limits implementation:**

What to look for:
- Rate limiting on business operations (not just API rate limiting): maximum transactions per day, maximum withdrawal amounts, maximum failed attempts before lockout.
- Check that limits documented (per 2.1.3) are actually enforced in code.
- Look for: counter checks before operations, database-level constraints, application-level limit checks.
- **Red flags:** Business operations (transfers, purchases, account creation) with no quantity or frequency checks.

**2.3.3 — Transaction atomicity:**

What to look for:
- Database transactions wrapping multi-step business operations. If step 2 of 3 fails, steps 1 and 2 should be rolled back.
- **Good patterns:** `@Transactional` (Spring), `transaction.atomic()` (Django), `ActiveRecord::Base.transaction` (Rails), explicit `BEGIN`/`COMMIT`/`ROLLBACK` in SQL, Sequelize/Knex transactions (Node.js).
- **Red flags:** Sequential database writes without transaction wrapping — if the process fails midway, the database is left in an inconsistent state. Fire-and-forget external API calls mixed with database operations without compensation logic.
- For operations involving external services (payment gateways, third-party APIs), check for saga patterns or compensation/rollback logic.

**2.3.4 — Resource locking (double-booking prevention):**

Applicable if the application manages limited-quantity resources (inventory, seats, bookings, time slots, unique codes). Mark N/A if not applicable.

What to look for:
- **Good patterns:** Database-level locking (`SELECT ... FOR UPDATE`), optimistic locking (version columns), pessimistic locking, unique constraints, atomic decrement operations (`UPDATE ... SET qty = qty - 1 WHERE qty > 0`).
- **Red flags:** Read-then-write patterns without locking — checking availability, then separately updating, with no protection against concurrent requests (TOCTOU race condition). In-memory checks without database-level enforcement.
- Check whether concurrent request handling has been considered — can two simultaneous requests both pass the availability check and both succeed?

**2.3.5 — Multi-user approval for high-value operations:**

This is a Level 3 requirement. Applicable if the application handles high-value operations (financial transactions above thresholds, administrative actions, data deletion, configuration changes, access grants).

What to look for:
- Approval workflow implementations: maker-checker patterns, dual authorization, multi-signature requirements.
- Check whether high-value operations can be completed by a single user without any secondary approval.
- This often requires business context to evaluate — what constitutes "high value" depends on the application domain. Mark with moderate confidence and flag for MANUAL_REVIEW if unsure whether multi-user approval is appropriate for identified operations.

---

## V2.4: Anti-automation

This section includes anti-automation controls to ensure that human-like interactions are required and excessive automated requests are prevented.

| # | Requirement | Level |
|---|-------------|-------|
| **2.4.1** | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | 2 |
| **2.4.2** | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | 3 |

### Audit Guidance for V2.4

**2.4.1 — Anti-automation controls:**

What to look for:
- **Rate limiting:** Check for rate limiting middleware or configuration — `express-rate-limit` (Node.js), Django Ratelimit, Rack::Attack (Rails), Spring Cloud Gateway rate limiter, API gateway rate limiting (Kong, AWS API Gateway, nginx `limit_req`).
- **Scope of rate limiting:** Is it applied globally, per-endpoint, per-user, or per-IP? Per-endpoint and per-user are more effective than global-only.
- **Sensitive endpoints:** Check that particularly abuse-prone endpoints have tighter limits: login, registration, password reset, search, export/download, API endpoints returning large datasets.
- **CAPTCHA/challenge mechanisms:** Check for CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile) on public-facing forms — registration, contact forms, comments.
- **Account creation controls:** Anti-bot measures on signup flows.
- **Red flags:** No rate limiting on any endpoint, no CAPTCHA on public forms, expensive operations (report generation, data export, search) callable without throttling.

**2.4.2 — Realistic human timing enforcement:**

This is a Level 3 requirement.

What to look for:
- Minimum time enforcement between critical operations (e.g., minimum 2 seconds between transaction submissions, minimum time on a form page before submission is accepted).
- Server-side timestamp tracking: is the time between request receipt and prior step completion checked?
- **Good patterns:** Token-based timing (issue a token with timestamp, reject submissions faster than threshold), server-side session timestamps tracking step completion times.
- **Red flags:** High-value operations (purchases, transfers, votes) that can be submitted hundreds of times per second with no timing check.
- Note: this is distinct from rate limiting (2.4.1) — rate limiting caps total requests, while this checks that individual flows take a realistic amount of time.

---

## References

For more information, see also:

* [OWASP Web Security Testing Guide: Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README.html)
* [OWASP Web Security Testing Guide: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README)
* Anti-automation can be achieved in many ways, including the use of the [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [JSON Schema](https://json-schema.org/specification.html)

---

## V2 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 4 | 2.1.1, 2.2.1, 2.2.2, 2.3.1 |
| L2 | 7 | 2.1.2, 2.1.3, 2.2.3, 2.3.2, 2.3.3, 2.3.4, 2.4.1 |
| L3 | 2 | 2.3.5, 2.4.2 |
| **Total** | **13** | |
