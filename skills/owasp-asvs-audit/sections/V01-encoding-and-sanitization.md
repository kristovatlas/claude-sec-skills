# V1: Encoding and Sanitization

**ASVS Version:** 5.0.0
**Source file:** `5.0/en/0x10-V1-Encoding-Sanitization.md`

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## V1.1: Encoding and Sanitization Architecture

In the sections below, syntax-specific or interpreter-specific requirements for safely processing unsafe content to avoid security vulnerabilities are provided. The requirements in this section cover the order in which this processing should occur and where it should take place. They also aim to ensure that whenever data is stored, it remains in its original state and is not stored in an encoded or escaped form (e.g., HTML encoding), to prevent double encoding issues.

| # | Requirement | Level |
|---|-------------|-------|
| **1.1.1** | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | 2 |
| **1.1.2** | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | 2 |

### Audit Guidance for V1.1

**1.1.1 — Canonicalization and decode-once:**

What to look for:
- Multiple calls to decoding functions on the same input (e.g., `decodeURIComponent()` called twice, double URL decoding, HTML entity decode followed by URL decode).
- Decode operations happening *after* validation or sanitization — the correct order is: decode → validate → process.
- Data stored in encoded form in the database (e.g., HTML entities like `&lt;` stored instead of `<`), which forces decode-on-read and risks double-encoding.

Language-specific patterns:
- **Python:** `urllib.parse.unquote()` called multiple times, `html.unescape()` after validation.
- **JavaScript/Node.js:** `decodeURIComponent()` called in multiple middleware layers, `he.decode()` or `entities.decode()` after sanitization.
- **Java:** `URLDecoder.decode()` applied repeatedly, XML entity decoding after input validation.
- **PHP:** `urldecode()` called after validation (note: PHP auto-decodes `$_GET`/`$_POST`, so manual decoding can cause double-decode).
- **Go:** `url.QueryUnescape()` called multiple times on the same value.

Red flags in architecture:
- Middleware that decodes input globally, followed by handler-level decoding.
- ORM or database layer that HTML-encodes on write and decodes on read.

**1.1.2 — Output encoding as final step:**

What to look for:
- Output encoding applied early (e.g., at input time or at storage time) rather than at the point of output.
- Template rendering that uses pre-encoded values and also applies auto-escaping, resulting in double-encoding (e.g., `&amp;lt;` appearing in rendered HTML).
- Manual encoding applied before passing data to a framework that also auto-encodes.

Positive patterns to confirm:
- Template engines with auto-escaping enabled (Django templates, Jinja2 with `autoescape=True`, React JSX, Rails ERB `<%= %>`).
- Encoding/escaping applied in the view/template layer, not in the model/controller layer.
- Parameterized queries where the database driver handles escaping (this counts as "the interpreter itself" handling it).

---

## V1.2: Injection Prevention

Output encoding or escaping, performed close to or adjacent to a potentially dangerous context, is critical to the security of any application. Typically, output encoding and escaping are not persisted, but are instead used to render output safe for immediate use in the appropriate interpreter. Attempting to perform this too early may result in malformed content or render the encoding or escaping ineffective.

In many cases, software libraries include safe or safer functions that perform this automatically, although it is necessary to ensure that they are correct for the current context.

| # | Requirement | Level |
|---|-------------|-------|
| **1.2.1** | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | 1 |
| **1.2.2** | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | 1 |
| **1.2.3** | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | 1 |
| **1.2.4** | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | 1 |
| **1.2.5** | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | 1 |
| **1.2.6** | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | 2 |
| **1.2.7** | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | 2 |
| **1.2.8** | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | 2 |
| **1.2.9** | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | 2 |
| **1.2.10** | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | 3 |

> **Note from ASVS source:** Using parameterized queries or escaping SQL is not always sufficient. Query parts such as table and column names (including "ORDER BY" column names) cannot be escaped. Including escaped user-supplied data in these fields results in failed queries or SQL injection.

### Audit Guidance for V1.2

**1.2.1 — Context-specific output encoding (HTML/XML/HTTP):**

What to look for:
- User-controlled data rendered into HTML without context-appropriate encoding. The encoding must match the specific context: HTML element body, HTML attribute value, HTML comment, CSS value, or HTTP header value each require different encoding.
- HTML attribute values containing user data that are not both encoded *and* quoted (unquoted attributes can be broken out of with whitespace alone).
- User data injected into HTML comments (`<!-- -->`) — HTML encoding alone is not sufficient; `--` sequences must be prevented.
- User data inserted into CSS contexts (e.g., `style` attributes, `<style>` blocks) without CSS-specific escaping.
- User data reflected in HTTP response headers without CRLF (`\r\n`) filtering (HTTP header injection / response splitting).

Framework coverage:
- Most template engine auto-escaping covers HTML element body context only. Verify that attributes, CSS, and other contexts are handled separately.

**1.2.2 — URL construction and protocol allowlisting:**

What to look for:
- User input used to build `href`, `src`, `action`, `formaction`, or redirect URLs without URL encoding.
- Lack of protocol validation — check whether `javascript:`, `data:`, `vbscript:`, or other dangerous protocols are blocked when user input can influence the scheme portion of a URL.
- Path traversal via user input in URL path segments (e.g., `/../`).
- Open redirect vulnerabilities where user input controls the entire URL or domain.

Patterns:
- **Safe:** `encodeURIComponent()` for query parameters, URL builder libraries, framework URL helpers.
- **Unsafe:** String concatenation to build URLs, `encodeURI()` alone (does not encode `&`, `=`, etc. within query values).

**1.2.3 — JavaScript/JSON injection:**

What to look for:
- User data embedded directly in `<script>` blocks via server-side templating (even with HTML auto-escaping, this is often unsafe because HTML encoding is wrong for JavaScript context).
- JSON data rendered into HTML pages without proper escaping of `</script>`, `<!--`, or Unicode line/paragraph separators (U+2028, U+2029).
- Dynamic JavaScript string construction with user data.

Patterns:
- **Safe:** Rendering JSON into a `<script type="application/json">` tag and parsing with `JSON.parse()`, using `json_script` filter (Django), using CSP to prevent inline script execution.
- **Unsafe:** `var data = "{{ user_input }}";` in a `<script>` block, even with HTML escaping enabled.

**1.2.4 — SQL/NoSQL/database injection:**

What to look for:
- String concatenation or interpolation in SQL queries: `"SELECT * FROM users WHERE id = " + userId`, f-strings, template literals.
- ORM escape hatches: Django `raw()`, `extra()`, `RawSQL()`; Rails `find_by_sql()`, `where("col = '#{val}'")`; SQLAlchemy `text()` with string formatting; ActiveRecord string conditions.
- Stored procedures with dynamic SQL inside (`EXEC`, `sp_executesql` with concatenation).
- NoSQL: MongoDB `$where` with user input, `$regex` from user input, operator injection (user input containing `{"$gt": ""}` in query objects).
- Graph databases: Cypher injection in Neo4j via string concatenation.

> Pay special attention to the ASVS note: table names, column names, and ORDER BY targets cannot be parameterized. Look for allowlist validation of these when derived from user input.

**1.2.5 — OS command injection:**

What to look for:
- **Python:** `os.system()`, `subprocess.run(shell=True)`, `subprocess.Popen(shell=True)`, `os.popen()`
- **Node.js:** `child_process.exec()`, backtick execution in shell
- **PHP:** `exec()`, `system()`, `passthru()`, `shell_exec()`, backtick operator
- **Java:** `Runtime.getRuntime().exec()` with single string argument
- **C#:** `Process.Start()` with shell execution
- **Go:** `os/exec.Command()` with `/bin/sh -c`

Safe alternatives:
- `subprocess.run(['cmd', 'arg1', 'arg2'])` without `shell=True` (Python)
- `child_process.execFile()` or `spawn()` (Node.js)
- `ProcessBuilder` with argument list (Java)

**1.2.6 — LDAP injection:**

Applicable only if the application uses LDAP. Mark N/A if no LDAP libraries or connections are found. Look for string concatenation in LDAP filter construction. Characters requiring escaping: `*`, `(`, `)`, `\`, NUL, `/`.

**1.2.7 — XPath injection:**

Applicable only if the application processes XML with XPath queries. Mark N/A otherwise. Look for user input concatenated into XPath expression strings.

**1.2.8 — LaTeX injection:**

Applicable only if the application invokes LaTeX processors (e.g., for PDF generation). Mark N/A otherwise. Check for `--shell-escape` flag in LaTeX invocation commands. Check if user input is included in `.tex` source without sanitization of commands like `\input`, `\include`, `\write18`.

**1.2.9 — Regular expression metacharacter injection:**

What to look for:
- User input used directly as a regex pattern without escaping metacharacters.
- Patterns: `new RegExp(userInput)`, `re.compile(userInput)`, `Regex.new(userInput)`, `Pattern.compile(userInput)`.
- Safe alternatives: `re.escape()` (Python), `_.escapeRegExp()` (lodash), `Regexp.escape()` (Ruby), `Pattern.quote()` (Java).

**1.2.10 — CSV and Formula injection:**

Applicable only if the application exports data to CSV or spreadsheet formats. Mark N/A otherwise.

What to look for:
- CSV export functionality that includes user-controlled cell values.
- Check whether fields starting with `=`, `+`, `-`, `@`, `\t`, or `\0` are prefixed with a single quote (`'`) to prevent formula interpretation in spreadsheet applications.
- Check compliance with RFC 4180 sections 2.6 and 2.7 (proper quoting and escaping of fields containing commas, newlines, or double quotes).
- This is a Level 3 requirement — only flag for L3 audits.

---

## V1.3: Sanitization

The ideal protection against using untrusted content in an unsafe context is to use context-specific encoding or escaping, which maintains the same semantic meaning of the unsafe content but renders it safe for use in that particular context, as discussed in more detail in the previous section.

Where this is not possible, sanitization becomes necessary, removing potentially dangerous characters or content. In some cases, this may change the semantic meaning of the input, but for security reasons, there may be no alternative.

| # | Requirement | Level |
|---|-------------|-------|
| **1.3.1** | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | 1 |
| **1.3.2** | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | 1 |
| **1.3.3** | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | 2 |
| **1.3.4** | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | 2 |
| **1.3.5** | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | 2 |
| **1.3.6** | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | 2 |
| **1.3.7** | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | 2 |
| **1.3.8** | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | 2 |
| **1.3.9** | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | 2 |
| **1.3.10** | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | 2 |
| **1.3.11** | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | 2 |
| **1.3.12** | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | 3 |

### Audit Guidance for V1.3

**1.3.1 — HTML sanitization of WYSIWYG/rich text input:**

What to look for:
- Rich text / WYSIWYG editor integration (TinyMCE, CKEditor, Quill, ProseMirror, Draft.js, Trix).
- Is the HTML output sanitized server-side before storage or rendering?
- Known secure HTML sanitization libraries: DOMPurify (client-side JS), Bleach (Python), Sanitize (Ruby), HtmlSanitizer (.NET), OWASP Java HTML Sanitizer, `ammonia` (Rust).
- **Red flags:** Storing raw HTML from editors without server-side sanitization, relying *only* on client-side sanitization (bypassable), custom regex-based HTML stripping (almost always insufficient).

**1.3.2 — Avoiding eval() and dynamic code execution:**

What to look for:
- **JavaScript:** `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`, `vm.runInNewContext()` with user data
- **Python:** `eval()`, `exec()`, `compile()` with user data
- **Ruby:** `Kernel.eval()`, `instance_eval()`, `class_eval()` with user data
- **Java:** Spring Expression Language (SpEL) `ExpressionParser.parseExpression()` with user input, `ScriptEngine.eval()`
- **PHP:** `eval()`, `assert()` (in older PHP), `preg_replace()` with `/e` modifier (deprecated)
- **C#:** `CSharpScript.EvaluateAsync()`, Roslyn scripting with user input

Finding `eval()` with user-controlled input is critical. Finding `eval()` with only static/developer-controlled input is lower severity but still a code smell worth noting as it increases attack surface.

**1.3.3 — General sanitization before dangerous contexts:**

This is a general catch-all. Look for data flowing to dangerous sinks without any sanitization. Dangerous sinks include: `innerHTML`, `document.write()`, `Function()` constructor, template engines with raw mode, command execution functions, dynamic SQL construction. Assess whether an allowlist of safe characters is enforced and whether input length is bounded before reaching these sinks.

**1.3.4 — SVG sanitization:**

Applicable if the application handles user-supplied SVG files or inline SVG content. Mark N/A otherwise.

What to look for:
- SVG upload/rendering features. SVGs can contain `<script>`, `<foreignObject>`, event handler attributes (`onload`, `onclick`, etc.), and `<use>` elements referencing external resources.
- Check: Are dangerous tags and attributes stripped? Is SVG served with `Content-Type: image/svg+xml` and proper `Content-Disposition`?
- Consider: Converting SVG to a raster format (PNG) on upload as a safe alternative.

**1.3.5 — Scriptable content languages (Markdown, CSS, XSL, BBCode):**

What to look for:
- **Markdown:** Does the renderer allow raw HTML? Many do by default (e.g., `marked`, `markdown-it` without `html: false`). Check for XSS through raw HTML blocks, `javascript:` links, or event handlers in allowed HTML.
- **User-provided CSS:** Check for `expression()` (IE), `url()` with `javascript:` or `data:` schemes, `@import` for data exfiltration, `behavior:` property (IE).
- **XSL:** User-controlled XSLT can lead to arbitrary code execution via `<xsl:script>` or Java/C# extension functions.
- **BBCode:** Custom BBCode renderers may generate unsafe HTML from malformed or nested tags.

**1.3.6 — SSRF prevention:**

What to look for:
- Outbound HTTP requests where the URL or any component (host, path, port) is derived from user input.
- Common patterns: webhook URLs, URL preview/unfurling, PDF generation from URLs, image fetching from URLs, RSS feed fetching, API proxy endpoints.
- Check for: Allowlist validation of domains/IPs, blocking of private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, ::1, fd00::/8), blocking of non-HTTP(S) protocols (file://, gopher://, dict://), DNS rebinding protections.
- Cloud-specific: Check whether access to cloud metadata endpoints is blocked (169.254.169.254 for AWS/GCP/Azure, fd00:ec2::254 for AWS IMDSv2).

**1.3.7 — Server-side template injection (SSTI):**

What to look for:
- User input used to construct template *source* (not just template *variables*).
- Patterns: `render_template_string(user_input)` (Flask), `ERB.new(user_input).result` (Ruby), `new Template(user_input)` (Freemarker/Velocity/Pebble), `Handlebars.compile(user_input)`, Twig/Smarty/Blade with user-controlled template strings.
- **Safe:** User input only passed as template *context variables*, never as part of the template source itself.
- SSTI can lead to RCE. Very high severity when found.

**1.3.8 — JNDI injection:**

Applicable only if the application is Java-based and uses JNDI. Mark N/A otherwise.

What to look for:
- User input passed to `InitialContext.lookup()`, `Context.lookup()`, or similar JNDI APIs.
- Log4j-style JNDI lookup strings (`${jndi:ldap://...}`) in user-controllable log messages (CVE-2021-44228 and related).
- Check that JNDI remote class loading is disabled (`com.sun.jndi.ldap.object.trustURLCodebase=false`, `com.sun.jndi.rmi.object.trustURLCodebase=false`).

**1.3.9 — Memcache injection:**

Applicable only if the application uses memcached. Mark N/A otherwise.

What to look for:
- User input included in memcache keys or values without sanitization.
- Newline (`\r\n`) injection in memcache protocol commands — memcache uses a text-based protocol where CRLF separates commands, allowing injection of arbitrary commands.
- Check that memcache client libraries properly sanitize keys.

**1.3.10 — Format string sanitization:**

What to look for:
- User input passed as a format string (not as a format argument).
- **C/C++:** `printf(user_input)` instead of `printf("%s", user_input)`. This is critical — format string vulnerabilities can lead to arbitrary memory read/write.
- **Python:** `user_input.format(**locals())` or f-strings constructed from user input (unusual but possible via `eval`).
- **Java:** `String.format(user_input, ...)` where user controls the format pattern.
- In managed languages this is typically lower severity (information disclosure) but still a finding.

**1.3.11 — SMTP/IMAP injection:**

Applicable only if the application sends or processes email. Mark N/A otherwise.

What to look for:
- User-provided values (email addresses, subject lines, message bodies, CC/BCC fields) passed to SMTP/IMAP functions.
- **Red flags:** Newline characters (`\r\n`) in email header values from user input — allows injection of additional headers (e.g., BCC, additional recipients).
- **Safe patterns:** Using well-maintained email libraries that handle header escaping: `nodemailer` (Node.js), Python `email.message` module, PHPMailer, ActionMailer (Rails), JavaMail.

**1.3.12 — ReDoS prevention:**

What to look for:
- Regular expressions with nested quantifiers that can cause catastrophic backtracking: `(a+)+`, `(a|a)+`, `(a+)*`, `(.*a){n}`.
- User-controlled input matched against complex regexes — even without user-controlled patterns, long input strings can trigger exponential backtracking on vulnerable patterns.
- Safe alternatives: RE2-compatible regex engines (Go's `regexp`, Rust's `regex`, Google's RE2), regex timeout mechanisms, linear-time matching modes.
- Tools: `recheck`, `safe-regex`, `rxxr2` can statically analyze regex patterns for ReDoS vulnerability.
- This is a Level 3 requirement.

---

## V1.4: Memory, String, and Unmanaged Code

The following requirements address risks associated with unsafe memory use, which generally apply when the application uses a systems language or unmanaged code.

In some cases, it may be possible to achieve this by setting compiler flags that enable buffer overflow protections and warnings, including stack randomization and data execution prevention, and that break the build if unsafe pointer, memory, format string, integer, or string operations are found.

| # | Requirement | Level |
|---|-------------|-------|
| **1.4.1** | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | 2 |
| **1.4.2** | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | 2 |
| **1.4.3** | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | 2 |

### Audit Guidance for V1.4

**Applicability:** These requirements apply primarily when the application uses C, C++, Objective-C, or other memory-unsafe languages, or includes native extensions, FFI bindings, or WebAssembly modules compiled from such languages. If the entire application is written in a memory-safe language (Python, JavaScript, Java, Go, Rust, C#, Ruby) with no native extensions, mark all V1.4 requirements as N/A with a note that memory safety is provided by the language runtime. However, still check for native extensions or FFI:
- **Python:** C extensions, `ctypes`, `cffi`, Cython modules
- **Node.js:** Native addons (`.node` files), N-API modules
- **Java:** JNI code
- **Ruby:** C extensions in gems
- **Go:** `cgo` usage
- **C#/.NET:** P/Invoke, unsafe blocks (`unsafe { }`)

**1.4.1 — Memory-safe string and memory operations:**

What to look for (in C/C++ codebases):
- Unsafe functions: `strcpy()`, `strcat()`, `sprintf()`, `gets()`, `scanf("%s", ...)`, `memcpy()` without bounds checking.
- Safe alternatives: `strncpy()`, `strncat()`, `snprintf()`, `fgets()`, `memcpy_s()`, C++ `std::string`, `std::vector`.
- Compiler flags: Check build configuration for stack protection (`-fstack-protector-all`, `-fstack-protector-strong`), ASLR (`-fPIE -pie`), DEP/NX (`-z noexecstack`), stack canaries, FORTIFY_SOURCE (`-D_FORTIFY_SOURCE=2`).

**1.4.2 — Integer overflow prevention:**

What to look for:
- Arithmetic operations on user-controlled integer values without range or sign checking, especially before memory allocation or array indexing.
- Signed/unsigned comparison mismatches.
- Size calculations that can wrap around (e.g., `malloc(n * sizeof(element))` where `n` is user-controlled).
- Compiler flags: `-ftrapv` (GCC), integer sanitizer (`-fsanitize=integer`).

**1.4.3 — Use-after-free and dangling pointer prevention:**

What to look for:
- `free()` or `delete` followed by continued use of the pointer without nulling it.
- Returning pointers to stack-allocated variables.
- Double-free vulnerabilities.
- In C++: use of raw `new`/`delete` instead of smart pointers (`std::unique_ptr`, `std::shared_ptr`).
- Tools: AddressSanitizer (`-fsanitize=address`), Valgrind, static analysis tools (Coverity, PVS-Studio, clang-tidy).

---

## V1.5: Safe Deserialization

The conversion of data from a stored or transmitted representation into actual application objects (deserialization) has historically been the cause of various code injection vulnerabilities. It is important to perform this process carefully and safely to avoid these types of issues.

In particular, certain methods of deserialization have been identified by programming language or framework documentation as insecure and cannot be made safe with untrusted data. For each mechanism in use, careful due diligence should be performed.

| # | Requirement | Level |
|---|-------------|-------|
| **1.5.1** | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | 1 |
| **1.5.2** | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | 2 |
| **1.5.3** | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | 3 |

### Audit Guidance for V1.5

**1.5.1 — XXE prevention in XML parsers:**

What to look for by language:
- **Java:** Check `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `XMLReader` configurations. Must disable: `FEATURE_EXTERNAL_GENERAL_ENTITIES`, `FEATURE_EXTERNAL_PARAMETER_ENTITIES`, `FEATURE_DISALLOW_DOCTYPE_DECL` (safest), `XMLConstants.ACCESS_EXTERNAL_DTD`, `XMLConstants.ACCESS_EXTERNAL_SCHEMA`.
- **Python:** `lxml` — check for `resolve_entities=False`, `no_network=True`. `xml.etree.ElementTree` is safe by default (no external entity resolution). `xml.sax` — check for feature flags. `defusedxml` library is the safest option.
- **PHP:** Check for `libxml_disable_entity_loader(true)` (deprecated in PHP 8.0+, but LIBXML_NOENT should not be passed). Check `LIBXML_NOENT` flag usage in `simplexml_load_string()`, `DOMDocument::loadXML()`.
- **C#/.NET:** `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit` or `DtdProcessing.Ignore`. Check `XmlDocument`, `XPathDocument`, `XslCompiledTransform` for unsafe defaults (older .NET Framework versions are vulnerable by default).
- **Ruby:** `Nokogiri` — check for `Nokogiri::XML(input) { |config| config.nonet }`. `REXML` is generally safe by default.
- **Node.js:** Most JSON-native workflows don't use XML, but check for `libxmljs`, `xml2js`, `fast-xml-parser`. `libxmljs` is vulnerable by default.

**1.5.2 — Insecure deserialization:**

What to look for by language:
- **Java:** `ObjectInputStream.readObject()` with untrusted data, `XMLDecoder`, Java serialization (`Serializable` interface) from network input. Check for use of deserialization filters (JEP 290). Libraries: check for known gadget chains in dependencies (Apache Commons Collections, Spring, etc.). Tools: `ysoserial` payloads.
- **Python:** `pickle.loads()`, `pickle.load()`, `shelve`, `marshal.loads()`, `yaml.load()` without `Loader=SafeLoader`. **Safe:** `yaml.safe_load()`, `json.loads()`, custom deserialization with explicit type checking.
- **PHP:** `unserialize()` with user input. **Safe:** `json_decode()`, `unserialize()` with `allowed_classes` parameter (PHP 7+).
- **Ruby:** `Marshal.load()` with untrusted data, `YAML.load()` (unsafe in older Ruby). **Safe:** `YAML.safe_load()`, `JSON.parse()`.
- **C#/.NET:** `BinaryFormatter.Deserialize()` (deprecated and unsafe), `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter` with untrusted input. **Safe:** `System.Text.Json`, `JsonSerializer`, `DataContractSerializer` with known types only.
- **Node.js:** `node-serialize` (known vulnerability), `cryo`, any library that reconstructs object prototypes from serialized data. **Safe:** `JSON.parse()` (no code execution).

**1.5.3 — Parser consistency:**

This is a Level 3 requirement. What to look for:
- Multiple JSON parsers in the same application (e.g., `JSON.parse()` in one layer, a different JSON library in another) that may handle edge cases differently (duplicate keys, comment handling, trailing commas, numeric precision).
- Multiple URL parsers that may interpret URLs differently (e.g., `url.parse()` vs `new URL()` in Node.js, Python's `urllib.parse` vs `furl`).
- XML parsers with different entity resolution, namespace handling, or encoding defaults.
- The concern is that an attacker can craft input that is interpreted differently by different parsers in the processing chain, bypassing validation performed by one parser while exploiting behavior of another.
- Reference: "An Exploration of JSON Interoperability Vulnerabilities" (Bishop Fox) and Orange Tsai's research on URL parser differential exploits.

---

## References

For more information, see also:

* [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP DOM Based Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
* [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [OWASP Web Security Testing Guide: Client-Side Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing)
* [OWASP Java Encoding Project](https://owasp.org/owasp-java-encoder/)
* [DOMPurify - Client-side HTML Sanitization Library](https://github.com/cure53/DOMPurify)
* [RFC4180 - Common Format and MIME Type for Comma-Separated Values (CSV) Files](https://datatracker.ietf.org/doc/html/rfc4180#section-2)

For more information, specifically on deserialization or parsing issues, please see:

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [An Exploration of JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)
* [Orange Tsai - A New Era of SSRF Exploiting URL Parser In Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

---

## General Audit Approach for V1

When auditing this chapter, the sub-agent should:

1. **Identify all output contexts** — Places where data is rendered into HTML, inserted into SQL queries, passed to OS commands, included in URLs, sent via email, used in LDAP queries, included in log output, etc.
2. **Trace data flow** from input sources (HTTP parameters, form data, file uploads, database reads, API responses) to output sinks (template rendering, query execution, command execution, response body).
3. **Identify the encoding/escaping mechanisms in use** — Framework auto-escaping, manual encoding functions, parameterized queries, prepared statements, ORM query builders.
4. **Look for bypasses** — Places where auto-escaping is disabled (e.g., `|safe` in Jinja2, `dangerouslySetInnerHTML` in React, `{!! !!}` in Blade, `Html.Raw()` in Razor, `v-html` in Vue).
5. **Check for double-encoding or premature encoding** — Data that is encoded before storage rather than at the point of output.

### Language/Framework Quick Reference for Auto-Escape Bypasses

| Framework | Auto-escapes by default | Bypass mechanism |
|-----------|------------------------|------------------|
| Django (templates) | Yes | `\|safe`, `mark_safe()`, `{% autoescape off %}` |
| Flask/Jinja2 | Yes (if configured) | `\|safe`, `Markup()`, `{% autoescape false %}` |
| React (JSX) | Yes | `dangerouslySetInnerHTML` |
| Vue | Yes (`{{ }}`) | `v-html` directive |
| Angular | Yes | `bypassSecurityTrustHtml()`, `[innerHTML]` |
| Rails (ERB) | Yes (`<%= %>`) | `raw()`, `.html_safe`, `<%== %>` |
| Laravel (Blade) | Yes (`{{ }}`) | `{!! !!}` |
| ASP.NET Razor | Yes (`@`) | `Html.Raw()` |
| Thymeleaf | Yes (`th:text`) | `th:utext` |
| Go `html/template` | Yes | Using `text/template` instead, `template.HTML()` type cast |

### V1 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 9 | 1.2.1, 1.2.2, 1.2.3, 1.2.4, 1.2.5, 1.3.1, 1.3.2, 1.5.1 |
| L2 | 17 | 1.1.1, 1.1.2, 1.2.6, 1.2.7, 1.2.8, 1.2.9, 1.3.3, 1.3.4, 1.3.5, 1.3.6, 1.3.7, 1.3.8, 1.3.9, 1.3.10, 1.3.11, 1.4.1, 1.4.2, 1.4.3, 1.5.2 |
| L3 | 3 | 1.2.10, 1.3.12, 1.5.3 |
| **Total** | **29** | |
