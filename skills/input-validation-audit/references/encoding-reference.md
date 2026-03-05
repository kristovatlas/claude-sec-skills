# Encoding Reference Guide

Context-appropriate encoding methods for preventing injection attacks.

## Why Context Matters

Different contexts require different encoding strategies. Using the wrong encoding can still leave you vulnerable:

```html
<!-- HTML context - need HTML encoding -->
<div>Hello, {{username}}</div>

<!-- JavaScript context - need JavaScript escaping -->
<script>var name = "{{username}}";</script>

<!-- URL context - need URL encoding -->
<a href="/profile?user={{username}}">Profile</a>

<!-- CSS context - need CSS escaping -->
<style>.user-{{username}} { color: red; }</style>
```

## HTML Context

### HTML Entity Encoding

Convert special characters to HTML entities to prevent XSS.

**Characters to Encode:**
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `'` → `&#x27;` or `&apos;`
- `&` → `&amp;`
- `/` → `&#x2F;` (for closing tags in attributes)

**JavaScript Implementation:**
```javascript
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// Usage
const safe = escapeHtml(userInput);
element.innerHTML = `<div>${safe}</div>`;
```

**Python Implementation:**
```python
import html

# Escape for HTML
safe = html.escape(user_input)
# Output: '<script>' becomes '&lt;script&gt;'
```

**PHP Implementation:**
```php
$safe = htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
// ENT_QUOTES: encode both single and double quotes
// ENT_HTML5: use HTML5 entities
```

**Libraries:**
- JavaScript: `DOMPurify.sanitize()` for rich HTML
- Python: `bleach.clean()` for rich HTML
- PHP: `HTMLPurifier` for rich HTML

### HTML Attribute Context

Inside HTML attributes, additional care is needed.

**Dangerous:**
```html
<!-- Even with encoding, this can be attacked -->
<div title="{{escapeHtml(userInput)}}">
<!-- If userInput = "x" onclick="alert(1)" -->
<!-- Result: <div title="x" onclick="alert(1)"> -->
```

**Safe:**
```html
<!-- Always quote attributes -->
<div title="{{escapeHtml(userInput)}}">
<!-- Now the space is inside quotes, safe -->
```

**Best Practice:**
- Always quote attributes
- Use HTML entity encoding
- Consider escaping spaces: ` ` → `&#x20;`

## JavaScript Context

### JavaScript String Escaping

When inserting into JavaScript strings, use JavaScript escaping.

**Characters to Escape:**
- `\` → `\\`
- `"` → `\"`
- `'` → `\'`
- Newline → `\n`
- Carriage return → `\r`
- Tab → `\t`
- Backspace → `\b`
- Form feed → `\f`

**JavaScript Implementation:**
```javascript
function escapeJavaScript(unsafe) {
  return unsafe
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/\x08/g, '\\b')
    .replace(/\x0c/g, '\\f')
    .replace(/</g, '\\x3c')  // Prevent </script>
    .replace(/>/g, '\\x3e');
}

// Usage
const script = `<script>var name = "${escapeJavaScript(userInput)}";</script>`;
```

**Python Implementation:**
```python
import json

# Use JSON encoding (handles JS escaping)
safe = json.dumps(user_input)
script = f'<script>var name = {safe};</script>'
```

**Important:** Avoid inserting user input into JavaScript whenever possible. Use data attributes instead:

```html
<!-- Instead of this -->
<script>var userData = "{{userInput}}";</script>

<!-- Do this -->
<div id="data" data-user="{{escapeHtml(userInput)}}"></div>
<script>
  const userData = document.getElementById('data').dataset.user;
</script>
```

## URL Context

### URL Encoding

Encode user input when constructing URLs.

**Characters to Encode:**
- Space → `%20` or `+`
- `<` → `%3C`
- `>` → `%3E`
- `#` → `%23`
- `%` → `%25`
- `{` → `%7B`
- `}` → `%7D`
- And many others...

**JavaScript Implementation:**
```javascript
// For URL parameters
const encoded = encodeURIComponent(userInput);
const url = `/search?q=${encoded}`;

// For full URLs
const fullUrl = encodeURI(userUrl);
```

**Python Implementation:**
```python
from urllib.parse import quote

# URL encode
encoded = quote(user_input)
url = f'/search?q={encoded}'

# For full URLs
from urllib.parse import quote_plus
encoded = quote_plus(user_input)  # Encodes spaces as +
```

**PHP Implementation:**
```php
$encoded = urlencode($user_input);
$url = "/search?q=$encoded";

// For full URLs
$fullUrl = rawurlencode($user_url);
```

### URL Validation

Before using URLs from user input:

```javascript
function isValidUrl(string) {
  try {
    const url = new URL(string);
    // Whitelist allowed protocols
    return ['http:', 'https:'].includes(url.protocol);
  } catch (_) {
    return false;
  }
}

// Validate before use
if (isValidUrl(userUrl)) {
  window.location = userUrl;
}
```

**Dangerous Protocols to Block:**
- `javascript:` → XSS
- `data:` → XSS
- `file:` → Local file access
- `vbscript:` → Script execution

## CSS Context

### CSS Escaping

When inserting into CSS, use CSS escaping.

**JavaScript Implementation:**
```javascript
function escapeCSS(unsafe) {
  return unsafe.replace(/[^a-zA-Z0-9]/g, function(char) {
    return '\\' + char.charCodeAt(0).toString(16) + ' ';
  });
}

// Usage
const className = escapeCSS(userInput);
const css = `.user-${className} { color: blue; }`;
```

**Best Practice:** Avoid user input in CSS entirely. Use inline styles with safe values:

```javascript
// Instead of generating CSS
element.style.color = 'blue';  // Safe, controlled value
```

## SQL Context

### NEVER Use Encoding for SQL

**Don't do this:**
```javascript
// Bad! Still vulnerable
const escaped = input.replace(/'/g, "''");
const query = `SELECT * FROM users WHERE name = '${escaped}'`;
```

**Always Use Parameterized Queries:**
```javascript
// Good! Use parameters
const query = 'SELECT * FROM users WHERE name = ?';
connection.execute(query, [userInput]);
```

## LDAP Context

### LDAP Escaping

Special characters in LDAP must be escaped.

**Characters to Escape:**
- `*` → `\2a`
- `(` → `\28`
- `)` → `\29`
- `\` → `\5c`
- NUL → `\00`

**Python Implementation:**
```python
def escape_ldap(s):
    replacements = {
        '*': '\\2a',
        '(': '\\28',
        ')': '\\29',
        '\\': '\\5c',
        '\x00': '\\00'
    }
    for char, escaped in replacements.items():
        s = s.replace(char, escaped)
    return s

# Usage
filter_str = f"(uid={escape_ldap(user_input)})"
```

## XML Context

### XML Entity Encoding

Similar to HTML but stricter.

**Characters to Encode:**
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`
- `"` → `&quot;`
- `'` → `&apos;`

**Python Implementation:**
```python
import xml.sax.saxutils as saxutils

safe = saxutils.escape(user_input, entities={
    '"': '&quot;',
    "'": '&apos;'
})
```

**Better: Use XML Libraries**
```python
import xml.etree.ElementTree as ET

root = ET.Element('user')
root.set('name', user_input)  # Library handles escaping
ET.tostring(root)
```

## JSON Context

### JSON Encoding

Use proper JSON serialization, don't build JSON strings manually.

**JavaScript:**
```javascript
// Good
const json = JSON.stringify({ name: userInput });

// Bad
const json = `{"name": "${userInput}"}`;  // Vulnerable!
```

**Python:**
```python
import json

# Good
json_str = json.dumps({'name': user_input})

# Bad
json_str = f'{{"name": "{user_input}"}}'  # Vulnerable!
```

## Command Line Context

### Shell Escaping

If you MUST pass to shell (avoid if possible):

**Python:**
```python
import shlex

# Escape for shell
safe = shlex.quote(user_input)
command = f'echo {safe}'
```

**JavaScript:**
```javascript
// No built-in, use library
const shellEscape = require('shell-escape');
const safe = shellEscape([userInput]);
```

**Better:** Don't use shell
```python
# Instead of shell
subprocess.run(['echo', user_input])  # No escaping needed!
```

## Email Header Context

### Email Header Injection Prevention

Validate email addresses and headers to prevent injection.

**Dangerous:**
```php
$to = $_POST['email'];
$subject = $_POST['subject'];
mail($to, $subject, $body);
// Attack: subject = "Test\nBcc: attacker@evil.com"
```

**Safe:**
```php
// Validate email
if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
    die('Invalid email');
}

// Remove newlines from headers
$subject = str_replace(["\r", "\n"], '', $subject);
mail($to, $subject, $body);
```

## Context Decision Tree

```
Is the data going into...
├─ HTML content?
│  └─ Use HTML entity encoding
├─ HTML attribute?
│  └─ Use HTML entity encoding + quote attributes
├─ JavaScript string?
│  ├─ Better: use data attributes
│  └─ If needed: JavaScript string escaping
├─ URL?
│  ├─ URL parameter? → URL encode
│  └─ Full URL? → Validate protocol + domain
├─ CSS?
│  └─ Avoid entirely, use inline styles with safe values
├─ SQL?
│  └─ NEVER encode, use parameterized queries
├─ Shell command?
│  ├─ Best: avoid shell, use arrays
│  └─ If needed: shell escaping
├─ XML?
│  └─ Use XML library, or XML entity encoding
├─ JSON?
│  └─ Use JSON.stringify() or json.dumps()
└─ Email header?
   └─ Validate format + remove newlines
```

## Testing Your Encoding

Test with these payloads:

**XSS:**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(1)
'"><script>alert(1)</script>
```

**SQL Injection:**
```
' OR '1'='1
'; DROP TABLE users; --
1' UNION SELECT NULL, NULL --
```

**Path Traversal:**
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
```

**Command Injection:**
```
; cat /etc/passwd
| whoami
`whoami`
$(whoami)
```

## Key Takeaways

1. **Context is everything** - Use the right encoding for each context
2. **Framework first** - Use framework auto-escaping when available
3. **Parameterize SQL** - Never encode for SQL, use parameters
4. **Avoid shell** - Don't use shell commands with user input
5. **Whitelist URLs** - Validate URL protocols and domains
6. **Test thoroughly** - Use XSS/SQLi payloads to verify protection
