# Secure Coding Practices by Framework

Framework-specific security guidance for common web frameworks.

## React / JSX

### XSS Protection
React automatically escapes JSX expressions, but certain patterns are still dangerous.

**Safe (Auto-Escaped):**
```jsx
const userInput = "<script>alert('XSS')</script>";
<div>{userInput}</div>  // Rendered as text, not HTML
```

**Dangerous:**
```jsx
// dangerouslySetInnerHTML bypasses escaping
<div dangerouslySetInnerHTML={{__html: userInput}} />

// href with javascript: protocol
<a href={`javascript:${userInput}`}>Click</a>
```

**Best Practices:**
- Trust JSX auto-escaping for text content
- Avoid `dangerouslySetInnerHTML` with user input
- Use DOMPurify if HTML rendering is required: `<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />`
- Validate URLs before using in href/src
- Use CSP headers

## Express.js / Node.js

### SQL Injection Prevention
Always use parameterized queries.

**mysql2 (Safe):**
```javascript
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = ?',
  [userEmail]
);
```

**Sequelize ORM (Safe):**
```javascript
// Query builder (safe)
User.findAll({
  where: { email: userEmail }
});

// Raw query (use replacements)
sequelize.query(
  'SELECT * FROM users WHERE email = :email',
  { replacements: { email: userEmail } }
);
```

### Command Injection Prevention

**Safe:**
```javascript
const { spawn } = require('child_process');
// Use array for arguments (no shell)
const child = spawn('ffmpeg', ['-i', userFile, 'output.mp4']);
```

**Dangerous:**
```javascript
const { exec } = require('child_process');
exec(`convert ${userFile} output.pdf`);  // Shell injection!
```

### Path Traversal Prevention

```javascript
const path = require('path');
const fs = require('fs').promises;

async function readFile(userFilename) {
  const baseDir = '/var/www/uploads';
  
  // Resolve and normalize path
  const filePath = path.resolve(baseDir, userFilename);
  
  // Verify it's within base directory
  if (!filePath.startsWith(baseDir)) {
    throw new Error('Invalid path');
  }
  
  return await fs.readFile(filePath);
}
```

## Django / Python

### XSS Protection
Django templates auto-escape by default.

**Safe (Auto-Escaped):**
```django
{{ user_input }}  <!-- Automatically escaped -->
```

**Dangerous:**
```django
{{ user_input|safe }}  <!-- Disables escaping! -->
{% autoescape off %}{{ user_input }}{% endautoescape %}
```

**Best Practices:**
- Trust default auto-escaping
- Avoid `safe` filter with user input
- Use `escape` filter for extra safety: `{{ user_input|escape }}`
- Enable CSP middleware

### SQL Injection Prevention
Django ORM protects against SQLi by default.

**Safe:**
```python
# ORM query (safe)
User.objects.filter(email=user_email)

# Raw query with parameters (safe)
User.objects.raw('SELECT * FROM users WHERE email = %s', [user_email])
```

**Dangerous:**
```python
# String formatting in raw query
User.objects.raw(f'SELECT * FROM users WHERE email = "{user_email}"')

# Extra queries with string concat
from django.db import connection
cursor = connection.cursor()
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Command Injection Prevention

```python
import subprocess

# Safe (no shell)
subprocess.run(['ping', '-c', '1', user_ip], capture_output=True)

# Dangerous (shell=True)
subprocess.run(f'ping -c 1 {user_ip}', shell=True)  # Injection!
```

## Laravel / PHP

### XSS Protection
Blade templates auto-escape with `{{ }}`.

**Safe:**
```blade
{{ $userInput }}  {{-- Auto-escaped --}}
```

**Dangerous:**
```blade
{!! $userInput !!}  {{-- Unescaped! --}}
<?php echo $userInput; ?>  {{-- Unescaped! --}}
```

**Best Practices:**
- Use `{{ }}` for output (auto-escaped)
- Avoid `{!! !!}` with user input
- Use `htmlspecialchars()` for extra escaping: `{{ htmlspecialchars($userInput) }}`

### SQL Injection Prevention
Eloquent ORM and Query Builder provide protection.

**Safe:**
```php
// Eloquent (safe)
User::where('email', $request->input('email'))->first();

// Query Builder with bindings (safe)
DB::select('SELECT * FROM users WHERE email = ?', [$email]);

// Named bindings (safe)
DB::select('SELECT * FROM users WHERE email = :email', ['email' => $email]);
```

**Dangerous:**
```php
// Raw query with string concat
DB::select("SELECT * FROM users WHERE email = '" . $email . "'");
```

### Command Injection Prevention

```php
// Safe
$output = shell_exec(escapeshellcmd($command));
$args = escapeshellarg($userInput);

// Better: avoid shell entirely
exec('ffmpeg', ['-i', $inputFile, 'output.mp4']);
```

## Ruby on Rails

### XSS Protection
ERB templates auto-escape with `<%= %>`.

**Safe:**
```erb
<%= user_input %>  <%# Auto-escaped %>
```

**Dangerous:**
```erb
<%== user_input %>  <%# Unescaped! %>
<%= raw user_input %>  <%# Unescaped! %>
<%= user_input.html_safe %>  <%# Marks as safe, dangerous! %>
```

### SQL Injection Prevention
ActiveRecord protects against SQLi.

**Safe:**
```ruby
# ActiveRecord with placeholders (safe)
User.where("email = ?", user_email)

# Named placeholders (safe)
User.where("email = :email", email: user_email)

# Hash conditions (safe)
User.where(email: user_email)
```

**Dangerous:**
```ruby
# String interpolation in query
User.where("email = '#{user_email}'")
```

## Flask / Python

### XSS Protection
Jinja2 templates auto-escape by default.

**Safe:**
```jinja2
{{ user_input }}  {# Auto-escaped #}
```

**Dangerous:**
```jinja2
{{ user_input | safe }}  {# Disables escaping! #}
{% autoescape false %}{{ user_input }}{% endautoescape %}
```

### SQL Injection Prevention

**Safe with SQLAlchemy:**
```python
# ORM (safe)
session.query(User).filter(User.email == user_email).first()

# Raw SQL with parameters (safe)
session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": user_email}
)
```

**Dangerous:**
```python
# String formatting
session.execute(f"SELECT * FROM users WHERE email = '{user_email}'")
```

## Vue.js

### XSS Protection
Vue templates auto-escape by default.

**Safe:**
```vue
<div>{{ userInput }}</div>  <!-- Auto-escaped -->
```

**Dangerous:**
```vue
<div v-html="userInput"></div>  <!-- Unescaped HTML! -->
```

**Best Practices:**
- Trust default auto-escaping
- Avoid `v-html` with user input
- Sanitize if HTML rendering needed: `<div v-html="$sanitize(userInput)"></div>` (with DOMPurify)

## ASP.NET / C#

### XSS Protection
Razor auto-escapes with `@`.

**Safe:**
```razor
@Model.UserInput  @* Auto-escaped *@
```

**Dangerous:**
```csharp
@Html.Raw(Model.UserInput)  // Unescaped!
```

### SQL Injection Prevention

**Safe:**
```csharp
// Entity Framework (safe)
var user = context.Users.Where(u => u.Email == userEmail).FirstOrDefault();

// ADO.NET with parameters (safe)
using (var command = new SqlCommand("SELECT * FROM Users WHERE Email = @email", connection))
{
    command.Parameters.AddWithValue("@email", userEmail);
    var reader = command.ExecuteReader();
}
```

**Dangerous:**
```csharp
// String concatenation
var query = $"SELECT * FROM Users WHERE Email = '{userEmail}'";
command.ExecuteReader(query);
```

## Spring Boot / Java

### XSS Protection
Thymeleaf auto-escapes by default.

**Safe:**
```html
<div th:text="${userInput}"></div>  <!-- Auto-escaped -->
```

**Dangerous:**
```html
<div th:utext="${userInput}"></div>  <!-- Unescaped! -->
```

### SQL Injection Prevention

**Safe with JPA:**
```java
// Named parameters (safe)
@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmail(@Param("email") String email);

// JdbcTemplate with parameters (safe)
jdbcTemplate.queryForObject(
    "SELECT * FROM users WHERE email = ?",
    new Object[]{email},
    new UserRowMapper()
);
```

**Dangerous:**
```java
// String concatenation
jdbcTemplate.query("SELECT * FROM users WHERE email = '" + email + "'", ...);
```

## General Framework-Agnostic Best Practices

### Input Validation
1. **Whitelist over Blacklist:** Define what's allowed, not what's forbidden
2. **Type Checking:** Ensure input matches expected type
3. **Length Limits:** Enforce maximum lengths
4. **Format Validation:** Use regex for structured data (email, phone, etc.)

```javascript
// Good validation
function validateEmail(email) {
  if (typeof email !== 'string') return false;
  if (email.length > 255) return false;
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}
```

### Output Encoding
Encode based on context:
- **HTML Context:** HTML entity encoding
- **JavaScript Context:** JavaScript escaping
- **URL Context:** URL encoding
- **CSS Context:** CSS escaping
- **SQL Context:** Parameterized queries (not encoding!)

### Content Security Policy (CSP)
Implement strict CSP headers:

```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' https://trusted-cdn.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://api.trusted.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

### Additional Headers
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Authentication & Authorization
1. Use framework authentication middleware
2. Implement proper session management
3. Apply principle of least privilege
4. Use secure password hashing (bcrypt, Argon2)
5. Implement rate limiting
6. Use HTTPS only

### Dependency Management
1. Keep dependencies updated
2. Use `npm audit`, `pip-audit`, `bundle-audit`
3. Pin dependency versions
4. Review dependencies for known vulnerabilities

## Framework-Specific Security Checkers

### Node.js
```bash
npm audit
npm audit fix
```

### Python
```bash
pip-audit
safety check
```

### Ruby
```bash
bundle audit
brakeman  # Rails security scanner
```

### PHP
```bash
composer audit
```

### Java
```bash
dependency-check
```

## Logging Best Practices

1. **Don't log sensitive data:** passwords, tokens, credit cards
2. **Log security events:** failed auth, privilege escalation attempts
3. **Sanitize logs:** prevent log injection
4. **Secure log storage:** restrict access, encrypt sensitive logs

```javascript
// Good logging
logger.info(`Login attempt for user: ${sanitize(username)}`);

// Bad logging
logger.info(`Login with password: ${password}`);  // Never log passwords!
```
