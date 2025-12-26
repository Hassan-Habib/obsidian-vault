
## **I. JWT (JSON Web Token)**

### **1. Signature Stripping & Algorithm Manipulation**

- **Signature Removal:** Strip the signature (the third part) and see if the server accepts `header.payload.` without validation.
    
- **`"alg": "none"` Attack:** Modify the header to set the algorithm to `none`.
    
    - _Format:_ `{"alg": "none", "typ": "JWT"}`
        
    - _Note:_ Ensure the trailing dot remains (e.g., `header.payload.`).
        

### **2. JWK (JSON Web Key) Header Injection**

- **Scenario:** Server trusts a key provided _inside_ the token header.
    
- **Step 1:** Generate Malicious RSA Pair:
    
    Bash
    
    ```
    openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
    ```
    
- **Step 2:** Use **CyberChef** (**PEM to JWK**) to convert `exploit_public.pem` to a JSON object.
    
- **Step 3:** In **JWT.io**:
    
    1. Replace only the `jwk` object details in the **Header**.
        
    2. Modify **Payload** (e.g., `"admin": true`).
        
    3. In **Verify Signature**, select **RS256** and set the format to **PEM**.
        
    4. Paste `exploit_private.pem` into the private key box.
        

### **3. Cross-Application Token Injection**

- **Scenario:** Company has `socialA.com` and `socialB.com`.
    
- **Test:** If you have high privileges on A and low on B, try using the JWT from A to access B.
    
- **Check:** Verify if the server fails to validate `aud` (audience) or `iss` (issuer) claims.
    

### **4. Secret Key Brute-Forcing (HS256)**

- Command: ```bash
    
    hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --show
    

### **5. Key Forgery & Algorithm Confusion**

- **Tool:** `jwt_forgery.py` (via Sig2n Docker).
    
- **Process:** Supply multiple JWTs to derive the public key.
    
    Bash
    
    ```
    docker run -it sig2n /bin/bash
    python3 jwt_forgery.py 'JWT_1' 'JWT_2' 'JWT_3'
    ```
    
- **Sign:** Take the resulting `.pem` and use **CyberChef (JWT Sign)** to sign your forged payload.
    

---

## **II. OAuth 2.0**

### **1. Redirect URI Manipulation**

- **Attack:** Change `redirect_uri` to your server (`attacker.com`) to steal the `code` or `token`.
    
- **Bypasses:** Try subdomains (`victim.com.attacker.com`), path traversal (`/../`), or regex flaws.
    

### **2. Cross-Site Token Injection**

- **Test:** Obtain a token for your account on one site and see if it works to log you into a different site using the same provider.
    

### **3. CSRF via State Parameter**

- **Flaw:** `state` is missing, static, or unvalidated.
    
- **Attack:** Link an attacker’s social identity to a victim’s account by sending them a callback URL you generated.
    

### **4. Parameter Injection & XSS**

- **Test:** Inject payloads into `state`, `client_id`, or `scope`.
    
- **Payload:** `&state=<script>alert(document.cookie)</script>` or `<img>` tags to leak headers.
    

---

## **III. SAML (Security Assertion Markup Language)**

### **1. Signature Exclusion (Stripping)**

- **Technique:** Intercept the `SAMLResponse`.
    
- **Action:** Delete the entire `<ds:Signature> ... </ds:Signature>` block.
    
- **Test:** Modify the `NameID` to a target user and see if the Service Provider accepts the unsigned assertion.
    

### **2. XML Signature Wrapping (XSW)**

- Technique: 1. Capture a valid signed SAML response.
    
    2. Clone the <saml:Assertion> block.
    
    3. Modify the first (cloned) assertion: Delete the signature block (<ds:Signature> ... </ds:Signature>) and change the user ID.
    
    4. Wrap: Paste this malicious assertion before the original signed one.
    
- **Logic:** The server validates the signature on the _original_ but the application processes the _first_ (malicious) assertion.
    

### **3. Recommended Tool: SAML Raider (Burp Suite)**

- Use to automate **Signature Removal** and **XSW Attacks (1-8)**.
    

---

**Would you like me to add a section on Common MFA Bypass techniques or rate-limiting bypasses to complete this cheat sheet?**