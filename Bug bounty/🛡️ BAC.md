# **🔍 Information Gathering & Enumeration**

### ✅ **Analyzing Role-Based Access Control (RBAC)**

- Enumerate all user roles and permissions.
- Try accessing admin or privileged endpoints with lower-privileged accounts.
- Check API responses for role-based restrictions.

---

## **🔓 Bypassing Access Control**

### ✅ **IDOR (Insecure Direct Object References)**

- Modify `user_id`, `account_id`, or `document_id` parameters.
- Try numeric increments/decrements (`1001 → 1002`).
- Test UUIDs for predictability.
- Change `GET` to `POST` or vice versa.

### ✅ **Testing with Different Authentication States**

- Access resources as:
    - **Authenticated user** (with minimal privileges)
    - **Unauthenticated user**
    - **Admin user**

### ✅ **Access Control Through Referer Tampering**

- Change `Referer` header in requests to access restricted pages.
- Remove the `Referer` header completely and observe behavior.

### ✅ **Bypassing JWT and Token-Based Authentication**

- Modify JWT tokens (e.g., changing role from `user` to `admin`).
- Use None algorithm in JWT headers (`alg":"none"`).
- Try signing JWTs with an empty secret key.

### ✅ **Cookie and Session Manipulation**

- Modify session cookies to escalate privileges.
- Check for missing `HttpOnly`, `Secure`, or `SameSite` attributes.
- Test for weak session management by reusing old session cookies.

---

## **⚙️ Parameter Manipulation & Edge Cases**

### ✅ **Parameter Pollution**

- Send multiple `user_id` parameters:
    
    ```
    ?user_id=1001&user_id=1002
    
    ```
    
- Inject encoded versions of parameters (URL-encoded, Base64, Unicode).
    

### ✅ **Path Traversal & File Inclusion**

- Attempt accessing files outside of intended directories:
    
    ```
    ../../etc/passwd
    
    ```
    
- Test for local file inclusion (LFI) by manipulating file paths.
    

### ✅ **Tampering with Hidden Fields**

- Modify hidden form fields for privilege escalation.
- Change `role=user` to `role=admin` in HTML forms.

---

## **🔑 API & Web Application Vulnerabilities**

### ✅ **Broken Object-Level Authorization (BOLA)**

- Modify request bodies in APIs to access unauthorized data.
- Test `PUT`, `DELETE`, and `PATCH` methods on resources belonging to other users.

### ✅ **Testing OAuth & SSO Authentication**

- Attempt signing in with social logins to check for inconsistent role assignments.
- Try linking an existing account with a different OAuth provider.

## **🔑 Bypass 403**

[site.com/secret](http://site.com/secret) –> HTTP 403 Forbidden

[site.com/SECRET](http://site.com/SECRET) –> HTTP 200 OK

[site.com/secret/](http://site.com/secret/) –> HTTP 200 OK

[site.com/secret/](http://site.com/secret/). –> HTTP 200 OK

[site.com//secret//](http://site.com//secret//) –> HTTP 200 OK

[site.com/./secret/](http://site.com/./secret/).. –> HTTP 200 OK

[site.com/;/secret](http://site.com/;/secret) –> HTTP 200 OK

[site.com/.;/secret](http://site.com/.;/secret) –> HTTP 200 OK

[site.com//;//secret](http://site.com//;//secret) –> HTTP 200 OK

[site.com/secret.json](http://site.com/secret.json) –> HTTP 200 OK (ruby)

---