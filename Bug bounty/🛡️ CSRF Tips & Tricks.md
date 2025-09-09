### ✅ Basics

1. **Use GET if possible**: Some endpoints allow sensitive actions via GET—use them directly for CSRF if CSRF protection isn’t enforced on GET.
2. **Remove CSRF Token**: Try removing the `csrf` param if it’s not validated server-side.
3. **Use Attacker's CSRF Token**: If token validation is weak (e.g., not session-bound), include a token from your own session.
4. **_method Bypass**: Use `_method=POST` or `_method=PUT` in a GET request to trick frameworks that support method override.

---

### 🧠 Advanced Techniques

### 🍪 Cookie Handling

1. **Set-Cookie via Response Splitting**: Inject a `Set-Cookie` header via CRLF (`%0d%0a`) in query params to set your own CSRF token.
2. **Leverage SameSite=Lax**: If the cookie is `SameSite=Lax`, a top-level GET request will include it—just trigger the CSRF with a link or image.
3. **Target Image `onerror` for Form Submit**: Use `<img src=x onerror="document.forms[0].submit()">` to auto-submit forms.

### 🏹 Redirect-Based CSRF

1. **Open Redirect to CSRF URL**: If there's an open redirect, redirect the victim to a URL that triggers CSRF.
2. **Relative Path Traversal Redirection**: Abuse redirect parameters like `postId=../../change-email?email=...` to point to CSRF endpoints.

### 🧬 Content-Type Issues

1. **Send POST without Content-Type**: Some servers don’t validate CSRF if `Content-Type` is missing or `text/plain`.
2. **Multipart/Form-Data Override**: Use `<form enctype="multipart/form-data">` to bypass weak CSRF protections.

### 🕵️ Recon & Exploitation

1. **Check for CORS Misconfigs**: If CORS allows your origin, you can do CSRF with XHR and even read responses.
2. **Check for Referer Validation**: If the app checks referer or origin, iframe or redirect-based CSRF may fail—test with image or meta refresh.

### 🧨 Auto-CSRF Payloads

1. **Auto Link Click (via JS)**:

```html
<script>
  location = '<https://target.com/endpoint?param=value>';
</script>

```

1. **Meta Refresh**:

```html
<meta http-equiv="refresh" content="0;url=https://target.com/endpoint?param=value">

```

---

1- csrf=0

2-csrf[]=0