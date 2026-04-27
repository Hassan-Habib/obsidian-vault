
padding oracles 

### **1. Identifying the Entry Point**

- **Target Encoded Strings:** Look for Base64 or Hex encoded strings in **Cookies**, **Hidden Form Fields**, or **URL Parameters** (e.g., `user=QUJDREVGR0hJSktMTU5PUA==`).
    
- **Analyze the Content:** Decode the string; if it results in unreadable "garbage" binary data, it is likely encrypted and worth testing.
    

### **2. Testing for the "Oracle"**

- **Trigger an Error By modifying last bytes**
    
- **Compare Responses** 
    

### **3. What to Look For (The Indicators)**

- **Verbose Error Messages:** Explicit responses like "Invalid Padding," "PKCS#7 error," or "Decryption failed."
    
- **HTTP Status Codes:** A `500 Internal Server Error` for bad padding versus a `200 OK` or `401 Unauthorized` for valid padding.
    
- **Different Response Length:**
    
- **Timing Differences:** 
    

### **4. Practical Exploitation**

- **Determine Block Size:** Test with common sizes like **16 bytes** (AES) or **8 bytes** (DES/3DES).
    
- **Automate with Tools:** * **PadBuster:** Use for automated decryption of existing strings or for forging new ones (e.g., changing `user=guest` to `user=admin`).
    
    - **Burp Suite:** Use the "Padding Oracle Hunter" extension or the "Intruder" tool to manually compare response differences.

**A. Decrypting Data:** Run this to see what is hidden inside the encrypted string (e.g., `user=guest`):

if it was a post param then it would be -post instead of -cookie flag

```
padbuster [URL] "[EncryptedSample]" [BlockSize] -cookies "user=[EncryptedSample]"
```

B- Forging the data you want 
Bash

```
padbuster [URL] "[Sample]" 16 -cookies "user=[Sample]" -plaintext "user=admin"
```


Poodle&BEAST 

To identify and exploit **POODLE** and **BEAST** vulnerabilities, focus on these practical points:

### **1. How to Find the Vulnerabilities**

- **Check Protocol Support:** Use tools like `nmap` or `sslyze` to see if the server supports **SSL 3.0** (for POODLE) or **TLS 1.0** (for BEAST).
    
    - Example: `nmap --script ssl-enum-ciphers -p 443 <IP>`
        
- **Identify CBC Ciphers:** These attacks only work if the server uses **Cipher Block Chaining (CBC)** mode (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`).
    
- **Look for Protocol Downgrades:** Test if you can force a modern browser to "fallback" to SSL 3.0 by interfering with the initial handshake.
To identify and exploit **POODLE** and **BEAST** vulnerabilities, focus on these practical points:

### **1. How to Find the Vulnerabilities**

- **Check Protocol Support:** Use tools like `nmap` or `sslyze` to see if the server supports **SSL 3.0** (for POODLE) or **TLS 1.0** (for BEAST).
    
    - Example: `nmap --script ssl-enum-ciphers -p 443 <IP>`
        
- **Identify CBC Ciphers:** These attacks only work if the server uses **Cipher Block Chaining (CBC)** mode (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`).
    
- **Look for Protocol Downgrades:** Test if you can force a modern browser to "fallback" to SSL 3.0 by interfering with the initial handshake.
    

### **2. Practical Identification Checklist**

|Attack|Primary Target|Key Indicator|
|---|---|---|
|**POODLE**|SSL 3.0|Server accepts connections using SSL 3.0 with CBC ciphers.|
|**BEAST**|TLS 1.0|Server supports TLS 1.0 and uses CBC-based suites.|

---

### **3. Exploitation Steps (Using TLS-Breaker)**

If the server supports the vulnerable protocols, use **TLS-Breaker** to verify.

- **Setup:** Ensure you have Java 11 installed and build the tool using Maven.
    
- **Scanning for POODLE:**
    
    Bash
    
    ```
    java -jar apps/poodle-1.0.1.jar -connect <IP>:<PORT>
    ```
    
- **Interpreting Results:**
    
    - `VULNERABILITY_POSSIBLE`: The server accepted the crafted handshake and didn't throw a MAC error where it should have.
        
    - `NOT_VULNERABLE`: The server rejected the connection or correctly handled the padding/MAC check.