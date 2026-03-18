### **Systemic CSRF Vulnerability: Global Scope**

**Root Cause:** The Administrative Interface (Port 8001) lacks any Anti-CSRF tokens and improperly allows sensitive state-changing actions via **HTTP GET** requests.

**Confirmed "Infested" Endpoints:** The following administrative modules were successfully exploited using a "tokenless" PoC, proving the server blindly trusts the browser's session:

- **User Management:** `/add-user-go.xqy` (Create Admin users)
    
- **Role Management:** `/add-role-go.xqy` (Create custom roles)
    
- **Privilege Control:** `/add-privilege-go.xqy` (Grant "Execute" & "URI" permissions)
    
- **Trust Store:** `/import-trusted-certificate-go.xqy` (Inject rogue SSL certificates)
    
- **System Amps:** `/add-amp-go.xqy` (Escalate script execution rights)
    

**Conclusion:** This is not an isolated bug; it is a **systemic failure** of the management plane. An attacker can force a logged-in Admin to completely reconfigure the server's security model with a single "Zero-Click" malicious link.