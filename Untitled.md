Here is the professional markdown report for the **Broken Access Control** vulnerability you discovered.

---

# Security Vulnerability Report: Unauthorized Access to Administrative Logs

### **1. Executive Summary**

A **Broken Access Control** vulnerability was identified in the Administrative Interface (Port 8001). While the main administrative UI correctly restricts access to non-privileged users, the log-retrieval endpoint `/get-error-log.xqy` fails to enforce these same authorization checks. This allows an authenticated attacker to bypass restricted areas and directly read sensitive system logs, exposing administrative activity and internal configuration.

+4

---

### **2. Vulnerability Details**

- **Vulnerability Type:** Broken Access Control / Information Disclosure
    
- **Severity:** **High**
    
- **Vulnerable Endpoint:** `http://localhost:8001/get-error-log.xqy?filename=[file-name]`
    
- **Affected Port:** 8001 (Administrative Interface)
    

### **3. Root Cause**

The application fails to verify if the requesting user possesses the `admin` role before executing the `get-error-log.xqy` script. The server incorrectly relies on the assumption that if a user is "Forbidden" from the main UI, they cannot reach individual backend scripts.

+2

---

### **4. Proof of Concept (PoC)**

1. **Authenticate** as a low-privileged user (e.g., `attacker`).
    
    +1
    
2. **Access** the main admin page at `http://localhost:8001/`. The server correctly returns a `403 Forbidden` or `401 Unauthorized`.
    
3. **Bypass** this restriction by navigating directly to the log endpoint: `http://localhost:8001/get-error-log.xqy?filename=ErrorLog.txt`
    
4. **Result:** The server returns the full content of the system logs to the unauthorized user.
    
    +1
    

---

### **5. Observed Impact & Information Disclosure**

Based on the logs gathered via this vulnerability, an attacker can obtain the following sensitive data:

+1

- **Administrative Activity Monitoring:** Real-time tracking of an administrator's actions, such as visiting `/cluster-status.xqy` or `/add-user.xqy`.
    
    +1
    
- **User Reconnaissance:** Exposure of internal user IDs (e.g., `user=7071164303237443533`) which can be used to target specific accounts for CSRF or other attacks.
    
- **Internal Network Mapping:** Discovery of internal IP addresses (e.g., `172.17.0.2`) and service discovery through automated `curl` requests (e.g., `/admin/v1/init`).
    
    +1
    
- **Software Versioning:** Identification of exact system versions (e.g., `v12.0.1`), allowing for the selection of specific version-based exploits.
    
    +1
    

---

### **6. Remediation Recommendations**

1. **Enforce Strict Authorization:** Implement a server-side check within `get-error-log.xqy` to validate that the user has the required administrative privileges before processing the request.
    
2. **Apply Principle of Least Privilege:** Ensure that system-level files and logs are only accessible to the highest-level service accounts.
    
3. **Global Authorization Filter:** Implement a global security filter for Port 8001 that validates permissions for _all_ `.xqy` scripts, rather than relying on UI-level restrictions.
    

---

**Would you like me to help you integrate your previously found CSRF vulnerabilities into this report to create a "Full System Compromise" chain?**