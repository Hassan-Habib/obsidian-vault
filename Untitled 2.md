## **Vulnerability Report: Race Condition Bypasses API Credential Limit (10)**

### **Summary**

A Race Condition in the `service-credentials` endpoint allows a Tenant to bypass the documented limit of 10 API credentials. By utilizing a "Single Packet Attack" (Parallelized POST requests), a user can exceed the administrative limit and create an arbitrary number of Service Principals (30+ verified).

### **Technical Details**

- **Vulnerability Type:** Race Condition / Business Logic Bypass
    
- **Endpoint:** `POST https://central.sophos.com/api/service-credentials/[TENANT-ID]/credentials`
    
- **CWE:** CWE-367 (Time-of-Check to Time-of-Use) / CWE-770 (Allocation of Resources Without Limits)
    

### **Steps to Reproduce**

1. Log in to **Sophos Central** as a Super Admin.
    
2. Navigate to **Global Settings > API Credentials Management**.
    
3. Capture the `POST` request sent when creating a new credential using a proxy (e.g., Burp Suite).
    
4. Send this request to **Burp Repeater**.
    
5. Create a **Request Group** containing 20–30 identical `POST` requests.
    
6. Configure the group to **"Send requests in parallel (single packet attack)"**.
    
7. Execute the group.
    
8. Refresh the Sophos Central UI. Observe that the "Limit 10" note is ignored, and 30+ credentials have been successfully provisioned.
**Impact**
**Resource Exhaustion (Storage DoS):** Potential to flood the backend database with unauthorized objects via automated race-condition exploitation.