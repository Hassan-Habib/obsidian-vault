### **🛡️ Bug Bounty Triage Report: Unauthorized Sensitive Data Leak**

**Vulnerability Type:** Broken Access Control (BAC) / Insecure Direct Object Reference (IDOR)

**User Role:** Read-only

**Impact:** Sensitive Information Disclosure (High)

**Target URL:** `https://central.sophos.com/api/graphql` (or similar GraphQL gateway)

**Vulnerable Query:** `allAudits`

---

### **1. Executive Summary**

A Read-only user can bypass the standard visibility restrictions of the Sophos Central web interface by using the GraphQL API to query audit logs. While the web interface correctly filters sensitive incident details, the `allAudits` GraphQL query returns the full state of security investigations—including incident summaries, key findings, and remediation recommendations—to users who are not authorized to view them.

---

### **2. The Gap: Website View vs. API Leak**

The following table highlights the critical difference between what the system is **configured** to show and what it **actually** leaks through the API.

|Data Point|Web UI (Allowed View)|GraphQL API (`leak.json`)|Status|
|---|---|---|---|
|**Audit Log Metadata**|Date, IP Address, Action Name|Full JSON Metadata, Trace IDs, Tokens|**Intended**|
|**Action Description**|"get investigation:Read Case"|"Read Investigation"|**Intended**|
|**Investigation ID**|Redacted or limited to UUID|`98912829-4a12-4e8d-87b2...`|**Low Risk**|
|**`afterState` Content**|**Not Visible**|**FULL CASE DETAILS LEAKED**|❌ **CRITICAL LEAK**|

Export to Sheets

---

### **3. Detailed Findings & Evidence**

#### **The Leak in `afterState`**

In the standard web interface (`allowed.txt`), a Read-only user sees only that an investigation was "read". However, the `leak.json` file confirms that the GraphQL response for the same action includes the `afterState` object, which contains:

+1

- **Incident Summary:** Full description of the threat.
    
- **Key Findings:** Specific evidence discovered during the investigation.
    
- **Recommendations:** Security steps to mitigate the incident.
    
- **Status & Priority:** Internal classification levels (e.g., `priority: 2`, `status: OPEN`).
    

#### **Proof of Authorization Bypass**

Official Sophos documentation restricts "Intelligence Reports" and "Investigations" to **Super Admin, Admin, or Help Desk** roles. Read-only users are intended to have "Visibility without Volatility," but this visibility should not extend to the internal details of active security incidents.

---

### **4. Reproducing the Vulnerability**

1. **Authenticate** as a user with the **Read-only** role.
    
2. **Send a POST request** to the GraphQL endpoint with the following query:
    
    GraphQL
    
    ```
    query {
      allAudits(allAuditsInput: { limit: 10 }) {
        audits {
          eventName
          afterState # This is the vulnerable field
        }
      }
    }
    ```
    
3. **Observe the Response:** The `afterState` field will contain full investigation objects for `INCIDENT_RESPONSE` type events, even though the user cannot access the "Investigations" tab in the UI.
    

---

### **5. Impact Assessment**

This vulnerability allows an unauthorized observer (such as a junior auditor or a compromised read-only account) to view high-sensitivity details about a company's security posture, active breaches, and ongoing remediation efforts. This information could be used by an attacker to understand what security teams have discovered and what remains unprotected.

---

### **6. Recommended Remediation**

- **Field-Level Filtering:** The `afterState` and `beforeState` fields in the `allAudits` query should be nullified or redacted for users without the `Admin` or `Help Desk` roles if the `application` is `investigations`.
    
- **Role-Based Resolvers:** Implement stricter checks in the GraphQL resolver to ensure that users can only fetch detailed state changes for modules they are explicitly authorized to manage.