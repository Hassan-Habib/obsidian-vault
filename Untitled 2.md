## **Vulnerability Report: Broken Access Control on Verified Domains Management**

### **Summary**

A **Broken Access Control (BAC)** vulnerability exists in the Sophos Central Admin dashboard. Users assigned the **Help Desk Admin** role—which is intended for low-level troubleshooting—are able to access, view, and potentially modify the **Verify Domains** configuration. According to Sophos's security policy and official documentation, this functionality must be restricted exclusively to **Super Admins**.

### **Vulnerability Details**

- **Vulnerability Type:** CWE-285: Improper Authorization / Broken Access Control
    
- **Access Level Required:** Help Desk Admin (Predefined Role)
    
- **Impacted Area:** Global Settings > Administration > Verify Domains
    

### **Supporting Evidence (Documentation Mismatch)**

Sophos official documentation explicitly defines the security boundary that this vulnerability violates:

- **Policy Link:** `https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/GlobalSettings/FederatedDomain/`
    
- **Documented Constraint:** _"Note: You must be a Super Admin."_
    
- **Role Definition:** The _Administration Roles Summary_ states that Help Desk Admins should have _"No access to Super Admin only options."_
    

---

### **Steps to Reproduce**

1. Log in to **Sophos Central** using an account with the **Help Desk Admin** role.
    
2. Navigate to **Global Settings** (the gear icon or the left-hand menu).
    
3. Under the **Administration** section, click on **Verify Domains**.
    
4. **Observed Result:** The Help Desk user is granted full access to the page, displaying all currently verified Federated and Phish Threat domains.
    
5. **Test for Impact:** Observe the presence of the **"Add Domain"** button or the **"Delete"** (X) icons next to existing domains. (In a restricted environment, this page should return a `403 Forbidden` error or be hidden entirely).
    

### **Impact Analysis**

Unauthorized access to domain management by a low-privileged user presents a critical risk to the organization:

- **Denial of Service (Authentication):** Verified domains are used to facilitate **Federated Sign-in (SSO)**. An attacker or rogue employee with Help Desk access could delete a verified domain, immediately locking out all users who rely on that domain for SSO.
    
- **Email Communication Blackout:** For organizations using Sophos Email, deleting a verified domain can disrupt mail routing and security filtering, leading to a total loss of corporate email flow.
    
- **Phish Threat Manipulation:** Unauthorized users can add or remove domains used for phishing simulations, allowing them to bypass security training protocols or set up unauthorized testing environm
**Security Policy Violation:** This directly undermines the "Principle of Least Privilege," allowing users to modify the most sensitive identity-related settings in the tenant.
- ents.
    

### **Recommended Remediation**

- **Server-Side Authorization:** Implement a strict server-side check to ensure the requesting user's role is `Super Admin` before rendering the `Verify Domains` data or processing `POST/DELETE` requests on the domains API.
    
- **UI Masking:** Ensure the "Verify Domains" link is removed from the navigation menu for all roles except Super Admin to prevent unauthorized reconnaissance.