## Gemini said

Here is the most concise breakdown of the "Verify Domain" permission conflict.

---

### **The Proof: Role Conflict**

According to the [Sophos Central Docs](https://docs.sophos.com/central/customer/help/en-us/ManageYourProducts/GlobalSettings/FederatedDomain/index.html):

- **Documentation Requirement:** "You must be a **Super Admin** to verify a domain."
    
- **UI Reality:** Users with the standard **Admin** role are currently able to perform this action.
    

### **Why this is a Bug**

In the Sophos hierarchy, a standard **Admin** should only manage security policies. Granting them "Verify Domain" access allows them to alter **Federated Sign-in** settings—a high-level global configuration that the documentation explicitly reserves for **Super Admins**.