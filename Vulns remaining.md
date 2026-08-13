The practical impact of this LDAP wildcard bypass is limited to unauthorized read access of user directory data:

  

- **Confidentiality:** All user email addresses stored in the directory are exposed, including mic****@vitamedix.htb and any other accounts. This is PII that can be used for phishing, targeted attacks, or correlation with other breaches.
    
      
    
- **Integrity:** No evidence of account modification, password changes, or directory writes. The exploited endpoint only returned search results.
    
      
    
- **Availability:** No service disruption observed.