### Remediation / Patching

1. **Use LDAP bind, not search filters, for authentication**
    
    Authenticate by binding with the user-supplied credentials directly. A failed bind means invalid credentials.
    
      
    
2. **Escape LDAP metacharacters**
    
    If you must build filters, escape *, (, ), , and NUL before inserting user input.
    
      
    
3. **Validate input**
    
    Enforce allowlists for usernames (e.g., alphanumeric/email format) and reject wildcard characters.
    
      
    
4. **Least-privilege service account**
    
    The application should bind with an account that can only read the minimum attributes required.
    
      
    
5. **Return only needed attributes**
    
    Restrict the LDAP query to return only the fields necessary for login.
    
      
    
6. **Monitor and alert**
    
    Log failed and unusual login patterns, especially wildcard submissions.