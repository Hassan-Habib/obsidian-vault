The impact is remote code execution (RCE) on the vault web server.

  

When the malicious serialized object is deserialized, the attacker can execute arbitrary commands in the context of the IIS application pool identity. This turns a data-access vulnerability into full server compromise, with consequences including:

  

- **Complete host takeover**
    
      
    
    The attacker can run arbitrary commands, install persistence mechanisms, create new accounts, and take full control of the underlying Windows server.
    
      
    
- **Confidentiality breach**
    
      
    
    With code execution, the attacker can read any file the application pool can access, including source code, configuration files, the database, and Windows secrets such as DPAPI-protected values.
    
      
    
- **Integrity and availability damage**
    
      
    
    The attacker can modify application files, delete data, stop services, deface the application, or deploy malware such as web shells and ransomware.
    
      
    
- **Lateral movement**
    
      
    
    From the compromised server, the attacker can scan the internal network, pivot to other systems, and abuse trust relationships to reach the database server, domain controller, or other internal services.
    
      
    
- **Theft of cryptographic material**
    
      
    
    Even without the earlier SQL injection, RCE allows the attacker to read Web.config directly and steal the AuthKey, PasswordKey, and PasswordIV, enabling forged authentication cookies and decryption of all stored passwords.
    
      
    
- **Total loss of trust in the vault**
    
      
    
    RCE on a password-vault application means the attacker can silently intercept, exfiltrate, or modify every secret managed by the application without users noticing.