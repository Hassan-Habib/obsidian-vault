- **Broken access control:** Any authenticated user can read files owned by other users or admins by swapping error.php for render.php after a failed `/reports.php?id=<id>` request.
    
      
    
- **Credential leak:** Sensitive files stored in the system — such as documents containing SMTP credentials — can be accessed without authorization, enabling further compromise of email/SMTP infrastructure.