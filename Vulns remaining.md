1. Log in to `storage.vitamedix.htb` and request a file you own: `GET /reports.php?id=1`.
    
      
    
2. Intercept the response — server sets `$_SESSION['id'] = 1`, passes the access check, and redirects to `render.php`.
    
      
    
3. Request a file you do not own: `GET /reports.php?id=133`.
    
      
    
4. Server sets `$_SESSION['id'] = 133`, fails `check_access()`, and redirects to `error.php`.
    
      
    
5. Intercept the `error.php` redirect and change the location to `render.php`.
    
      
    
6. Browser follows `GET /render.php`; it reads `$_SESSION['id']` (still 133) and returns the file contents.
    
      
    
7. The response now leaks the unauthorized file, e.g., SMTP credentials.