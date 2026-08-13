
The Vault application's backup-email update feature is vulnerable to SQL injection. When a logged-in user submits a new secondary email address, the application checks whether the email is already in use by running a `SELECT` query. The user-supplied value is inserted directly into the SQL command string using `string.Format()`, and the preceding regex validation is weak enough to be bypassed. As a result, an attacker can inject arbitrary SQL into the query.

  

Because the backend uses Microsoft SQL Server and the connection is configured with database credentials, a successful injection can be escalated to dump arbitrary tables, extract sensitive records (such as stored passwords and user data), and read files from the underlying server using SQL Server primitives such as `OPENROWSET(BULK...)`, `xp_dirtree`, or error-based file reads.

  

## Root Cause

The root cause is unsafe dynamic SQL construction combined with ineffective input validation:

  

1. **User input concatenated into SQL**
    
      
    
    In `MyController.SecondaryEmail()`, the secondary email value is embedded directly into the query string:
    
      
    
    C#
    
    ```
    cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
    ```
    
    Because there are no query parameters, any single quote (`'`) in the input terminates the string literal and alters the query's syntax and semantics.
    
      
    
2. **Bypassable regex validation**
    
      
    
    The validation pattern is configured as:
    
      
    
    C#
    
    ```
    string emailPattern = @"\S+@[a-z\.]+";
    ```
    
    Because it is not anchored with `^` and `$`, the `\S+` pattern permits quotes, comment markers, and SQL keywords as long as the payload ends with an `@domain.tld`-style substring. For example, `' OR 1=1--@x.com` successfully passes validation while executing injected SQL.
    
      
    
3. **Inconsistent parameterization**
    
      
    
    Although other methods within the same controller correctly utilize `SqlParameter`, this specific lookup relies on `string.Format()`, completely bypassing SQL Server's parameterization and escaping defenses.
    
      
    
4. **High-privilege database context**
    
      
    
    The connection string initialized in `DbService.GetConnectionString()` uses a dedicated SQL account with privileges sufficient to read database contents and access server files. This context elevates the impact from simple data disclosure to file-system traversal.