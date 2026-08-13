## Patching and Remediation

1. **Remove BinaryFormatter entirely**
    
    BinaryFormatter is obsolete and unsafe. The simplest fix is to stop serializing the password at all. Passwords should be stored as plain UTF-8 strings and encrypted directly:
    
    C#
    
    ```
    public static string EncryptPassword(string password)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(password);
        byte[] ciphertext;
    
        using (ICryptoTransform encryptor = GetAES().CreateEncryptor())
            ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    
        return Convert.ToBase64String(ciphertext);
    }
    
    public static string DecryptPassword(string b64)
    {
        try
        {
            byte[] ciphertext = Convert.FromBase64String(b64);
            byte[] plaintext;
    
            using (ICryptoTransform decryptor = GetAES().CreateDecryptor())
                plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception)
        {
            return "[!] ERROR: Corrupted Password";
        }
    }
    ```
    
    If the current database already contains BinaryFormatter-serialized entries, write a one-time migration that decrypts, deserializes in a fully trusted offline process, re-encrypts as plain strings, and updates the records.
    
2. **If serialization is truly required, use a safe serializer**
    
    Replace BinaryFormatter with `System.Text.Json` or `Newtonsoft.Json` with `TypeNameHandling.None`. Never enable type-name handling unless a strict `SerializationBinder` whitelist is in place.
    
3. **Authenticate encrypted values (Encrypt-then-MAC)**
    
    Encryption alone does not protect integrity. Use an HMAC (e.g., `HMACSHA256` with a separate key) over the ciphertext and verify it before decryption. This prevents an attacker from forging ciphertext even if the encryption key is compromised.
    
    C#
    
    ```
    byte[] ComputeHmac(byte[] data)
    {
        using (var hmac = new HMACSHA256(hmacKey))
            return hmac.ComputeHash(data);
    }
    ```
    
4. **Validate imported encrypted passwords**
    
    Do not allow the `ImportPassword` endpoint to accept arbitrary encrypted blobs without verification. After decrypting, validate that the result is a legitimate password string (length, character set) before storing it.
    
5. **Remove or restrict the ImportPassword feature**
    
    If the feature is not required, delete the `ImportPassword` action entirely. If it is required, require re-authentication, log every import, and restrict it to administrators.
    
6. **Rotate cryptographic keys**
    
    Because the `PasswordKey`, `PasswordIV`, and `AuthKey` were exposed, generate new keys immediately. Re-encrypt all stored passwords with the new keys and invalidate all existing sessions/cookies.
    
7. **Run the application pool under a low-privilege account**
    
    Configure IIS to run the application pool as a dedicated, low-privilege service account with no administrative rights. This limits the damage if RCE is achieved.
    
8. **Enable deserialization mitigations**
    
    If migration away from BinaryFormatter is not immediately possible, set an AppContext switch to block dangerous types and configure a strict `SerializationBinder` that whitelists only `byte[]`:
    
    C#
    
    ```
    AppContext.SetSwitch("Switch.System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.A deserialization vulnerability", true);
    ```
    
    However, this is only a temporary defense; complete removal is strongly recommended.
    
9. **Patch and update dependencies**
    
    Ensure all .NET libraries and NuGet packages are up to date so that known gadget chains in common libraries are eliminated.
    
10. **Monitor for exploitation**
    
    Log and alert on unusual process creation from the IIS worker process, such as `powershell.exe`, `cmd.exe`, or network connections to unexpected external addresses.