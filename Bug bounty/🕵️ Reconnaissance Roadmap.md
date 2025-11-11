
# 📌 **Step 1: Manual Reconnaissance (Application Walkthrough)**
👉 **Explore the application manually before using automated tools**

👉 Identify key functionalities, authentication mechanisms, and input fields

👉 Look for exposed sensitive information (error messages, JavaScript files)

---

# 📌 **Step 2: Open-Source Intelligence (OSINT)**

🔍 **Google/Baidu/BING Dorking**

[Google Dorking](obsidian://open?vault=obsidian-vault&file=Bug%20bounty%2FGoogle%20Dorking)

🔍 **Intel Techniques**

- [IntelTechniques OSINT Tools](https://inteltechniques.com/tools/Domain.html)

🔍 **Wayback Machine Enumeration**

```bash
echo "example.com" | waybackurls | tee wayback.txt
```

---

# 📌 **Step 3: Domain & Subdomain Enumeration**

🔹 **IP Rotation to Avoid Rate-Limiting**

```bash
sudo systemctl start tor
tmux new -s tor
while true; do sudo pkill -HUP tor; sleep 1; done

after finish 
sudo systemctl stop tor

```

🔹 **Find Domains**

```bash
subfinder -d example.com -recursive -all
```

**🔹find endpoints**

```bash
 katana -u example.com -js-crawl -kf robotstxt,sitemapxml -H " Cookie: session=token"   
```

🔹 **Amass (Passive & Active Recon) (Still under study)**

🔹 **Favicon Search**

> **What is a favicon?** The image/icon shown on the left-hand side of a tab is called as **favicon.ico**


1. View source of the website page
    
2. Search for favicon.ico
    
3. download it from the link you got from source code
    
4. Calculate the hash using python3
    

5. ```
    import hashlib
    
    def calculate_favicon_hash(file_path):
        with open(file_path, 'rb') as file:
            favicon_data = file.read()
            favicon_hash = hashlib.md5(favicon_data).hexdigest()
        return favicon_hash
    
    favicon_path = '/path/to/favicon.ico'
    favicon_hash = calculate_favicon_hash(favicon_path)
    print(favicon_hash)
    ```
    
6. Shodan Search `http.favicon.hash:[Favicon hash here]`
    

> **Hint**: Generally the favicon hash of any spring boot application is `116323821`**.** So we can use this shodan filter ****`http.favicon.hash:116323821`, You can use different favicon hashes for different services.


[](https://sallam.gitbook.io/sec-88/web-appsec/web-app-security#automation)
🔹 **Check Live Domains**

```bash
cat output.txt | httpx -mc 200
```

---

# 📌 **Step 4: Fuzzing & Virtual Host Discovery**

🔹 **FFUF (Fuzzing Subdomains & Virtual Hosts)**

```bash
ffuf -w wordlist.txt -X <request_method> -u FUZZ.example.com -H "Content-Type: application/x-www-form-urlencoded" -d <post_data> -x socks5://127.0.0.1:9050 -recursion -fc 403
ffuf -w wordlist.txt -u FUZZ.example.com
ffuf -w wordlist.txt -u <https://FUZZ-test.example.com>
ffuf -w wordlist.txt -u example.com -H "HOST:FUZZ.example.com"
```

🔹 **ASN Enumeration**

```bash
whois -h whois.radb.net -- '-i origin AS***' | grep '^route'
```

---

# 📌 **Step 5: Directory & File Enumeration**

🔹 **Dirsearch (Brute-force Directories & Files)**

```bash
dirsearch -u <https://example.com> -w wordlist.txt -f
dirsearch -l urls.txt -w wordlist.txt -e php,html,js -r --exclude-sizes=1234 -o output.txt --cookie="auth=token" -f --recursion-status 200-399
```

**🔹 Eyewitness**

```bash
eyewitness -f urls.txt --web --delay 5 -d output/location
```

🔹 **Extract Endpoints from JavaScript Files**

```bash
subjs -i urls.txt
cat urls.txt | jsleak -l -s 
awk -F'.js' 'NF<3' jsleak_results.txt > filtered_results.txt
```

---

# 📌 **Step 6: Port & Service Enumeration**

🔹 **Naabu (Port Scanning)**

```bash
naabu [options] -host <target>
```

---

### Reveal hidden elements by using console
```
function unhideElement(el) {
  if (!(el instanceof HTMLElement)) return;

  // Reset common hiding styles
  el.style.display = 'block';
  el.style.visibility = 'visible';
  el.style.opacity = '1';
  el.style.height = 'auto';
  el.style.width = 'auto';
  el.style.overflow = 'visible';
  el.style.clipPath = 'none';
  el.style.position = 'static';
  el.style.zIndex = '9999';

  // Highlight with red border
  el.style.border = '2px solid red';
}

function unhideSequentially(delay = 200) {
  const elements = Array.from(document.querySelectorAll('*')).filter(el => {
    if (!(el instanceof HTMLElement)) return false;
    const style = window.getComputedStyle(el);
    return (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      style.opacity === '0'
    );
  });

  elements.forEach((el, i) => {
    setTimeout(() => unhideElement(el), i * delay);
  });
}

// Run it
unhideSequentially(200); // 200ms between each

```
---

shodan commands

ssl:”company name”

ssl.cert.subject.on:”[domain.com](http://domain.com)”

http.tilte:”page title”

http.favicon.hash:-123456789

X-XXX-X 200/301/302/403

net:127.0.0.1:22

product:”product name”

-DORK

virustotal commands

[https://www.virustotal.com/vtapi/v2/domain/report?apikey=317db3a5286f8ae6ba724f4a9bbc5ade3a55d2cf581b72aa3f872b3e56f88bb1&domain=i](https://www.virustotal.com/vtapi/v2/domain/report?apikey=317db3a5286f8ae6ba724f4a9bbc5ade3a55d2cf581b72aa3f872b3e56f88bb1&domain=i)

sqlmap -r filter.txt --dbs --batch --risk=2 --level=3 --tamper=space2comment,between,charencode --random-agent --delay=1 --retries=5 --timeout=15 --threads=1 --flush-session --hex



test for DNS zone transfer via 
dnsenum domain 
or dig axfr @{Nameserver} domain