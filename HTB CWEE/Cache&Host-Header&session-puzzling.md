# **Cache Poisoning**

You have 2 types of param , 
Keyed params => param where the responses are saved under its value , like lang=en , it shouldnt have any payloads since the victim wont send a payload to the victim
Unkeyed params => params which are saved in the responsed but doesnt matter to the cache , these is where we put out payload , since its added no matter the victim request it or not

try to look for cache using Cache busters => values that no one will ever send like lang=remoooooo , no one will send this value so we gurantee we dont hit cache

Server vs Cache
in FAT GET and Cloak attack, the server act diff than cache server 
so in FAT GET : 
GET /admin?lang=en
...
Content-Type: application/x-www-form-urlencoded

lang=`<img src=0 onerror=alert(1)>`
the server saves the body lang of the response while the cache save the response under lang=en , so when victim request lang=en the payload is server 


Cloak attack 
GET /admin?lang=en&a=blabla;lang=`<img src=0 onerror=alert(1)>`
some times in server you can separate between params other than "&" so in Bottle Python you use ; 
so again diff between server and cache so you give the cache lang=en and the server lang=`<img src=0 onerror=alert(1)>` which is add to response

WCVS
wcvs -u url  -sp language=en -gr
# **HOST Header Attack**

Scenarios:
Login page , with cache poison
Forgot password
SSRF  => tip outside CWEE: try to send 2 request in sequence via repeater one to original host and one to the local one and check 


Host
X-Forwarded-Host
X-Forwarded-Server
X-Forwarded-For
X-Host
X-Original-Host
X-Remote-Host
X-Client-Host
X-HTTP-Host-Override
Forwarded
Origin
Referer
X-Original-URL
X-Rewrite-URL

test all ips 

``````
for a in {1..255};do
    for b in {1..255};do
        echo "192.168.$a.$b" >> ips.txt
    done
done
```
```

## **Session Puzzling**

If the web app uses session not JWT ,.. etc 
FINGER THE FKIN SITE in all auth routes , logging then midway jump to forget , to register  etc بعبص الموقع يعني
mark the request that gives you the session of admin i.e first step of forget password 
then gain access to normal user , then go to first step of reset password and submit the username of admin then go back to home page and check if u have admin

