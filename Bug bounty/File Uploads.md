1- try to upload php file
2- check if the protection is just client side, intercept the request and modify the .png to .php
3-run intruder with multiple php extensions and see if anyone is accepted
4- append whitelisted extension to the php file test.php.png
5-you can add characters to make it work 
- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`
- i.e test.php%0a.png