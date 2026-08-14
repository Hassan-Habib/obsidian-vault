The `validateToken` function in `Vitamedix-master/src/database.js:112-129` is vulnerable to NoSQL injection. It builds a CouchDB Mango query using the attacker-controlled token value from `req.body` without validation, escaping, or parameterization. Because CouchDB Mango selectors accept query operators such as `$gt`, `$ne`, `$regex`, and `$exists`, an attacker can supply a NoSQL operator object instead of a literal token string. This changes the query semantics and forces a match against token documents that should not match.

  

### Cause

- Unsanitized user input is inserted directly into the NoSQL selector:
    
      
    
    JavaScript
    
    ```
    const options = {
      'selector': {
        'token': token   // <- user-controlled
      }
    }
    ```
    
- There is no allowlist, type check, or prepared-statement-style binding for the token.
    
      
    
- The same vulnerable `validateToken` sink is reused by `POST /api/register`, so the bypass affects the account-registration flow.
    
      
    

### Impact — leak token and create account

- **Token leak / enumeration:** The boolean response (true / 401 false) acts as an oracle. An attacker can send payloads like:
    
      
    
    JSON
    
    ```
    {"token": {"$regex": "^a"}}
    ```
    
    and iterate over characters to enumerate valid registration tokens stored in CouchDB.
    
      
    
- **Unauthorized account creation:** Because `/api/register` calls `db.validateToken(token)`, sending a universally-matching operator lets the registration succeed without knowing any real token:
    
      
    
    JSON
    
    ```
    {"token": {"$gt": ""}, "username": "attacker", "password": "password123"}
    ```
    
    This creates an authenticated user account, bypassing the intended token-gating control.