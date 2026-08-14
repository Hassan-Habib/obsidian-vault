The token value from the request body is placed directly into the CouchDB Mango selector. CouchDB interprets an object value (e.g., `{"$regex":"^0.*"}`) as a query operator, allowing an attacker to change the query logic. The fix is to enforce that the token is a literal string matching the expected format before it ever reaches the database query.

  

The application generates tokens with:

  

JavaScript

```
crypto.randomBytes(16).toString('hex')
```

This always produces exactly 32 lowercase hexadecimal characters. We can therefore reject anything that does not match that strict pattern.

  

### Fixed code

**`Vitamedix-master/vitamedix/vitamedix.htb/src/database.js`**

  

JavaScript

```
async validateToken(token) {
  return new Promise(async (resolve, reject) => {
    try {
      // 1. Enforce type: token must be a plain string
      if (typeof token !== 'string') {
        return reject(new Error('Invalid token format'));
      }

      // 2. Enforce format: exactly 32 lowercase hex characters
      const TOKEN_REGEX = /^[a-f0-9]{32}$/;
      if (!TOKEN_REGEX.test(token)) {
        return reject(new Error('Invalid token format'));
      }

      // 3. Safe query: token is now guaranteed to be a literal string
      const options = {
        'selector': {
          'token': token
        }
      };

      const resp = await this.registerTokens.find(options);

      if (resp.docs.length > 0) {
        return resolve();
      }

      return reject(new Error('Invalid token'));
    } catch (e) {
      return reject(e);
    }
  });
}
```

### Additional hardening recommendations

1. **Single-use tokens**
    
      
    
    After a successful `/api/register`, delete the consumed token from the `registertokens` database so it cannot be reused.
    
      
    
2. **Remove or protect the validation oracle**
    
      
    
    The `/api/validateToken` endpoint itself is not required for registration and provides a boolean oracle. Consider removing it from the public API, or at least rate-limiting it.
    
      
    
3. **Rate limiting**
    
      
    
    Apply rate limiting to `/api/register` and `/api/validateToken` to slow down token enumeration attempts.
    
      
    
4. **Consistent input validation at the route layer**
    
      
    
    Add Joi validation to `/api/validateToken` so malformed requests are rejected before reaching the database helper:
    
    JavaScript
    
    ```
    // In helpers/ValidationSchema.js
    token: Joi.object({
      token: Joi.string().hex().length(32).required()
    })
    ```