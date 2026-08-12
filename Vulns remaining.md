### Discovery

During a review of the application source code and version-control history, the complete `.env` configuration file was identified in the repository's initial commit. Although modified in subsequent commits, the initial commit remained accessible in Git history. This file contained operational secrets, including `AUTH_SECRET`, which is used by the application to sign user authentication cookies.

### Secret Extraction & Mechanism Analysis

The `AUTH_SECRET` key was recovered from the historical `.env` file. Analysis of `www/util/auth.py` indicated that this secret is used to generate HMAC-SHA256 signatures over a YAML payload containing:

- `email`
    
- `username`
    
- `expires_at`
    

### Cookie Forgery

Using the recovered `AUTH_SECRET`, an authentication token was generated targeting a specific user account:

- **Email:** `lbrown@hotmail.com`
    
- **Username:** `chandlerjoseph`
    

#### Construction Steps

The manual cookie generation process mirrors the application's internal `gen_token()` implementation:

1. **Build the YAML payload:**
    
    YAML
    
    ```
    email: lbrown@hotmail.com
    username: chandlerjoseph
    expires_at: <future_timestamp>
    ```
    
2. **Compute Signature:** Calculate the HMAC-SHA256 signature of the payload using the recovered `AUTH_SECRET`.
    
3. **Concatenate:** Append the 32-byte signature to the YAML payload.
    
4. **Encode:** Base64-encode the combined binary/text structure.
    
5. **Set Cookie:** Inject the encoded string into the browser's `auth` cookie field.
    

_(Automated via proof-of-concept script: `forge_both_admin_cookies.py`)_

### Verification & Impact

When the forged cookie was set in the browser and applied to subsequent application requests, the server accepted the token as legitimate:

- The session successfully authenticated as `lbrown@hotmail.com` (`chandlerjoseph`).
    
- Full access was granted to user-restricted endpoints, including `/settings` and role-specific portal functionality.
    
- Because the `expires_at` field within the payload is attacker-controlled, forged sessions can be set to remain valid indefinitely.