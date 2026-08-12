## Initial Reconnaissance & Credential Disclosure

During the initial reconnaissance phase, public content on the **RoyalFlush forum** (`[http://forum.royalflush.htb](http://forum.royalflush.htb)`) was analyzed. A thread was identified in which an administrator posted a public message advising a user named `charles` not to set his password to be identical to his username.

### Credential Inference

Based on the explicit disclosure in the public forum thread, the target credentials were inferred as:

- **Username:** `charles`
    
- **Password:** `charles`
    

## Exploitation & Verification

1. Navigated to the primary RoyalFlush login portal at `[https://www.royalflush.htb/login](https://www.royalflush.htb/login)`.
    
2. Submitted the inferred credentials (`charles:charles`).
    
3. The authentication request was successful, yielding a valid session for the target account.
    

## Post-Exploitation & Impact Assessment

- **Access Level:** Successfully authenticated as `charles`.
    
- **Privilege Level:** Inspection of the session context confirmed the account operates with default standard privileges (`role_id = 1`).
    
- **Available Functionality:** The access grants interaction only with standard user features (e.g., modifying personal account settings, participating in gameplay).
    
- **Administrative Scope:** No direct administrative privileges or elevated routes were accessible strictly through this credential set.