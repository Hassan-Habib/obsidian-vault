# Vulnerability Analysis: Plaintext Credential Exposure via Insecure Support Workflow

Staff members share plaintext account credentials inside public forum threads because the application provides no secure channel for password reset delivery. When a user forgets a password, the intended reset flow fails to deliver the new credential securely (the email function is disabled), so support staff fall back to posting the password directly in a thread reply.

Since those threads remain visible to regular forum users, any credential disclosed in this way is exposed to unauthorized actors. An attacker who reads the relevant threads can collect the leaked password together with other identity clues (such as a Discord handle) and reuse the credentials to access internal systems like `vault.royalflush.htb`.

## Root Cause

The root cause is not that the forum accepts text, but that sensitive operational data is being shared through an insecure, public channel:

1. **Secure password delivery is non-functional**
    
    `AuthController::handleLostPassword()` generates a random password, but the `mail()` call is commented out. As a result, the new password is never actually sent to the user via out-of-band email:
    
    PHP
    
    ```
    try {
        // mail(
        //     $user['email'],
        //     'RoyalFlush Forum Password Reset',
        //     'Your password has been reset. It is now:\n' . $newPassword
        // );
    } catch (Exception $e) {}
    ```
    
    Because the email never arrives, support staff are forced to manually communicate the password through alternative means.
    
2. **No private support channel exists**
    
    The application only supports public forum threads. There is no private message, ticket, or secure note feature, leaving staff with no safe space to share a temporary password with a user.
    
3. **No access control on support threads**
    
    Threads containing password-reset conversations are not restricted to the affected user and staff. `ThreadController::show()` returns every post in a thread to any visitor, allowing regular users reading the forum to view credentials intended for someone else.
    
4. **No post redaction or sensitive-data detection**
    
    Even after a password is posted, the application does not redact, expire, or flag high-entropy strings that look like passwords, leaving the credential exposed indefinitely.