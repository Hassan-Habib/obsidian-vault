
### 1. Browsing Staff-Only Threads

After gaining staff-level access to the forum, review the private staff threads. In `thread/2`, a password-reset conversation is exposed in plaintext:

  

Plaintext

```
john: Like the question says, how can I access the team slack? I got logged out and realized I don't remember the password lul
admin: The password is in Vault.
john: Ahhhh okay.. what if I don't remember my password for vault either?
admin: Mmmm alright, I'll have will change your password
will: Hi John! I just reset you password to `42zyTJ94BwdKjEw1XNmt`. Your email is still the same one as here. Make sure you change it once you log in.
john: Thx, will do <3
```

### 2. Collecting Leaked Credentials

From this thread, extract the exposed sensitive data:

  

- **Username:** `john`
    
      
    
- **Password:** `42zyTJ94BwdKjEw1XNmt`
    
      
    
- **Note:** Confirmation from `admin` that the user's email address matches the forum registration.
    
      
    

### 3. Enumerating the Target Email Address

Reviewing `thread/4` reveals another post where the same user shared his Discord handle while offering administrative support:

  

Plaintext

```
roverturbo: How can I change my email? I don't use this one for much anymore
john: Hi, we have not implemented this functionality yet. But if you message me privately I can change it for you. Discord: jdover66#0066
roverturbo: Ok I messaged you
```

From the Discord handle `jdover66#0066`, infer the username `jdover66` and construct the associated corporate email address:

  

Plaintext

```
jdover66@royalflush.htb
```

### 4. Credential Reuse Against Internal Vault

Navigate to `[https://vault.royalflush.htb](https://vault.royalflush.htb)` and authenticate using the extracted credentials:

  

Plaintext

```
Email:    jdover66@royalflush.htb
Password: 42zyTJ94BwdKjEw1XNmt
```

The application accepts the credentials, granting full access to the vault under John's account and confirming account takeover via information leaked in internal staff threads.