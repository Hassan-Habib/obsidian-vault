
# Report: 2FA Bypass via Password Reset Flow

## Summary

The **Upstart** authentication system fails to enforce Two-Factor Authentication (2FA) requirements following a password reset. While 2FA is successfully challenged during a standard login, an attacker who gains access to a user's registered email (Gmail) can bypass the 2FA requirement entirely by performing a password reset. This allows for a full account takeover (ATO) despite the victim having extra security measures enabled.

## Vulnerability Details

- **Target:** `https://www.upstart.com`
    
- **Vulnerability Type:** Improper Authentication / 2FA Bypass
    
- **Severity:** **High (8.0 - 8.5)**
    

### Prerequisites

1. The victim has an Upstart account with **2FA enabled** (TOTP or SMS).
    
2. The attacker has gained access to the victim's email account.
    

## Steps to Reproduce

1. **Victim Side:** Log in to Upstart, go to security settings, and enable 2FA. Confirm it works by logging out and logging back in (you should be prompted for a code).
    
2. **Attacker Side:** Open a **New Incognito Window** (to ensure no existing session cookies interfere).
    
3. Navigate to the Upstart "Forgot Password" page and enter the victim’s email address.
    
4. Access the victim's Gmail, find the password reset email, and click the provided link.
    
5. Set a new password for the account and submit.
    
6. **Observation:** Upon setting the new password, the application automatically authenticates the user and redirects to the account dashboard **without requesting the 2FA token**.
    

## Impact

The 2FA feature is designed to be the "last line of defense" if a primary credential (password/email) is compromised. By bypassing this check during the password reset flow, the application leaves users vulnerable to complete account takeover. In a financial context, this could lead to unauthorized access to sensitive documents, banking details, and personal identification information.

## Expected Behavior

After a password reset, the application should:

1. Redirect the user to a 2FA challenge screen before creating a session.
    
2. **OR** Redirect the user to the standard login page where they must enter the new password **and** the 2FA code.
    

## Supporting Evidence

> [Insert Screenshot 1: Showing 2FA is enabled on the account]
> 
> [Insert Screenshot 2: Showing the password reset success page]
> 
> [Insert Screenshot 3: Showing the user logged into the dashboard without a 2FA prompt]

---

### Suggested Next Step

Before you hit send, check if you can **disable or change the 2FA phone number/method** once you are inside the account. If you can change the 2FA settings without providing the _old_ 2FA code, mention that in your report—it makes the impact even higher.

**Would you like me to help you refine the "Impact" section specifically for financial data risks found on Upstart?**