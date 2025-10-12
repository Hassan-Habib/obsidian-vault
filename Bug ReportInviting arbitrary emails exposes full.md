

**Title:** Any authenticated user can invite arbitrary emails and immediately retrieve full user profiles (PII & privilege flags) for invited users

**Product / Host:** `staging-prime.navan.com` — `/api/admin/users/bulk/enhanced` (invite) and `/api/admin/users` (list)

**Reported:** 2025-10-12

**Reporter:** [REDACTED]

**Severity (recommended):** High (may be Critical if chained to other flaws)  
**Estimated CVSS v3.1 (base):** **7.5 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N (est.)

---

## Executive summary

Any authenticated user can create an invite for any email using the `POST /api/admin/users/bulk/enhanced` endpoint. Immediately after inviting, the same caller can invoke `GET /api/admin/users?...` and receive full user objects for the invited email — including UUID, names, email, admin flags, policyLevel, and other internal booleans — **before the invitee accepts**. This allows large-scale user enumeration and privilege mapping and leaks sensitive internal account metadata.

---

## Why this is a security issue

- Admin-style endpoints return sensitive details without proper authorization checks for the caller.
    
- The application conflates “invite” state with a full user profile, exposing fields that should be private until account creation/acceptance.
    
- Any authenticated user can harvest PII and mapping of privilege flags (admin, superAdmin, policy level, etc.), enabling targeted attacks (phishing, social engineering) and reconnaissance for privilege escalation.
    

---

## Proof of concept (POC) — steps to reproduce

> **Important:** remove or redact real Authorization tokens, cookies, and other secrets before sharing publicly.

1. Authenticate as any regular user (no admin privilege required per testing).
    
2. Invite an arbitrary email:
    

```bash
POST /api/admin/users/bulk/enhanced HTTP/1.1
Host: staging-prime.navan.com
User-Agent: BurpSuite
Accept: application/json, text/plain, application/pdf
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Authorization: TripActions <REDACTED_JWT>
Cookie: <REDACTED_COOKIE>
Connection: close
Content-Length: 217

{"users":[{"givenName":"Test","familyName":"Testy","email":"victim@example.com","travelRoles":[],"delegatedUsersEmails":[],"managedUsersEmails":[]}],"skipSignup":false,"emailNote":""}

```

3. Immediately list users:
    

```bash
curl -i -X GET "https://staging-prime.navan.com/api/admin/users?enabled=true&page=1&size=10&includeRolesForDisplay=true&includeExpenseRole=true&includeNavanCardInfo=true" \
  -H "Authorization: TripActions <REDACTED_JWT>" \
  -H "Accept: application/json"
```

4. Observe the returned JSON includes the invited user object (example fields returned):
    

```json
{
  "uuid": "560950df-5e90-48f1-8265-ed15e497f427",
  "email": "victim@example.com",
  "givenName": "Test",
  "familyName": "Testy",
  "passwordSet": false,
  "phoneNumber": null,
  "admin": false,
  "superAdmin": false,
  "policyLevel": "DEFAULT",
  "companyPolicyLevel": {
     "uuid":"5dc64b53-...",
     "name":"DEFAULT",
     ...
  },
  ...
}
```

5. Repeat with many emails to confirm enumeration at scale.
    

**Observation:** Invite acceptance by the victim is **not required** — data is available immediately after invite creation.

---

## Tests already performed (by reporter)

- Confirmed any authenticated user can create a company and invite arbitrary emails.
    
- Confirmed invited user objects appear in `GET /api/admin/users` immediately and include sensitive fields and role booleans.
    

---

## Impact

- **Information disclosure** of PII (names, emails, UUIDs) and internal flags.
    
- **Privilege mapping**: attacker can identify administrative or privileged accounts by boolean flags.
    
- **Enumeration at scale**: attacker can automate invites + listing to harvest many accounts.
    
- **Facilitates targeted attacks** (phishing, social engineering, account takeover attempts).
    
- May enable **chaining** to other flaws (e.g., if other endpoints accept leaked UUID/email to perform sensitive actions without proper ownership checks).
    

---

## Classification / CWE / OWASP

- **OWASP Top 10:** Broken Access Control / Sensitive Data Exposure
    
- **CWE:** CWE-200 (Information Exposure), CWE-639 (Authorization Bypass Through User-Controlled Key)
    
- **Bug type:** Broken Object Level Authorization (BOLA) / IDOR-like info disclosure / user enumeration
    

---

## Recommended urgency & remediation priority

1. **Immediate (urgent):**
    
    - Restrict access to `/api/admin/*` endpoints so only properly authorized admin/system roles can call them.
        
    - Stop returning sensitive user fields for invited/unaccepted users.
        
    - Add temporary rate limiting on invite + listing endpoints to reduce mass enumeration risk.
        
2. **Short-term (days):**
    
    - Return a minimal invite object on invite creation (e.g., `inviteId`, `email`, `inviteStatus`) — do **not** populate user profile fields or booleans until invite is accepted.
        
    - Add audit logs for invite and user-list actions.
        
3. **Medium-term:**
    
    - Review and harden role checks across all endpoints.
        
    - Add unit/integration tests that assert only allowed roles can access admin endpoints and that invited users are returned with minimal fields.
        

---

## Concrete remediation recommendations

1. **Enforce server-side RBAC:**
    
    - `/api/admin/*` endpoints must validate server-side that the caller has admin privileges for the tenant. Do not rely on token claims alone unless validated against server-side state.
        
2. **Separate invite entity from user profile:**
    
    - On invite creation return only invite metadata (email, inviteId, status). Do not create/return a fully materialized user profile with internal booleans.
        
3. **Redact sensitive fields pre-acceptance:**
    
    - Fields to redact until acceptance: `uuid`, `admin`, `superAdmin`, `policyLevel`, `companyPolicyLevel`, `phoneNumber`, any internal role booleans.
        
4. **Tighten listing endpoint:**
    
    - Listing endpoints should only show users within the caller’s scope and should not reveal role flags unless the caller is an admin and has valid justification.
        
5. **Rate limits & abuse detection:**
    
    - Rate-limit invites/list calls and detect patterns of mass invites+lists (automated enumeration).
        
6. **Audit & monitoring:**
    
    - Log invite and listing actions, alert on unusual volumes or accesses from newly created companies.
        
7. **Add tests:**
    
    - Add regression tests ensuring invited emails do not expose full user objects until acceptance and that non-admin users cannot access admin endpoints.
        

---

## Suggested PR/patch text (example)

> Change `/api/admin/users/bulk/enhanced` to return:

```json
{
  "inviteId":"abc123",
  "email":"victim@example.com",
  "inviteStatus":"PENDING",
  "createdAt":"2025-10-12T10:57:33Z"
}
```

> Ensure `GET /api/admin/users` only lists full user objects for actual accepted users; for invite-only entries, return invite objects or exclude them entirely unless caller is an admin with explicit permission.

---

## Detection & monitoring recommendations

- Add rules to SIEM to detect large numbers of invite creations from the same account/IP.
    
- Alert on calls to `/api/admin/users` from newly created companies or non-admin accounts.
    
- Periodic automated scans to ensure APIs don’t return internal flags for invited users.
    

---

## Suggested disclosure text (if reporting externally)

> While any authenticated user can create a company, the issue is not company creation itself — it’s that inviting an arbitrary email immediately returns a full user object (including UUID and internal privilege flags) via the admin listing endpoint before the invitee accepts. This enables bulk enumeration and privilege-mapping.

---

## Example severity justification (for program triage)

Because **any authenticated user** can enumerate PII and internal role flags across the platform without the target’s consent or acceptance, the issue enables high-impact reconnaissance and targeted attacks. The vulnerability should be triaged as **High**, and remediation should prioritize restricting access and redacting sensitive fields.

---

If you want, I can:

- Produce a **shorter “vulnerability summary/email** ready to send to a security inbox (1–3 paragraphs).
    
- Add **curl** commands with placeholder tokens for direct submission.
    
- Draft a **technical remediation ticket** for engineering (JIRA/Asana-friendly).
    

Which of those would you like next?