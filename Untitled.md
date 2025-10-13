

**Target:** `staging-prime.navan.com`

**Report date:** 2025-10-12

**Reported by:** Hassan Habib (provided PoC)

---



## 1 — Executive summary

An unauthenticated or insufficiently authorized feature in the support assistant / chat-analysis functionality allows an attacker to request and download large volumes of customer-support conversation data (bulk “fetch all chats”). The returned data includes personally identifiable information (names, corporate email addresses), ticket numbers, travel/booking details, and references to financial/refund actions. This is a high-impact data-exposure issue with regulatory and reputational risk.

---

## 2 — Impact

- **Confidentiality:** **High.** Full chat transcripts can expose PII (names, emails), financial dispute details, booking IDs, internal ticket numbers, and internal operational details.
    
- **Integrity:** **Low.** The issue primarily leaks data; there is no evidence that the attacker can modify stored records via the same path.
    
- **Availability:** **None** from the observed behavior.
    
- **Business / Legal:** Potential GDPR/CCPA exposure, regulatory notifications, customer trust damage, and internal process leakage (support procedures, internal ticketing).
    
- **Operational:** Staging data appears to contain production-like customer data — this increases the blast radius.
    

---

## 3 — Reproduction (safe, high-level)

> **Note:** do not include real transcripts, credentials, or production identifiers in public reports. Steps below are intentionally high-level so they may be shared safely.

1. Access the support assistant UI and choose the **Chat Analysis** feature in the staging environment.
    
2. Trigger the **export/fetch** action (e.g., “fetch all chats” or equivalent).
    
3. Observe that the response returns full chat transcripts (including PII, emails, ticket numbers, and transaction/refund details) without requiring privileged authentication / role checks or with insufficient authorization.
    
4. (Optional) Repeat for a time range (last 2 days) and note bulk data download of hundreds of chats.
    

**Observed result:** Bulk chat data returned containing user full names, corporate emails, booking/ticket numbers, and financial dispute messages. No role-based gate or MFA was required to perform the export.

---

## 4 — Proof-of-concept (redacted)

Below is a **redacted** conversation excerpt safe to include in reports. All personal identifiers, emails, booking IDs, ticket numbers, and URLs have been replaced with `[REDACTED]` or generic placeholders.

**Redacted Chat Excerpt (safe):**
```

navan support: Hi [USER]
navan support: How can I help you?
user: Hello — I need help modifying my travel trip.
navan support: Could you please provide the booking dates?
user: This is the flight and hotel — [REDACTED] to [REDACTED] — there is an earthquake warning and I’ve been advised not to travel there.
navan support: Do you know the booking ID?
user: [REDACTED]
navan support: Does the booking belong to someone else in your company?
user: Booked via company — it’s a business trip.
agent: Hi, [USER]! This is [AGENT] from Navan. I’m here to assist you in changing your flight.
user: Thank you — Booking ID [REDACTED] — I’m safe.
agent: After checking, your ticket is refundable with a fee of [REDACTED]. Shall we proceed?
user: Yes, please cancel.
agent: Cancellation processed. Approx. refund [REDACTED].
agent: Hotel policy shows non-refundable; I will request an exception via our third-party team.
user: Thank you. Please email me the update.
agent: I will send an update via email. Is there anything else?
user: No, thanks.
```



❯ ping www.google.com
ping: www.google.com: Temporary failure in name resolution
# Secure Connection Failed

An error occurred during a connection to www.google.com. SSL received a record that exceeded the maximum permissible length.

Error code: SSL_ERROR_RX_RECORD_TOO_LONG

- The page you are trying to view cannot be shown because the authenticity of the received data could not be verified.
- Please contact the website owners to inform them of this problem.

[Learn more…](https://support.mozilla.org/1/firefox/143.0.4/Linux/en-US/connection-not-secure)