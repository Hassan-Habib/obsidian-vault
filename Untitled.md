# Vulnerability Report: Cross-Tenant PII Leakage via Insecure API Endpoint

## Summary

A critical **Cross-Tenant PII Leakage** vulnerability exists in the Navan staging environment that allows unauthorized access to sensitive customer booking data and chat transcripts across multiple tenants. By manipulating an API request to remove query parameters, an attacker can retrieve booking metadata and complete chat histories containing Personally Identifiable Information (PII) for users they should not have access to. This represents a severe breach of tenant isolation in a multi-tenant SaaS platform.

## Steps to Reproduce

1. Create an account on the Navan staging platform
2. Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2691-fix-template-invoice-and-charges%2Fanalysis%2Fsupport-qa.json`
3. Start a conversation with the AI assistant
4. When prompted for your current task, send: `"agent_chats_with_booking_metadata"`
5. When asked for parameters, respond with: `"last 7 days, maximum 200 chats"` (or any desired duration/limit)
6. Click on the conversation again and intercept the HTTP request using a proxy tool (e.g., Burp Suite, OWASP ZAP)
7. **Remove all query parameters from the intercepted request**
8. Forward the modified request
9. Observe the response containing booking IDs, UUIDs, types, statuses, and complete chat transcripts with PII from multiple unrelated customers

## Impact

### Severity: **CRITICAL**

This vulnerability enables complete unauthorized access to sensitive multi-tenant data, resulting in:

**1. Mass PII Exposure:**

- Customer full names
- TSA Known Traveler Numbers (KTN) - government-issued security credentials
- Flight booking confirmation codes
- Travel itineraries (routes, dates, times)
- Airline loyalty program information
- Complete customer service chat histories
- Email addresses and contact information
- Corporate card usage patterns
- Business travel patterns and relationships

**2. Compliance Violations:**

- **GDPR** - Unauthorized processing and exposure of EU citizen data
- **CCPA** - California resident privacy rights violations
- **PCI DSS** - Potential payment card data exposure
- **SOC 2** - Failed access control requirements
- **TSA Security Program** - Unauthorized disclosure of KTN data

**3. Business Impact:**

- Complete breakdown of tenant isolation
- Competitive intelligence exposure (corporate travel patterns)
- Reputational damage and loss of customer trust
- Legal liability and regulatory fines
- Potential class-action lawsuits

**4. Security Risks:**

- Identity theft potential
- Social engineering attacks using exposed personal details
- Unauthorized booking modifications using confirmation codes
- Travel surveillance and tracking capabilities

## Proof of Concept - Exposed PII Examples

### Leak Example 1 - TSA KTN Exposure:

**Victim:** Tiffany  
**Booking ID:** SPQJWY  
**Booking UUID:** 3a115b84-2b20-450a-9cb8-1ac927e09077  
**Channel SID:** d3e85be3-3c2f-4f69-813f-169549e3e4fa  
**TSA KTN:** TT12K8Z7H  
**Flight Route:** ORD (Chicago) ↔ SFO (San Francisco)  
**Airline:** American Airlines (AA)  
**Date:** November 12, 2025  
**AA Advantage Account:** Referenced (number not shown in transcript)  
**Exposed Chat:** Complete customer service interaction including complaints about booking system

### Leak Example 2 - International Travel Data:

**Victim:** Jumpei  
**Booking ID:** LKZHQH (also references JFEARE)  
**Booking UUID:** 20bf711d-1cce-4d42-991b-6c03fea011e6  
**Channel SID:** c7967b02-41e1-4453-849c-6685560a753a  
**Flight Route:** NRT (Tokyo) → AKL (Auckland) → ZQN (Queenstown)  
**Flight Number:** NZ0090  
**Airline:** Air New Zealand (NZ)  
**Seat Selection:** 23G, 24B  
**Dates:** November 1-7, 2025  
**Exposed Chat:** Detailed seat selection preferences and booking modifications

### Leak Example 3 - Corporate Travel Assistant Access:

**Victim:** Ronald (executive)  
**Assistant:** Victoria (making bookings on behalf)  
**Booking ID:** GMNPYQ  
**Booking UUID:** 4a0d9764-ddc9-445c-9b5f-f8dad6125244  
**Channel SID:** 956ab436-9573-4e19-ad28-47cea7a77b48  
**Flight Route:** LGA/JFK (New York) → BOS (Boston)  
**Airlines:** Delta Air Lines (DL), American Airlines (AA)  
**Date:** October 30, 2025  
**Corporate Card:** Used for $1,428.94 first-class booking  
**Exposed Information:**

- Flight cancellations and rebooking attempts
- Real-time availability searches
- Corporate travel approval patterns
- Emergency travel arrangements
- Alternative transport options (Amtrak considered)

### Additional Metadata Exposed Across All Leaks:

- `booking_provider`: "sabre"
- `booking_status`: "ticketed"
- `booking_type`: "flight"
- `booking_conversation_time_status`: "upcoming"/"ongoing"
- Complete conversation timestamps
- Agent names (Mary, Shaniqua, Judea)
- Full unstructured chat bodies with all messages

## Root Cause Analysis

The vulnerability appears to stem from:

1. **Missing authentication/authorization checks** when query parameters are removed
2. **Lack of tenant isolation enforcement** at the API level
3. **No input validation** requiring mandatory tenant/user scoping parameters
4. **Insufficient access control logic** that defaults to exposing all data when filters are absent

## Recommended Remediation

**Immediate Actions:**

1. **Disable the vulnerable endpoint** on staging and production immediately
2. **Audit access logs** to identify if this vulnerability has been exploited
3. **Notify affected users** per GDPR/CCPA breach notification requirements
4. **Revoke exposed credentials** (KTNs should be flagged with TSA if possible)

**Permanent Fixes:**

1. Implement **mandatory tenant/user context validation** on all API endpoints
2. Add **server-side authorization checks** that cannot be bypassed by parameter manipulation
3. Enforce **principle of least privilege** - users should only access their own data
4. Implement **rate limiting and anomaly detection** for bulk data access
5. Add **API gateway-level validation** to reject requests missing required parameters
6. Conduct **comprehensive security audit** of all similar endpoints
7. Implement **automated security testing** to prevent regression

**Detection & Monitoring:**

1. Add alerts for requests with missing/removed query parameters
2. Monitor for bulk data access patterns
3. Log all cross-tenant access attempts

## CVSS Score Estimate

**CVSS v3.1: 9.1 (CRITICAL)**

- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: Low (PR:L)
- User Interaction: None (UI:N)
- Scope: Changed (S:C)
- Confidentiality: High (C:H)
- Integrity: None (I:N)
- Availability: None (A:N)

---

**Reported By:** [Your Name]  
**Report Date:** November 7, 2025  
**Platform:** Navan Staging Environment  
**Affected Endpoint:** `staging-prime.navan.com/app/assist/`