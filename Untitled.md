# Security Vulnerability Report: JWT Token Leak in Conversation API

## Summary

**Severity:** Critical  
**Vulnerability Type:** Sensitive Data Exposure / Information Disclosure  
**Affected Component:** MLflow Runner Snapshot API  
**CVSS Score:** 9.1 (Critical) - AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N

## Description

A critical security vulnerability has been identified in the Navan staging environment where JWT authentication tokens are being leaked through the conversation history API endpoint. When interacting with the AI assistant, valid JWT tokens belonging to internal users are exposed in the conversation snapshot response, allowing unauthorized access to user accounts.

## Affected Endpoint

```
https://staging-prime.navan.com/api/mlflow/runner/snapshot/{Conv-runId}
```

## Vulnerability Details

### What is Leaked

- **Token Type:** JWT (JSON Web Token)
- **Algorithm:** RS256 (RSA Signature with SHA-256)
- **Key ID:** 2020-01-09-staging

### Exposed Token Payload

The leaked JWT contains sensitive user information including:

- **User UUID:** 8bdb5c50-06f2-4b2b-89f3-27f44b82f170
- **Email:** rchabra+smb-t-zy68i@navan.com
- **User Name:** Roni Chabra
- **Role:** ADMIN
- **Company UUID:** 0f1278ae-4dfd-4593-bd84-57c9f6e547fc
- **Server Region:** US
- **Issued At:** 1760619994 (Unix timestamp)
- **JWT ID:** 71f6beda-37fc-40e6-9b81-2dd842ab14d8

### Complete Leaked JWT

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjAtMDEtMDktc3RhZ2luZyJ9.ewogICJzZXJ2ZXJSZWdpb24iIDogIlVTIiwKICAic3VwZXJBZG1pbiIgOiBmYWxzZSwKICAianRpIiA6ICI3MWY2YmVkYS0zN2ZjLTQwZTYtOWI4MS0yZGQ4NDJhYjE0ZDgiLAogICJpYXQiIDogMTc2MDYxOTk5NCwKICAic3ViIiA6ICI4YmRiNWM1MC0wNmYyLTRiMmItODlmMy0yN2Y0NGI4MmYxNzAiLAogICJlbWFpbCIgOiAicmNoYWJyYStzbWItdC16eTY4aUBuYXZhbi5jb20iLAogICJnaXZlbl9uYW1lIiA6ICJSb25pIiwKICAiZmFtaWx5X25hbWUiIDogIkNoYWJyYSIsCiAgInByZWZlcnJlZF9uYW1lIiA6ICJSb25pIiwKICAicm9sZXMiIDogWyAiQURNSU4iIF0sCiAgInBlcm1pc3Npb25zIiA6IFsgXSwKICAiY29tcGFueVV1aWQiIDogIjBmMTI3OGFlLTRkZmQtNDU5My1iZDg0LTU3YzlmNmU1NDdmYyIsCiAgImltcGVyc29uYXRlZCIgOiBmYWxzZSwKICAiaW1wZXJzb25hdG9yU3VwZXJBZG1pbiIgOiBmYWxzZSwKICAicmVmZXJyZXIiIDogIlRSSVBBQ1RJT05TIiwKICAicmVfc2lnbl90b2tlbiIgOiBmYWxzZQp9.0gXOmmLq4bWdKzutbJeCmo79O30BFvJs4RbaIJPwalVbpT4bw6Ohppa2Vm4eGFICabdjfQzBtA0GfaP4xY5Cuaa4b8m3bqars7UJgFfVTAbmHQlxDSULma6XvG_TMXDsjzKvI7uORmWQ1H8MmzQhEflHX4OBZenODBXoug8xf3ncNDi_H5lTVY2QdVJHsvS9-ClsCFVJ54GwxrQHBi0yoGnwMdo24b6fkdYff8Q8qJxF8FMF8smSP8E8IeFkzHqATlFjBDsVpxMfY8JJC5PdF1stV2n2YI0YFq9JPdbpEJ3qTSeBY2m7QoVkE69YxvFmExE9mSch0Gr-LH9-nIU2Rl0X8t_bcgaJeAfVD1hWLiiGSjqqiu_8YXkhi4Mv2Y4mgPOUz7DLlgo4mDr_lmoRlmARM7wlwYGvgpvuxhCVTex_AJWEGWEvM9j_Z-m9TgemYXX9CULAhIeEdGu3lrAyhsSmEeeqWvx8nL-eLS0tyQ1Hpiv_zJs4XJf25dNUKb10_SUuYczzGxEqrIkKA9r0xWTwiU0SZrezHUwxH4tw6Ig2DtiiMmAJpEnMjaMzUBvch0CBGriYhC333_UPqOIs3wkMPy5dJXx7oUIHBCUYhRuAIHGtsWSsaWw7EaMXmGTG0EGMkbN2J9bgRvRPDuIPnIBlrdm171BMXtLsjoyodLk
```

## Steps to Reproduce

1. **Create an Account**
    
    - Navigate to https://staging-prime.navan.com
    - Register a new account or log in with existing credentials
2. **Access the AI Assistant**
    
    - Go to: https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fsearch-evals-for-mvp%2FRefactor%2FCode%2Fentry-point-system.json
3. **Initiate Conversation**
    
    - Send any message (e.g., "Hi" or any text)
    - The chat interface will close automatically after sending
4. **Extract Conversation Run ID**
    
    - Capture the `Conv-runId` from the network traffic or browser developer tools
5. **Access Leaked Token**
    
    - Make a GET request to: `https://staging-prime.navan.com/api/mlflow/runner/snapshot/{Conv-runId}`
    - Observe the JWT token in the response containing admin user credentials
6. **Verify Token Contents**
    
    - Decode the JWT token to verify it contains valid user credentials
    - Note that the token belongs to user: rchabra+smb-t-zy68i@navan.com with ADMIN role

## Impact Assessment

### Critical Security Risks

1. **Account Takeover**
    
    - Attackers can use the leaked JWT to impersonate the admin user
    - Full access to user account and associated data
2. **Privilege Escalation**
    
    - The leaked token has ADMIN role privileges
    - Potential access to sensitive company data (Company UUID: 0f1278ae-4dfd-4593-bd84-57c9f6e547fc)
3. **Horizontal Privilege Escalation**
    
    - If multiple users' tokens are leaked through this mechanism, attackers can access other user accounts
4. **Data Breach**
    
    - Exposure of PII (Personally Identifiable Information)
    - Company organizational structure and user roles exposed
5. **Session Hijacking**
    
    - Valid authenticated sessions can be stolen
    - No user interaction required after initial token leak

## Business Impact

- **Confidentiality:** HIGH - Full exposure of authentication credentials and user data
- **Integrity:** HIGH - Attackers can perform actions as the compromised user
- **Availability:** MEDIUM - Potential for account lockout or service disruption
- **Compliance Risk:** HIGH - Violation of data protection regulations (GDPR, CCPA, etc.)

## Root Cause Analysis

The vulnerability appears to stem from:

1. Improper sanitization of conversation/debug data before storage
2. MLflow runner snapshot endpoint returning raw internal data
3. Lack of access controls on the snapshot API endpoint
4. JWT tokens being logged or stored in conversation metadata
5. Missing data redaction for sensitive authentication tokens

## Recommended Remediation

### Immediate Actions (Priority: Critical)

1. **Revoke Exposed Tokens**
    
    - Immediately invalidate the leaked JWT token
    - Force re-authentication for affected user (rchabra+smb-t-zy68i@navan.com)
    - Audit all conversation snapshots for additional token leaks
2. **Disable or Restrict Endpoint**
    
    - Temporarily disable `/api/mlflow/runner/snapshot/` endpoint
    - Or implement strict authentication and authorization checks
3. **Incident Response**
    
    - Investigate access logs for unauthorized use of leaked tokens
    - Notify affected users
    - Review all conversations for similar leaks

### Short-term Fixes (1-2 weeks)

1. **Implement Data Sanitization**
    
    - Add filters to remove JWT tokens from conversation logs
    - Implement regex-based token detection: `^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`
    - Sanitize all authentication headers before logging
2. **Access Controls**
    
    - Implement proper authorization checks on snapshot endpoints
    - Ensure users can only access their own conversation snapshots
    - Add rate limiting to prevent mass enumeration
3. **Token Rotation**
    
    - Implement shorter JWT expiration times
    - Add token rotation mechanism

### Long-term Improvements

1. **Secure Logging Practices**
    
    - Implement comprehensive PII and credential redaction in all logs
    - Use structured logging with automatic sensitive data filtering
    - Regular security audits of logged data
2. **Security Headers**
    
    - Implement `X-Content-Type-Options: nosniff`
    - Add appropriate CORS policies
3. **Monitoring & Detection**
    
    - Implement anomaly detection for JWT usage patterns
    - Alert on JWT access from unexpected IPs or locations
    - Monitor for bulk snapshot API access
4. **Security Testing**
    
    - Add automated security tests to CI/CD pipeline
    - Include checks for credential leaks in API responses
    - Regular penetration testing of API endpoints

## Proof of Concept

```bash
# Step 1: Authenticate and get conversation ID
curl -X POST 'https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fsearch-evals-for-mvp%2FRefactor%2FCode%2Fentry-point-system.json' \
  -H 'Content-Type: application/json' \
  -d '{"message": "Hello"}'

# Step 2: Extract Conv-runId from response (example: abc123)

# Step 3: Access snapshot to retrieve leaked JWT
curl 'https://staging-prime.navan.com/api/mlflow/runner/snapshot/abc123'

# Response contains the leaked JWT in the conversation data
```

## References

- **OWASP:** A01:2021 – Broken Access Control
- **OWASP:** A02:2021 – Cryptographic Failures
- **OWASP:** A05:2021 – Security Misconfiguration
- **CWE-200:** Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-522:** Insufficiently Protected Credentials
- **CWE-532:** Insertion of Sensitive Information into Log File

## Additional Notes

- This vulnerability exists in the **staging environment** but should be verified in production
- The leaked token has ADMIN privileges, significantly increasing the severity
- Multiple conversation runs may expose different users' tokens
- The issue is reproducible consistently across different accounts

## Timeline

- **Discovery Date:** [Your Discovery Date]
- **Reported Date:** [Today's Date]
- **Vendor Response:** Pending
- **Status:** Reported

---

**Reporter:** [Your Name/Handle]  
**Contact:** [Your Email]  
**Date:** November 2, 2025