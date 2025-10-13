## Executive Summary

A critical security vulnerability has been identified that allows authenticated administrators to access sensitive Personally Identifiable Information (PII) of any user by manipulating the `travellerUuid` parameter during trip creation. This vulnerability exposes comprehensive user data including personal contact information, company details, and system permissions.

## Vulnerability Details

**Severity:** Critical  
**CVSS Score:** 8.5 (High)  
**Impact:** Confidentiality compromise leading to PII exposure

### Technical Description

The `/api/admin/trips` endpoint improperly authorizes access to user PII when creating trips. By substituting the legitimate user UUID with any victim's UUID in the `travellerUuid` parameter, an attacker can retrieve complete user profile information without proper authorization checks.

### Vulnerable Request

http

POST /api/admin/trips HTTP/2
Host: staging-prime.navan.com
Authorization: TripActions <JWT_TOKEN>
Content-Type: application/json
{
  "name": "Kuwait Trip",
  "startDate": "2025-11-12",
  "endDate": "2025-11-26",
  "travellerUuid": "9d201ba2-04d3-4d7f-8d57-5e45dcda952b", // Victim UUID
  "category": "BUSINESS_ONLY",
  ...
}

## Exposed PII Data

The vulnerability exposes the following sensitive information:

### Personal Information

- **Email addresses**: Primary and alternate emails
    
- **Phone numbers**: Personal and work contacts
    
- **Full names**: Given name, family name, preferred name
    
- **Account details**: Password status, enabled status
    

### Company Information

- **Company UUID and name**
    
- **Department and title**
    
- **Employee ID**
    
- **Manager relationships**
    
- **Policy levels and permissions**
    

### System Access Information

- **User roles** (ADMIN, etc.)
    
- **Administrative privileges**
    
- **System permissions**
    
- **Agency associations**
    

### Additional Sensitive Data

- **Locale and country information**
    
- **Onboarding dates**
    
- **Marketing preferences**
    
- **Travel preferences and policies**
    

## Attack Vectors

### 1. UUID Enumeration Methods

Based on the report, UUIDs can be obtained through:

1. **Guest Travel Invitations**
    
    - Inviting users to guest travel reveals their UUIDs
        
2. **Group Travel Invitations**
    
    - Adding users to group travel exposes UUIDs
        
3. **Mass Email Enumeration**
    
    - Previously reported vulnerability allows bulk email-to-UUID mapping
        

### 2. Attack Scenarios

- **Internal Threat**: Malicious administrator harvesting user data
    
- **Privilege Escalation**: Lower-privileged users accessing admin data
    
- **Data Exfiltration**: Systematic collection of organizational user data
    

## Impact Assessment

### Business Impact

- **Privacy Violation**: Exposure of employee PII
    
- **Compliance Risks**: Potential GDPR/HIPAA violations
    
- **Reputation Damage**: Loss of customer trust
    
- **Security Breach**: Unauthorized access to sensitive data
    

### Technical Impact

- **Information Disclosure**: Complete user profiles accessible
    
- **Lateral Movement**: UUIDs can be used for further attacks
    
- **Data Mining**: Bulk collection of organizational data
    

## Proof of Concept

The vulnerability was successfully exploited by:

1. Obtaining a victim UUID through known enumeration methods
    
2. Replacing the `travellerUuid` parameter in trip creation request
    
3. Receiving complete user PII in the response without authorization checks
    

## Recommendations

### Immediate Actions

1. **Input Validation**: Implement strict authorization checks for UUID access
    
2. **Principle of Least Privilege**: Ensure users can only access data they explicitly need
    
3. **Audit Logging**: Monitor all UUID access attempts
    

### Technical Fixes

javascript

// Pseudocode for proper authorization check
function createTrip(request) {
    const userUuid = request.travellerUuid;
    const requesterUuid = getRequesterUuidFromToken(request.auth);
    
    // Validate requester has permission to access target user
    if (!hasUserAccess(requesterUuid, userUuid)) {
        throw new AuthorizationError("Access denied to user data");
    }
    
    // Proceed with trip creation
    return tripService.create(request);
}

### Long-term Security Measures

1. **API Security Review**: Comprehensive audit of all user data access endpoints
    
2. **UUID Obfuscation**: Implement non-sequential UUID generation
    
3. **Rate Limiting**: Prevent bulk UUID enumeration
    
4. **Regular Security Testing**: Continuous vulnerability assessment
    

## Evidence

The provided HTTP request and response demonstrate successful exploitation, returning full user PII including:

- Email: `bold-wood-9978@bugcrowdninja-125.com`
    
- Phone: `+16465724561`
    
- Alternate email: `habibhassad@gmail.com`
    
- Complete company and role information
    

## Conclusion

This vulnerability represents a significant security risk that could lead to mass PII exposure. Immediate remediation is required to prevent unauthorized access to sensitive user information and maintain compliance with data protection regulations.