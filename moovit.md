# CWEE Exam Report {#cwee-exam-report}

## Table of Contents {#table-of-contents}

* [CWEE Exam Report](#cwee-exam-report)
    * [Table of Contents](#table-of-contents)
    * [Meta](#meta)
    * [Executive Summary](#executive-summary)
    * [Scope](#scope)
    * [Web Application Security Assessment Summary](#web-application-security-assessment-summary)
    * [Findings](#findings)
        * [Stored Cross-Site Scripting (XSS)](#dfee355f-30f6-4129-b8c1-43cc7d581387)
    * [Appendix](#appendix)
        * [Finding Severities](#finding-severities)
        * [Flags Discovered](#flags-discovered)
        * [Exploits](#exploits)

## Meta {#meta}

### HTB Logo

![logo](assets/logo-banner.svg)

### Report Date



### HTB Candidate

**Full Name**

TODO Candidate Name

**Title**

TODO Candidate Title

**Email**

TODO Candidate Email




### Engagement Contacts

TODO: update contacts

| Company Contacts      |                         |                                                     |
| --------------------- | ----------------------- | --------------------------------------------------- |
| **Primary Contact**   | **Title**               | **Primary Contact Email**                           |
| Yelon Husk            | Chief Executive Officer | [yelon@royalflush.htb](mailto:yelon@royalflush.htb) |
| **Secondary Contact** | **Title**               | **Secondary Contact Email**                         |
| Zeyad AlMadani        | Chief Technical Officer | [zeyad@securedata.htb](mailto:zeyad@securedata.htb) |

| Assessor Contact  |            |                            |
| ----------------- | ---------- | -------------------------- |
| **Assessor Name** | **Title**  | **Assessor Contact Email** |
| YOUR_NAME         | YOUR_TITLE | YOUR_EMAIL                 |


### Statement of Confidentiality

The contents of this document have been developed by Hack The Box. Hack The Box considers the contents of this document to be proprietary and business confidential information. This information is to be used only in the performance of its intended use. This document may not be released to another vendor, business partner or contractor without prior written consent from Hack The Box. Additionally, no portion of this document may be communicated, reproduced, copied or distributed without the prior consent of Hack The Box.

The contents of this document do not constitute legal advice. Hack The Box's offer of services that relate to compliance, litigation or other legal interests are not intended as legal counsel and should not be taken as such. The assessment detailed herein is against a fictional company for training and examination purposes, and the vulnerabilities in no way affect Hack The Box external or internal infrastructure.



## Executive Summary {#executive-summary}

TODO Royal Flush Ltd. ("RoyalFlush" herein), Secure Data Ltd. ("SecureData" herein), and Vita Medix Ltd. ("VitaMedix" herein), have invited 
TODO YOUR_NAME
to perform a targeted Web Application Penetration Test of their web applications to identify high-risk security weaknesses, assess their impact, document all findings in a clear, professional, and repeatable manner, and provide remediation recommendations.

All web-related findings were considered in-scope, as long as they can be proven harmful to the client with a Medium-High impact. The following types of activities were considered out-of-scope for this test:

* Physical attacks against the clients' properties
* Unverified scanner output
* Any vulnerabilities identified through DDoS or spam attacks
* Vulnerabilities in third-party libraries unless they can be leveraged to impact the target significantly
* Any theoretical attacks or attacks that require significant user interaction or are considered low-risk


## Approach

TODO YOUR_NAME performed testing under a mixture of "blackbox" and a "whitebox" approach from TODO START_DATE to TODO END_DATE, as follows:

TODO: update approach
* `RoyalFlush` A whitebox penetration test was carried out against their targets, with access to their web applications' source code on `http://git.royalflush.htb/`.
* `SecureData` A blackbox penetration test was performed, with no further details or access to their web applications.
* `VitaMedix` A mixture of blackbox and whitebox was carried out against all web applications under their sub-domains.

Testing was performed remotely from a non-evasive standpoint, with the goal of uncovering as many misconfigurations and vulnerabilities as possible. Each weakness identified was documented and manually investigated to determine exploitation possibilities and escalation potential.

TODO YOUR_NAME sought to demonstrate the full impact of every vulnerability, up to and including internal network access. Furthermore, TODO YOUR_NAME has also documented the sources of vulnerabilities that were identified through source code analysis, and provided recommended patches to fix them.



## Scope {#scope}

The scope of this assessment was as follows:

TODO: update scope

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

During the course of testing, TODO **YOUR_NAME** uncovered a total of TODO **number** of findings that pose a material risk to clients' web applications and systems. The below table provides a summary of the findings by severity level.

TODO: update table 

| Finding Severity |          |            |           |           |           |
| ---------------- | -------- | ---------- | --------- | --------- | --------- |
| **Critical**     | **High** | **Medium** | **Low**   | **Info**  | **Total** |
| **0**            | **0**    | **0**      | **0**     | **0**     | **0**     |

Below is a high-level overview of each finding identified during the course of testing. These findings are covered in depth in the [Technical Findings Details](#technical-findings-details) section of this report.

TODO: update table

| Finding # | Severity Level | Finding Name                 |
| --------- | -------------- | ---------------------------- |
| 1.        | **Critical**   | _Command Injection_          |
| 2.        | **Medium**     | _Username Enumeration_       |
| 3.        | **Low**        | _Cookie Missing Secure Flag_ |



### Assessment Overview and Recommendations

TODO: 1 page summary of all identified vulnerabilities, as well as their respective recommended remediations.


## Findings {#findings}

### Stored Cross-Site Scripting (XSS) {#dfee355f-30f6-4129-b8c1-43cc7d581387}

#### CWE

CWE-79

#### CVSS 4.0

CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N (5.3 - Medium)

#### Affected Component(s)

* TODO AFFECTED COMPONENT

#### External References

* TODO EXTERNAL REFERENCES

#### Description & Cause

TODO DESCRIPTION & CAUSE

#### Security Impact

TODO SECURITY IMPACT

#### Detailed Walkthrough

TODO: Explain in detail how to replicate this finding and how it was identified, and provide detailed steps, screenshots, and commands to support your findings.

TODO: For vulnerabilities identified through source code analysis "whitebox", you also need to include the vulnerable code block and highlight the vulnerable lines of code. Then, you need to explain how this lead to the vulnerability. You do not need to include the entire file, but only the parts that are related to the vulnerability.


#### Patching and Remediation

TODO: Provide detailed remediation advice to fix the identified vulnerability. The advice needs to be practical with detailed instructions, and not just an overview.

TODO: For vulnerabilities identified through source code analysis "whitebox", you need to provide a recommended patch for each vulnerable code block, while highlighting the applied changes, and explaining how they remediate the issue.



## Appendix {#appendix}

### Finding Severities {#finding-severities}

Each finding has been assigned a severity rating of critical, high, medium, low or info. The rating is based off of an assessment of the priority with which each finding should be viewed and the potential impact each has on the confidentiality, integrity, and availability of data.

| Rating   | CVSS Score Range |
| -------- | ---------------- | 
| Critical | 9.0 – 10.0       |
| High     | 7.0 – 8.9        |
| Medium   | 4.0 – 6.9        |
| Low      | 0.1 – 3.9        |
| Info     | 0.0              |


### Flags Discovered {#flags-discovered}

TODO: fill in any identified flags. 

| Flag # | Application           | Flag Value | Method Used           |
| ------ | --------------------- | ---------- | --------------------- |
| 1.     | **RoyalFlush - Auth** | **HASH**   | **Command Injection** |
| 2.     | **RoyalFlush - RCE**  |            |                       |
| 3.     | **SecureData - Auth** |            |                       |
| 4.     | **SecureData - RCE**  |            |                       |
| 5.     | **VitaMedix - Auth**  |            |                       |
| 6.     | **VitaMedix - RCE**   |            |                       |


### Exploits {#exploits}

The exploit scripts used during this penetration test are attached as files in the `exploits` directory of the submitted `zip` file.

TODO: go to Notes -> Exploits and upload your exploit scripts







