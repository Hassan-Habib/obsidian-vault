## Reproduction Steps

### Method 1: Via Browser (Probably won't work as Navan blocked browser access to the AI agent)

**Steps:**

1. **Initial Setup**
    - Create an account on Navan staging environment
    - Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fmario-project%2Fchat-quality%2Fschedules.json`
2. **Initiate Conversation**
    - Start a new conversation with the AI assistant
    - Wait approximately 1 minute for the conversation to process
3. **Intercept API Request**
    - Click on the conversation again and intercept the request using Burp Suite
4. **Exploit the Vulnerability**
    - Remove all query parameters from the intercepted request
    - Resend the modified request
    - Observe the leaked call transcript in the response

**Expected Result:** Call transcripts should NOT be accessible without proper authorization.

**Actual Result:** Call transcripts are exposed when query parameters are removed.

---

### Method 2: Via Burp Requests

**Prerequisites:**

- Burp Suite or similar HTTP proxy tool
- Valid JWT authentication token
- Access to the provided request files

**Steps:**

1. **Start Conversation**
    - Open the `start conversation.txt` file in Burp Suite
    - Add your JWT token to the request headers
    - Send the request to initiate a conversation
2. **Extract Run ID**
    - Copy the `runId` value from the API response
3. **Retrieve Conversation Data**
    - Open the `check conversation.txt` file in Burp Suite
    - Add the `runId` to the URL endpoint
    - Send the request
4. **Verify Data Exposure**
    - Examine the API response
    - Notice the call transcript is exposed in the response body

**Expected Result:** Call transcripts should require proper authorization and should only be accessible to authorized users.

**Actual Result:** Call transcripts are fully exposed in the API response using only the runId.