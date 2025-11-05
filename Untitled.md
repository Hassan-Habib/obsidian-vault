## Proof of Concept: Support Chat Leakage

### Prerequisites

- Create an account on the staging environment

### Steps to Reproduce

**1. Navigate to the Application**

- Go to [https://staging-prime.navan.com/app/assist/](https://staging-prime.navan.com/app/assist/)

**2. Configure Project Settings**

- Click the folder icon at the top left
- Select branch: `adminPoC`
- Select project: `query-agent-chats.json`
- Verify URL changes to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fmaster%2Fanalysis%2Fschedules%2Fagent-policies-procedures.json`

**3. Intercept Network Traffic**

- Start a new conversation with the AI
- Intercept the "start conversation" request using a proxy tool (e.g., Burp Suite)

**4. Modify Request Parameters**

- Send the intercepted request to Repeater
- Locate the `logs` parameter in the request body
- Change `logs` value from `false` to `true`
- Send the modified request

**5. Observe the Vulnerability**

- Wait approximately 1 minute
- Observe that support chats from other users are being leaked