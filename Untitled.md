## Steps to Reproduce

### Prerequisites

- Burp Suite or similar proxy tool configured
- Valid account credentials
- Access to staging environment

### Reproduction Steps

1. **Initial Setup**
    - Create an account on the platform
    - Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Filan-tools%2Fanalysis%2Fandrei.json`

2. **Trigger the Analysis**
    - When prompted, select **"Redundant Chats"** from the 3 available options
    - Enter the following parameters when asked:
        - Date range: `August 1, 2025` to `October 30, 2025`
        - Number of chats: `500`

3. **Complete Initial Load**
    - Wait approximately 1 minute for processing
    - When prompted, type `go` to load the results
    - Observe the output: "Analyzing 500 chats... then Found 8 redundant chats"

4. **Exploit the Vulnerability**
    - Enable Burp Suite interception
    - Click on any current chat to trigger a new request
    - Capture the request in Burp Suite
    - Send the captured request to Repeater

5. **Manipulate the Request**
    - In Burp Repeater, remove **all query parameters** from the URL
    - Send the modified request

6. **Observe the Result**
    - Notice that **all 500 support chats** are now loaded and accessible
    - This bypasses the filter that should only show 8 redundant chats