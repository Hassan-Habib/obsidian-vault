**Steps to Reproduce:**

1. **Account Creation & Initial Access**
    
    - Create a user account on the staging environment
        
    - Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fandrey-faq%2Fanalysis%2Fandrey-faq.json`
        
    - Ensure you're accessing the `andrey-faq` branch and `andrey-faq.json` AI agent
        
2. **Initiate Conversation**
    
    - Start a conversation with the AI agent
        
    - Let the initial interaction complete normally
        
3. **Intercept and Modify Request**
    
    - Open Burp Suite and configure your browser to route traffic through it
        
    - Capture the HTTP request that is sent when the AI agent processes your query
        
    - In Burp, find the relevant request containing the chat/data parameters
        
    - Locate the body parameter `logs` (currently set to `false`)
        
    - Modify the value from `false` to `true`
        
    - Forward the modified request
        
4. **Observe Information Disclosure**
    
    - The initial response will show: `"User requested chat data; {number} results returned"`
        
    - Wait approximately 1 minute for the full data processing
        
    - Observe that the response now includes other customers' chat conversations with support
        
    - Note that sensitive customer data and support interactions are exposed
        

**Expected Result:**

- The `logs` parameter should not enable access to other users' chat data
    
- User should only see their own conversation history
    

**Actual Result:**

- Modifying `logs: false` to `logs: true` exposes other customers' private chat conversations
    
- Significant information disclosure vulnerability allowing access to sensitive support interactions