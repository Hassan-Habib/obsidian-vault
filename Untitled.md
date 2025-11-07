## Steps to Reproduce

### Method 1: Via Browser

1. **Initial Setup**
    
    - Create a user account on `https://staging-prime.navan.com`
        
    - Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2FAVA-489_Try-to-route-non-answered-questions-back-to-main-loop%2Fchat-quality%2Fschedules.json`
        
2. **Trigger Conversation**
    
    - Start a new conversation in the chat interface
        
    - Wait for approximately 1 minute for the conversation to be processed
        
3. **Intercept and Modify Request**
    
    - Click on the chat again to generate a new request
        
    - Intercept the request using browser developer tools or proxy tool
        
    - Remove all query parameters from the intercepted request
        
4. **Verify Data Leakage**
    
    - Forward the modified request
        
    - Examine the response to observe leaked chat conversations from other customers
        

### Method 2: Via Burp Suite

1. **Authentication**
    
    - Use the provided raw request file
        
    - Insert your valid JWT token into the authorization header
        
    - Send the request to the AI agents endpoint
        
2. **Extract Run ID**
    
    - Observe the unusually large response
        
    - Copy the `runId` UUID value from the response
        
3. **Query Chat Data**
    
    - Use the provided "check response" raw request template
        
    - Insert the extracted `runId` into the request query parameters
        
    - Send the request
        
4. **Confirm Data Leakage**
    
    - Review the response containing leaked chat conversations from multiple customers