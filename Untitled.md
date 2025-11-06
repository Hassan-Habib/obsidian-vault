**Summary**
Ai Agent leaks random customer chats after initiating a conversation with it

**Steps to Reproduce:**

1. **Account Creation & Initial Access**
    
    - Create a user account on the staging environment
        
    - Navigate to: `https://staging-prime.navan.com/app/assist/?projectId=git%3A%2F%2Fandrey-faq%2Fanalysis%2Fandrey-faq.json`
        
    - Ensure you're accessing the `andrey-faq` branch and `andrey-faq.json` AI agent
        
2. **Initiate Conversation**
    
    - Start a conversation with the AI agent ( while intercept is on)

for some reason the POC video aint uploading , so ill upload it in comments 
        
3. **Intercept and Modify Request**
    
    - Open Burp Suite and send the request to repeater
        
    - Modify the body param value from `false` to `true`
        
    - Forward the modified request
        
4. **Observe Information Disclosure**
    
    - The initial response will show: `"User requested chat data; {number} results returned"`
        
    - Wait approximately 1 minute for the full data processing
        
    - Observe that the response now includes other customers' chat conversations with support
        
    - Note that sensitive customer data and support interactions are exposed
        


    
**Notice**
the site is blocking me through cloudflare for some reason so the POC will be via burp requests

**For some reason i cant upload the POC video in the report , so ill upload it in the comments**