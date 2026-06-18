# How Parameter Tampering Exposed 4,700 Agents and Tons of PII

**Free Palestine**

While testing on a target platform, I hit that classic wall where everything seems like i’ve tested before. I had already found a couple of vulnerabilities (which I’ll write up later), but the main application felt completely safe now.

When that happens, I look where I usually don’t: **the support chat**. I threw standard payloads at it — XSS, malicious file uploads — but nothing. So, I decided to dig into the background HTTP traffic to see how the chat session was actually getting initialized.

## 🛠️ The Entry Point: Parameter Tampering

Looking at the initialization request for the chat window, I noticed a parameter in the JSON body:

JSON

```
{
  "tester": false
}
```

Naturally, I changed it to `true` and re-sent the request.

The application accepted it. Instead of the standard customer service bot, a completely different internal development AI agent loaded into my chat window. I began messing around with its prompts, and after a few tries, the agent casually gave me a url to an endpoint.

As it turns out, this endpoint could have been found with some basic directory brute-forcing during reconnaissance, but I had missed it. When I navigated to the leaked path, I was greeted by an unauthenticated directory listing roughly **4,700 AI agents**.

## 🪦 Navigating the Agent Graveyard

The naming conventions of these agents instantly signaled high-value targets. I saw names like:

- `Support Chat AI Agent`
    
- `Cancel **** AI Agent`
    
- `Root AI Agent`
    

I started testing one of the support chat agents. It was incredibly stupid; it required a very specific conversation flow, and if you didn’t provide the exact phrase it wanted, the session would automatically close.

After about 20 attempts, I figured out the exact syntax it expected:

Plaintext

```
Me: Hi
Agent: Hi there what do you wan to explore today
Me: support chat
Agent: which filter do you want to apply
Me: Time range last 2 days
```

The moment I supplied the time range, the agent served up a file containing over 2,000 raw customer support chats. The logs were packed with plaintext emails, flight details, phone numbers, and full names. That was just a 2-day filter — requesting 2 years’ worth of data would have dumped the entire history.

## 🤖 Automating the Triage (Filtering 4,700 Targets)

If one agent was this insecure, I assumed the other 4,700 were just as vulnerable. However, manually testing thousands of broken or duplicated bots was just stupid. Many agents were just older versions left online when developers pushed updates.

I needed a way to isolate unique, active agents. I noticed that when you message a working agent — even if you send a junk payload that crashes it — the server instantly generates a `session_id`.

I wrote a quick Python script to automate the triage:

1. Parse the endpoint to scrape all agent locations.
    
2. Deduplicate the list based on agent names and versions.
    
3. Send an initial `"Hi"` request to each unique agent.
    
4. Check the response for a valid `session_id`. If found, save the agent's identifier and URL to a clean target list.
    

The script narrowed the attack surface down to **700 active, unique AI agents**.

## 🔍 The Findings

I went through and tested every single one of those 700 filtered agents. It was a massive haul of data and high-severity issues, though almost all of them ultimately came back flagged as duplicates by the platform:

- **Stored XSS:** Found within an agent’s UI, leading to a zero-click Account Takeover (ATO) _(Duplicate)_.
    
- **Mass Support Log Leaks:** 10 other separate agents were vulnerable to the same database dumping trick, exposing customer logs _(Duplicate)_.
    
- **Admin Credentials:** Active, valid Administrator JSON Web Tokens (JWTs) exposed in development agent configs _(Duplicate)_.
    
- **Internal Communications:** Full text call transcripts between the company and its customers _(Duplicate)_.
    
- **Sensitive Travel PII:** Deep customer travel details, including precise flight times and hotel stay locations _(Duplicate)_.
    
- **BOLA / IDOR:** One agent allowed me to directly modify the internal shift schedules of actual employees _(Marked as Informational)_.
    

> 💔 P1 Duplicates BREAK MY HEART :(

## 🎯 Takeaway

Even though the platform ended up slapping a “Duplicate” label on almost the entire which feels as a scam

The only reward i got from it