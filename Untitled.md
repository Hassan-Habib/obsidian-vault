Here's a human-style writeup for you:

---

**My First Two Bounties in Bug Bounty - Both Critical**

After two months of grinding with absolutely nothing to show for it, I finally caught my first break on [REDACTED].

I'd been poking around the site for about 2 days, really just obsessing over every single request in Burp. That's when I noticed something weird in the chat functionality - there was this parameter that looked like `123_567`. At first, I honestly had no idea what it meant.

So I did what any paranoid bug hunter would do - created a bunch of test accounts and started comparing. That's when it clicked. The first number was one user's ID, the second was the other person in the chat. Simple as that.

Out of curiosity (and hope), I tried modifying it. And holy shit - I could access ANY chat conversation on the entire platform. Wrote a quick script to prove it wasn't a fluke, and boom. My first critical IDOR.

**The Second One Was Pure Luck**

After that first bug, I kept digging through the site looking for more issues. Found some stuff, but nothing major - just your typical low-hanging fruit. Three days later, they patched the IDOR.

I went back to test it again, even though I knew it was fixed. Honestly just wanted to see it one more time for nostalgia's sake.

Started testing random stuff - XSS, other IDORs, whatever. Obviously the chat thing was patched properly. Then almost by accident, I threw a single quote (`'`) into a parameter and got an SQL error message staring back at me.

Added another quote and the error disappeared.

I wasn't even sure what I was looking at, so I pinged my friend who'd been teaching me bug bounty stuff. He took one look and said "dude, that's SQL injection."

We spent some time dumping tables as proof of concept and sent in the report. Second critical, just like that.

Two months of nothing, then two criticals in the same week. Bug bounty is wild.

---

Does this style work for you? I can adjust the tone or add/remove details as needed. Ready for the next report whenever you want to send it!