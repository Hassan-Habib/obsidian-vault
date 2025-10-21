## Setup

You need two accounts (privilege level does **not** matter — admin or normal user).

## Steps

`As the attacker`

### Flight selection

1. Sign in to Navan:
    

> `https://staging-prime.navan.com/app/user2/auth`

**Obtaining UUID of the victim**
2. Go to group travel page:
    

> `https://staging-prime.navan.com/app/user2/group-travel/landing-page`

3. Click **Create event**, and add the needed info (event name, event type, location and start and end date — it doesn't matter what info you insert). Press **Save and continue**.
    
4. Go to **Participants** tab and click **Add participants** => **Add participants manually**.
    
5. Type the victim email => choose it from below => click **Add participants**.
    
6. Intercept the request to:
    

> `https://staging-prime.navan.com/api/v1/user/travel-events/a4a1c9f6-f9d2-40d2-bec2-96ea50df5651/invitations/bulk-create`  
> and check the response.

7. Notice the victim UUID is supplied in the response.
    
8. Example response (truncated):
    

```json
{
  "invitationReports" : [ {
    "progressStatus" : {
      "progressPercent" : 100,
      "status" : "FINISHED",
      "error" : null
    },
    "invitationId" : "74f6fbbf-b897-409a-8898-b991f179da3f",
    "participantId" : "9d201ba2-04d3-4d7f-8d57-5e45dcda952b",
    "participantEmail" : "bold-wood-9978@bugcrowdninja-125.com"
  } ]
}
```

**Obtaining victim PII**

9. Go to **Home** and select a flight (From, To, departure/return times do not matter).
    
10. Proceed to pick any flight any class (the flight **must** have the option to change or add seats — you only know if this feature is available at checkout).
    

### Checkout & seat selection

11. When you reach the **Flight Services** section, click **Add seats**.
    
12. Turn on intercept in Burp and choose any seat — this is the request that will be sent when a seat is chosen:
    

> `https://staging-prime.navan.com/api/v1/trip/flight/searches/2e753bf0-3c30-4e58-8da4-551e36fc70ca/contracts/a79ea2e3-5216-4f5a-9301-b9aaa80a5435/flightsegments/0/selectseat?fullSeatMap=true&seat=2D`

13. In the intercepted request, change the `passengerUuid` to the victim UUID (can be fetched from invited users to trips, invited company members).
    
14. Send the modified request and notice the response returns PII related to the victim.