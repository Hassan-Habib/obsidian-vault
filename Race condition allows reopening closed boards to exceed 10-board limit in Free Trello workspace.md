

## Summary

A race condition in the board reopen/create flow allows a Free-tier workspace to exceed the documented limit of **10 active boards**. By closing the existing 10 boards and then issuing multiple concurrent `PUT /1/boards/{board-id}` reopen requests , an attacker can cause the backend to accept multiple reopens and reach unlimited active boards in the workspace.

This bypasses plan enforcement for the Free workspace's board limit. The issue appears to be caused by a non-atomic limit check when boards are reopened/created concurrently.

## Impact

- Business logic enforcement bypass: Free workspace may end up with more than the stated 10 active boards.
    

---

## Steps to reproduce (minimal, repeatable)

> **Precondition:** Use a Free workspace (confirm in Workspace settings → Billing). Create 10 active boards.

1. Create 10 boards in a Free workspace and confirm there are exactly 10 active boards.
    
2. Close (archive) the 10 boards using the UI or API so they become closed/archived.
    
3. Create an additional <10 new boards (so the workspace has 9 or less newly-created active boards in addition to 10 closed boards).
    
4. Capture a valid `PUT /1/boards/{board-id}` request that reopens a closed board (use DevTools or Burp).  The request body looks like:
    

```
PUT /1/boards/$BOARD_ID$
Host: trello.com
Content-Type: application/json

{"closed":false,"keepBillableGuests":true,"idOrganization":"$ORG_ID$","dsc":"$DSC_VALUE$"}
```

5. Using the captured request as a template, issue **multiple parallel** `PUT` requests to reopen several closed boards at the same time . 
    
6. Now you have over 10 open boards 
    
