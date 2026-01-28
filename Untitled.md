This is a great catch. You’ve identified a **Broken Access Control** flaw, specifically a **Session Persistence/Inadequate Authorization Revocation** issue. Even though the platform (Visio-Sandbox) is using LiveKit (a robust WebRTC stack), the custom business logic handling the "Lobby" is failing to invalidate permissions upon a "Kick" action.

Here is a professional bug report formatted for a security disclosure or a bug bounty platform.

---

## Vulnerability Report: Inadequate Authorization Revocation (Bypass of Lobby Restrictions)

### **Summary**

The "Kick Out" functionality in the meeting room fails to revoke the user's authorization state on the server side. Once a participant has been accepted into a restricted meeting once, they can bypass the "Lobby/Waiting Room" and rejoin the meeting automatically, even after being explicitly expelled by an administrator.

### **Vulnerability Details**

- **Vulnerability Type:** Broken Access Control / Business Logic Flaw
    
- **Severity:** Medium (CVSS: 5.4 - `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`)
    
- **Affected Endpoint:** `POST /api/v1.0/rooms/{room-id}/request-entry/`
    
- **Platform:** `visio-sandbox.beta.numerique.gouv.fr`
    

### **The Root Cause**

The server-side logic checks the `lobbyParticipantId` or the existing `sessionid`. If the ID was previously marked as "accepted," the `request-entry` endpoint immediately returns a **200 OK** with a fresh LiveKit JWT token rather than placing the user back into a "waiting" state. The "Kick" action removes the user from the current socket connection but does not reset the participant's status in the database to `denied` or `pending`.

---

### **Steps to Reproduce (PoC)**

1. **Attacker:** Request entry to a restricted room:
    
    `POST /api/v1.0/rooms/tes-test-tes/request-entry/` with `{"username":"asd"}`.
    
2. **State:** Response shows `status: waiting`.
    
3. **Victim (Admin):** Accepts the user "asd" by mistake or for a limited time.
    
4. **Attacker:** Receives a JSON response containing the `livekit` token and successfully joins the call.
    
5. **Victim (Admin):** Uses the "Kick" button to remove "asd" from the meeting.
    
6. **Attacker:** Refresh the page or re-send the same `POST` request to the `/request-entry/` endpoint.
    
7. **Result:** The server immediately returns a new JWT token (`status: accepted`), allowing the attacker to rejoin without the Admin seeing a new request in the lobby.
    

---

### **Impact**

An unauthorized individual can maintain persistent access to a private meeting. If an admin kicks a participant for disruptive behavior or because sensitive information is about to be shared, that individual can "ghost" back into the meeting instantly. This undermines the primary security control of the "Lobby" feature.

---

### **Recommended Remediation**

1. **State Reset on Kick:** When an admin "Kicks" a user, the backend must update that participant's record (associated with their `sessionid` or `lobbyParticipantId`) from `accepted` to `kicked` or `denied`.
    
2. **Authorization Re-evaluation:** Ensure the `/request-entry/` logic explicitly checks if a user has been expelled before issuing a new LiveKit JWT.
    
3. **Token Invalidation:** (Optional but Recommended) Integrate with the LiveKit server to invalidate the specific JWT issued to that user immediately upon the "Kick" action.
    

---

**Would you like me to help you find the specific security contact or "HackerOne" page for the French Government's digital services to report this?**