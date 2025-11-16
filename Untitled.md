# Proof of Concept - Method 2

## Overview

Since the site blocks browser access, use **Method 2** with the provided RAW request files.

---

## Prerequisites

- Two RAW request files:
    - `Start-conversation`
    - `check-conversation`
- Valid JWT token

---

## Steps to Reproduce

### Step 1: Prepare Request Files

Add your JWT token to **both** request files:

- `Start-conversation`
- `check-conversation`

### Step 2: Initiate Conversation

Send the request using the `Start-conversation` file.

- This starts a conversation with the AI

### Step 3: Extract Run ID

From the response:

- Copy the `runId` UUID

### Step 4: Retrieve Transcript

1. Paste the `runId` into the URL parameter in the `check-conversation` request file
2. Send the request

### Step 5: Review Results

- The response will contain the **call transcript**
- **Tip**: Use AI to parse and format the transcript for better readability

---

## Notes

- Both request files require authentication via JWT
- The `runId` is essential for linking the conversation check to the initiated session
- AI processing can help structure the leaked conversation data into a more readable format