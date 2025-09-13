## Summary

It is possible to access **posts that have been deleted by administrators** through the site’s API and public endpoints. These posts are marked with `"status":"ILLEGAL"` in the JSON response but are still fully retrievable, including their text content, author IDs, timestamps, and sometimes external links.

This behavior breaks user expectations of deletion, poses privacy risks, and undermines the moderation process.

## Affected Endpoints

1. Prompt pages (frontend):
    

```
GET /en/prompt/$prompt$
Host: www.italki.cn
```

2. API endpoint exposing all prompts:
    

```
https://api.italki.cn/api/v3/community/prompts_recommends?length=9999&offset=0&sort_by=order
```

From these endpoints, deleted posts are still accessible in the JSON response.

## Steps to Reproduce

1. Visit the API endpoint:
    
    ```
    https://api.italki.cn/api/v3/community/prompts_recommends?length=9999&offset=0&sort_by=order
    ```
    
    → This returns a list of all prompts with their IDs.
    
2. Open any prompt page with:
    
    ```
    GET /en/prompt/{prompt_id}
    Host: www.italki.cn
    ```
    
3. Inspect the `__NEXT_DATA__` JSON response.
    
    - Observe that posts with `"status":"ILLEGAL"` (deleted by admins) are still present.
        
    - Example (redacted for sensitive content):
        
    
    ```json
    {
      "scope":"post",
      "data":{
        "id":"LJHCjPuTFbKgLap59irlai",
        "create_at":"2022-05-11T10:22:43Z",
        "author_id":"9778385",
        "status":"ILLEGAL",
        "content":"Ciao ragazzi! hi guys, olá pessoal! ... [Instagram link]",
        "written_language":"italian"
      }
    }
    ```
    
    Another example (offensive content redacted):
    
    ```json
    {
      "scope":"post",
      "data":{
        "id":"57xuzzhLrVJNYi0eUEiX0O",
        "create_at":"2022-05-10T17:28:43Z",
        "author_id":"11915535",
        "status":"ILLEGAL",
        "content":"[Redacted offensive content]",
        "written_language":"english"
      }
    }
    ```
    

## Impact

- **Privacy risk**: Deleted posts may contain personal data (names, contact info, photos, opinions) that users/admins intended to remove.
    
- **Compliance risk**: This may violate data protection laws (e.g., GDPR right-to-erasure, CCPA).
    
- **Moderation bypass**: Harmful or illegal content that admins attempted to remove remains publicly accessible, undermining trust and site safety.
   

## Recommendation

- Implement **hard deletion** (removal from database and API responses) instead of just marking posts as `"ILLEGAL"`.
    
- Ensure that deleted content is excluded from all user-facing and public API responses.
    
- Consider maintaining a secure, internal-only archive for moderation/legal purposes if necessary.
    

