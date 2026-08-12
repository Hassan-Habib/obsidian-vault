A successful SQL Injection (SQLi) attack targeting the `/forgot` endpoint allows an unauthenticated attacker to execute arbitrary SQL statements within the context of the application's PostgreSQL session.

Because the injected queries run with the privileges of the database user configured in `www/util/db.py`, an attacker can enumerate and exfiltrate data across all accessible databases, schemas, tables, and columns on the connected PostgreSQL instance.

### Database Schema Exposure (`royalflush`)

Within the primary application database (`royalflush`), the attacker can directly query and exfiltrate data from the following tables and columns:

|**Table**|**Column**|**Description / Impact**|
|---|---|---|
|**`users`**|`user_id`|Unique user identifier|
||`username`|Account login name|
||`password`|Hashed/plaintext user password|
||`email`|User email address|
||`created_on`|Account creation timestamp|
|**`roles`**|`role_id`|Role identifier|
||`role_name`|Name/level of privilege|
|**`user_roles`**|`user_id`|Foreign key linking user|
||`role_id`|Foreign key linking role|
|**`forgot`**|`token`|Active password reset token|
||`user_id`|Foreign key mapping token to user|
