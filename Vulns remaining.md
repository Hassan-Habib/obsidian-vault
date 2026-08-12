### Primary Fix: Implementation of Parameterized Queries

The vulnerability stems from user input being directly concatenated into the SQL statement via Python string formatting:

Python

```
# Vulnerable Code:
cursor.execute("SELECT user_id FROM users WHERE email = '%s'" % (email,))
```

To fix this, the raw string formatting must be replaced with a parameterized query. Passing the `email` value as a separate argument ensures the database driver treats it strictly as data, preventing the engine from executing arbitrary SQL payload structures:

Python

```
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    ...
    else:
        email = request.form.get('email', '').strip()
        
        if email:
            with db.connect() as conn:
                cursor = conn.cursor()
                # Correct Fix: Parameterized query using placeholders
                cursor.execute(
                    "SELECT user_id FROM users WHERE email = %s",
                    (email,)
                )
                row = cursor.fetchone()
                ...
```

### Additional Defensive Recommendations

#### 1. Eliminate Blacklist-Based Filters

Remove reliance on custom decorators like `@anti_sqli`. Blacklist filters are easily bypassed because attackers can construct alternative SQL payloads. Parameterized queries should serve as the primary and only defense against SQL injection.

#### 2. Apply Parameterization Universally across Codebase

Ensure prepared statements or an Object-Relational Mapper (ORM) are used consistently across all database operations—including login, account settings, admin panels, and API endpoints—to eliminate similar hidden vulnerabilities elsewhere in the application.

#### 3. Implement Strict Input Validation

Validate that incoming parameters conform to expected formats before submitting them to the database handler. In this case, ensure the string is a valid email format before processing:

Python

```
import re

email_regex = re.compile(r'^[^@]+@[^@]+\.[^@]+$')

if not email_regex.match(email):
    return redirect(url_for('forgot', e='Invalid email address'))
```

#### 4. Enforce the Principle of Least Privilege

Restrict database user account permissions to only what is required for standard application function. The database user used by the Web app should not have elevated schema alteration, system command, or unnecessary write capabilities across unrelated tables.

#### 5. Set Up Logging & Abnormal Delay Alerts

Monitor application logs for suspicious characters or payload structures. Establish alerts for anomalous database response latencies (e.g., responses taking over 5–10 seconds), which typically signal active time-based blind SQL injection attempts.

#### 6. Retesting & Verification

Following implementation of the patch, the pentester should re-run the original time-based exploitation scripts to verify that response times remain consistent and data extraction is no longer possible.