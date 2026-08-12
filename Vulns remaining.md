## Primary Fix — Correct the API Key Validation Logic

The `api_key_required` decorator must check the actual parameter or header value, not a substring of the raw query string. Replace the flawed logic in `www/__init__.py:36-47`.

### Option A: Fix the Existing Query-Parameter Approach



```python
def api_key_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        api_key = request.args.get('key')
        if not api_key:
            return "Forbidden: Missing API key", 403
        if api_key != os.getenv('API_SECRET'):
            return "Forbidden: Incorrect API key", 403
        return f(*args, **kwargs)
    return decorator
```

**This ensures:**

- Only a parameter literally named `key` is accepted.
    
- An empty or missing key returns `403`.
    
- The value is securely compared against `API_SECRET`.
    

### Option B: Move the API Key to a Request Header (Recommended)

Query-string API keys are logged by proxies, browsers, and web servers. Use an `Authorization` header or custom `X-API-Key` header instead:



```python
def api_key_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return "Forbidden: Missing API key", 403
        if api_key != os.getenv('API_SECRET'):
            return "Forbidden: Incorrect API key", 403
        return f(*args, **kwargs)
    return decorator
```

## Add Authentication and Authorization to `/api/changeUserRole`

The endpoint must verify that the caller is logged in and has administrative privileges. The API key alone should **not** grant access to role changes.



```python
@app.route('/api/changeUserRole', methods=['POST'])
@login_required
@admin_required
def api_changeUserRole():
    user_id = request.form.get('user_id')
    role_id = request.form.get('role_id')
    
    if not user_id or not role_id:
        return "Missing parameters", 400
        
    with db.connect() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE user_roles SET role_id = %s WHERE user_id = %s', (role_id, user_id))
        conn.commit()
        
    return "OK"
```

### Key Changes:

- **`methods=['POST']`**: Role changes are state-modifying actions and must not use `GET`.
    
- **`@login_required`**: Ensures a valid session exists.
    
- **`@admin_required`**: Ensures only administrators can modify user roles.
    

### Example Decorators:



```python
def login_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = auth.parse_token(request.cookies.get(auth.cookie_name))
        if not token:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorator

def admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = auth.parse_token(request.cookies.get(auth.cookie_name))
        if not token or not auth.is_admin(token['email']):
            return "Forbidden: Admin access required", 403
        return f(*args, **kwargs)
    return decorator
```

## Rotate the API Secret

> **Critical Note:** Because the original `API_SECRET` was exposed in version-control history, rotate it immediately in your environment variables and treat the old value as fully compromised.

## Apply the Same Fix to All API Endpoints

The same authentication bypass affects multiple endpoints:

- `/api/changeUsername` (`www/__init__.py:205`)
    
- `/api/changeUserPassword` (`www/__init__.py:222`)
    
- `/api/changeUserRole` (`www/__init__.py:241`)
    

### Implementation Standards for Endpoints:

1. Use `POST`, not `GET`.
    
2. Require a valid user session.
    
3. Enforce proper authorization checks (IDOR prevention).
    
4. Accept `user_id` modifications **only from administrators**; normal users should only be permitted to modify their own active account session.
    

### Example for Non-Admin User Endpoints:



```python
@app.route('/api/changeUsername', methods=['POST'])
@login_required
def api_changeUsername():
    new_username = request.form.get('username')
    token = auth.parse_token(request.cookies.get(auth.cookie_name))
    
    if not new_username:
        return "Missing username parameter", 400
        
    with db.connect() as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET username = %s WHERE email = %s', (new_username, token['email']))
        conn.commit()
        
    return "OK"
```