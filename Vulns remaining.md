### 1. Eliminate the `$where` Operator

Do **not** use MongoDB's `$where` operator with any user-controlled input. `$where` executes arbitrary JavaScript inside the database engine and cannot be safely parameterized, making it highly vulnerable to NoSQL Injection (SSJI).

Replace any raw `$where` evaluation with standard Eloquent query-builder lookups that use MongoDB's native comparison operators:

PHP

```
public function showVerifyEmail(Request $request)
{
    $request->validate([
        'email' => 'required|email',
        'token' => 'required|string|alpha_num|size:128',
    ]);

    $email = $request->input('email');
    $token = $request->input('token');

    $user = User::where('email', $email)->first();

    if (!$user) {
        return $this->invalidVerification();
    }

    $verificationToken = VerificationToken::where('userId', $user->id)
        ->where('token', $token)
        ->first();

    if ($verificationToken) {
        $user->update(['verified' => true]);
        $verificationToken->delete(); // One-time use

        session()->flash('status', 'Thank you, your email has been successfully verified');
        session()->flash('statusType', 'success');
        
        return view('verify-email');
    }

    return $this->invalidVerification();
}

private function invalidVerification()
{
    session()->flash('status', 'Invalid or expired verification link');
    session()->flash('statusType', 'danger');
    
    return view('verify-email');
}
```

### 2. Strict Input Validation

Validate and sanitize both `email` and `token` prior to performing database execution.

- Enforce strict typing (`string`, `alpha_num`).
    
- Require exact string lengths (`size:128`) to neutralize payload injection at the HTTP request layer before reaching MongoDB.
    

### 3. One-Time Token Use

Always invalidate or delete the `VerificationToken` document immediately after a successful status change. This prevents token replay attacks and limits exposure if tokens leak via web server access logs or browser history.

### 4. Token Expiration (TTL Check)

Ensure verification tokens are short-lived. Store a timestamp during token creation and check for expiration against a designated Time-To-Live (e.g., 24 hours):

PHP

```
$verificationToken = VerificationToken::where('userId', $user->id)
    ->where('token', $token)
    ->where('created_at', '>=', now()->subHours(24))
    ->first();
```

Alternatively, leverage MongoDB **TTL Indexes** on the `created_at` field to automatically purge expired documents at the database layer.

### 5. Rate Limiting

Apply Laravel's `throttle` middleware to the `/verify-email` endpoint to mitigate automated brute-force attacks and parameter tampering:

PHP

```
Route::get('/verify-email', [AuthController::class, 'showVerifyEmail'])
    ->middleware('throttle:5,1');
```

### 6. Use Signed URLs (Defense in Depth)

Consider replacing custom manual token logic with Laravel's native signed URLs (`URL::signedRoute()`) or the built-in `Illuminate\Auth\Notifications\VerifyEmail` notification class. Signed URLs use HMAC SHA-256 validation, eliminating the requirement to manually query or manage persistent tokens.

### 7. Audit Application-Wide Queries

Audit the codebase for similar vulnerable patterns. For instance, endpoints like `SearchController` that accept user input to construct raw MongoDB `Regex` objects can lead to **ReDoS (Regular Expression Denial of Service)** or injection bypasses. Ensure search parameters are passed through `preg_quote()` prior to building regex queries or transition to MongoDB Native Text Search.