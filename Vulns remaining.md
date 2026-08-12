Here is the organized section formatted in clean, human-written Markdown for your report:

## Finding: Hardcoded Secrets Exposed via Git Repository History

### Description

During the repository analysis, the pentester discovered that the application’s full `.env` configuration file was committed in the initial Git commit. This file contained critical operational credentials, including database access passwords, keys used to sign Flask sessions, cookie authentication secrets, and administrative API keys.

Although the `.env` file was modified or removed in subsequent commits, the original secrets remain fully accessible within the repository’s commit history.

Because these security-sensitive values were exposed together, an attacker with repository access can chain them to achieve complete application compromise. Most notably, extracting `AUTH_SECRET` and `API_SECRET` allows for unauthenticated account takeovers and complete administrative privilege escalation.

### Root Causes

#### 1. Commit of Production Secrets to Source Control

The `.env` file was included in the initial codebase commit. Version control systems retain full historical file contents even after a file is deleted or modified in later commits, leaving the credentials permanently exposed unless the Git history is rewritten or purged.

#### 2. Reliance on Static, Unrotated Secrets

The application relies on static, long-lived secrets across its environment without runtime binding or regular rotation:

- **`AUTH_SECRET`**: Signs and verifies all authentication cookies.
    
- **`API_SECRET`**: Controls access to administrative API endpoints.
    
- **`APP_SECRET`**: Secures Flask session state and CSRF tokens.
    
- **`DB_PASS`**: Authenticates directly to the backend PostgreSQL database.
    

None of these secrets are rotated, restricted by IP/client context, or backed by a server-side session store. Compromising a single secret provides persistent unauthorized access; exposing the entire `.env` file grants complete system control.

#### 3. Lack of Infrastructure and Code Separation

Sensitive environment configuration was stored alongside application source code rather than being injected dynamically at runtime via a dedicated secrets manager, environment-specific deployment pipeline, or secure vault.