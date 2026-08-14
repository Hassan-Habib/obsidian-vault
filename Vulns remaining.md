The chain relies on four weak points. Patch all of them; removing only one may still leave another path open.

---

## 1. Pi-hole default credentials

Change the WEBPASSWORD in DNS-Server-master/dns-server/docker-compose.yml to a strong, randomly generated secret injected at deploy time, and do not expose the admin UI publicly.

```yaml
  environment:
    WEBPASSWORD: ${PIHOLE_PASSWORD}
```

---

## 2. Pin DNS resolution for bot / PDF fetches

The bot in /api/documentSubmit currently passes the user URL straight to bot.checkMessage(url) with no IP pinning. Reuse the same pinning logic for both the PDF helper and the document-review bot.

**src/helpers/URLHelper.js — resolve, pin, and validate**

```javascript
  const dns = require('dns');
  const url = require('url');
  const { promisify } = require('util');
  const dnsLookup = promisify(dns.lookup);

  const BLACKLIST = ['127.0.0.1', '::1', '::ffff:127.0.0.1', '0.0.0.0'];

  async function resolveAndPin(targetUrl) {
      const parsed = new URL(targetUrl);

      if (!['http:', 'https:'].includes(parsed.protocol)) {
          throw new Error('Invalid protocol');
      }

      // Resolve once and pin the IP
      const { address } = await dnsLookup(parsed.hostname);

      if (BLACKLIST.includes(address)) {
          throw new Error('URL not allowed');
      }

      // Rebuild URL using the pinned IP so no second DNS lookup happens
      const pinnedUrl = `${parsed.protocol}//${address}${parsed.port ? ':' + parsed.port : ''}${parsed.pathname}${parsed.search}`;

      return {
          url: pinnedUrl,
          headers: { Host: parsed.hostname },
          originalHostname: parsed.hostname
      };
  }

  module.exports = { resolveAndPin };
```

**src/helpers/PDFHelper.js — use the pinned URL**

```javascript
  const fs = require('fs');
  const axios = require('axios');
  const html_to_pdf = require('html-pdf-node');
  const { resolveAndPin } = require('./URLHelper');

  async function generatePDFFromURL(targetUrl) {
      const { url, headers } = await resolveAndPin(targetUrl);

      const response = await axios.get(url, {
          headers,
          timeout: 5000,
          maxRedirects: 0
      });

      const htmlContent = response.data;
      const file = { content: htmlContent };

      const pdfBuffer = await html_to_pdf.generatePdf(file, { format: 'Letter' });
      fs.writeFileSync('/tmp/result.pdf', pdfBuffer);

      return true;
  }

  module.exports = { generatePDFFromURL };
```

**src/routes/index.js — validate document URLs before the bot visits them**

```javascript
  const { resolveAndPin } = require('../helpers/URLHelper');

  router.post('/api/documentSubmit', [AuthMiddleware, JOImiddleware(schemas.url)], async (req, res) => {
      const { url } = req.body;

      try {
          await resolveAndPin(url);   // rejects loopback / invalid URLs
      } catch (e) {
          return res.status(400).send(response('URL not allowed!'));
      }

      await db.addDocument(req.user.username, url);
      bot.checkMessage(url);

      return res.send(response('Document submitted!'));
  });
```

Also sandbox the bot. The bot should run in a separate cookie jar / browser profile with no admin session, so even if it loads attacker content it cannot modify admin settings.

---

## 3. Fix stored XSS in profile rendering

Remove the | safe filter everywhere user.full_name is rendered. Nunjucks autoescape: true will then encode the value safely.

**src/views/dashboard.html**

```html
  <!-- before -->
  <option value="{{user.full_name}}">{{ user.full_name | safe }}</option>

  <!-- after -->
  <option value="{{user.full_name}}">{{ user.full_name }}</option>
```

**src/views/settings.html**

```html
  <!-- before -->
  <option value="{{ user.full_name | safe }}">{{ user.full_name | safe }}</option>
  <input value="{{ user.full_name }}" ...>

  <!-- after -->
  <option value="{{ user.full_name }}">{{ user.full_name }}</option>
  <input value="{{ user.full_name }}" ...>
```

**src/views/pdfgen.html**

```html
  <!-- before -->
  <option value="{{ user.full_name | safe }}">{{ user.full_name | safe }}</option>

  <!-- after -->
  <option value="{{ user.full_name }}">{{ user.full_name }}</option>
```

---

## 4. Add CSRF protection to state-changing endpoints

Set the session cookie with SameSite=Strict, HttpOnly, and Secure, and validate an anti-CSRF token on POST /api/settings.

**src/routes/index.js — secure cookie at login**

```javascript
  let token = JWTHelper.sign({ username: username, role: data.role });
  res.cookie('session', token, {
      maxAge: 3600000,
      httpOnly: true,
      sameSite: 'strict',
      secure: true
  });
```

**CSRF token generation and validation**

Add a middleware that compares a token from the request body/header against the value stored server-side for the session:

```javascript
  function csrfProtection(req, res, next) {
      const submitted = req.headers['x-csrf-token'] || req.body._csrf;
      if (!submitted || submitted !== req.user.csrfToken) {
          return res.status(403).send({ message: 'Invalid CSRF token' });
      }
      next();
  }
```

Include the token in the JWT payload when signing, and require it on POST /api/settings:

```javascript
  router.post('/api/settings', [AuthMiddleware, csrfProtection], async (req, res) => {
      const { full_name, address } = req.body;
      // ...
  });
```

---

## 5. Harden body-parser

Remove the type: () => true override so JSON endpoints only accept application/json:

```javascript
  app.use(bodyParser.json());
```

This prevents simple cross-origin text/plain fetch CSRF against JSON endpoints.

---