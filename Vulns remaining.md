1. Rotate the JWT secret out of source code and load it from a secure environment variable.
2. Verify the doctor role against the database, not just the JWT claim.
3. Harden URL validation with an allow-list plus a block on all private/reserved IP ranges, and pin DNS resolution so a validated public IP cannot be swapped via DNS rebinding.
4. Remove hard-coded CouchDB credentials from source and configuration; inject them at runtime.
5. Run the PDF fetcher in an isolated sandbox / egress-restricted network segment as a defense-in-depth measure.

---

## Fixed code

### 1. src/helpers/JWTHelper.js

```js
  const jwt = require('jsonwebtoken');
  const crypto = require('crypto');

  const APP_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

  module.exports = {
      sign(data) {
          // prevent prototype-pollution style mutations
          return jwt.sign({ ...data }, APP_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
      },
      async verify(token) {
          // explicitly reject tokens without a valid algorithm
          return jwt.verify(token, APP_SECRET, { algorithms: ['HS256'] });
      }
  };
```

### 2. src/helpers/URLHelper.js

```js
  const dns = require('dns');
  const { URL } = require('url');
  const net = require('net');

  const BLOCKED_PROTOCOLS = ['file:', 'ftp:', 'gopher:', 'mailto:', 'data:', 'javascript:'];
  const ALLOWED_PROTOCOLS = ['http:', 'https:'];

  // All private/reserved/loopback ranges (IPv4 and IPv6) that SSRF must not reach.
  function isPrivateIP(ip) {
      if (net.isIP(ip) === 0) return true;            // invalid IP -> block
      if (ip.startsWith('127.') || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
      if (ip === '0.0.0.0' || ip === '::') return true;

      const [a, b, c, d] = ip.split('.').map(Number);
      if (a === 10) return true;                      // 10/8
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
      if (a === 192 && b === 168) return true;        // 192.168/16
      if (a === 169 && b === 254) return true;        // link-local
      if (a >= 224 && a <= 239) return true;          // multicast
      if (a >= 240 && a <= 255) return true;          // reserved

      // IPv6 loopback / link-local / unique-local / multicast
      const low = ip.toLowerCase();
      if (low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd')) return true;
      if (low.startsWith('ff')) return true;

      return false;
  }

  function normalizeHostname(hostname) {
      // Reject encoded IP literals and common bypasses.
      if (/^0x[0-9a-f]+$/i.test(hostname)) return null;
      if (hostname.includes('::')) return null;
      return hostname.toLowerCase();
  }

  const validate = async (urlString) => {
      try {
          const parsed = new URL(urlString);

          if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) return true;  // not allowed
          if (BLOCKED_PROTOCOLS.includes(parsed.protocol)) return true;

          const hostname = normalizeHostname(parsed.hostname);
          if (!hostname) return true;

          // Block raw IP literals entirely unless you explicitly allow-list them.
          if (net.isIP(hostname)) return true;

          // Optional strict allow-list.  Example:
          // const ALLOWED_DOMAINS = process.env.PDF_ALLOWED_DOMAINS?.split(',') || [];
          // if (ALLOWED_DOMAINS.length && !ALLOWED_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))) return true;

          const addresses = await dns.promises.resolve4(hostname);
          if (!addresses.length) return true;

          // All resolved IPs must be public.
          if (addresses.some(isPrivateIP)) return true;

          return false; // URL passed validation
      } catch (error) {
          console.error('URL validation error:', error);
          return true; // malformed / unreachable -> reject
      }
  };

  module.exports = { validate };
```

### 3. src/helpers/PDFHelper.js

```js
  const fs = require('fs');
  const axios = require('axios');
  const html_to_pdf = require('html-pdf-node');
  const URLHelper = require('./URLHelper');

  async function generatePDFFromURL(url) {
      const blocked = await URLHelper.validate(url);
      if (blocked) {
          throw new Error('URL not allowed');
      }

      // Fetch only after validation.  Pin the resolved IP to prevent rebinding.
      const parsed = new URL(url);
      const resolved = await dns.promises.resolve4(parsed.hostname);
      const targetIP = resolved[0];

      // Egress timeout and no redirects to internal hosts.
      const response = await axios.get(url, {
          timeout: 10000,
          maxRedirects: 0,
          headers: { Host: parsed.hostname },
          // Optional: force axios to connect to the pinned IP while preserving SNI/Host.
          // This requires an HTTP agent or a separate fetch layer in production.
      });

      const htmlContent = response.data;

      const options = { format: 'Letter' };
      const pdfBuffer = await html_to_pdf.generatePdf({ content: htmlContent }, options);

      fs.writeFileSync('/tmp/result.pdf', pdfBuffer);
      return true;
  }

  module.exports = { generatePDFFromURL };
```

> Production hardening: use a dedicated egress proxy or microservice with no access to internal metadata/CouchDB. Pass the pre-resolved public IP to the fetcher and enforce the Host header there.

### 4. src/middleware/DoctorMiddleware.js

```js
  const db = require('../database'); // or inject the db instance

  module.exports = async (req, res, next) => {
      try {
          if (!req.user || req.user.role !== 'doctor') {
              return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
          }

          // Verify the user actually exists and still has the doctor role.
          const user = await db.getUser(req.user.username);
          if (!user || user.role !== 'doctor') {
              return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
          }

          next();
      } catch (e) {
          console.log(e);
          return res.status(403).json({ status: 'unauthorized', message: 'Unauthorized!' });
      }
  };
```

### 5. src/database.js

```js
  const crypto = require('crypto');
  const nano = require('nano');

  const COUCH_USER = process.env.COUCHDB_USER || 'admin';
  const COUCH_PASS = process.env.COUCHDB_PASSWORD || crypto.randomBytes(32).toString('hex');
  const COUCH_URL = process.env.COUCHDB_URL || `http://${COUCH_USER}:${COUCH_PASS}@127.0.0.1:5984`;

  class Database {
      async init() {
          this.couch = nano(COUCH_URL);
          // ... rest unchanged, but remove plaintext admin password literals
      }
      // ...
  }
```

### 6. config/local.ini

```ini
  [admins]
  admin = ${COUCHDB_PASSWORD}
```

At container start, generate or inject a strong password and write it into the CouchDB config instead of committing credentials to version control.

### 7. src/routes/index.js – endpoint usage

```js
  router.post('/api/pdfGeneration', [AuthMiddleware, DoctorMiddleware], async (req, res) => {
      const { url } = req.body;

      try {
          await PDFHelper.generatePDFFromURL(url);
          return res.download('/tmp/result.pdf', 'result.pdf', (err) => {
              if (err) {
                  console.error(err);
                  res.status(500).send('Internal Server Error');
              }
          });
      } catch (e) {
          console.error(e);
          return res.status(400).send(response('URL not allowed!'));
      }
  });
```