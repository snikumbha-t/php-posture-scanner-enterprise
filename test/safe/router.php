<?php
header_remove('X-Powered-By');
header('Server: nginx');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
setcookie('app_session', 'xyz', ['secure'=>true,'httponly'=>true,'samesite'=>'Lax','path'=>'/']);
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri !== '/') { http_response_code(404); echo '<html>404 Not Found</html>'; exit; }
?>
<!doctype html><html><head><title>Secure Site</title></head>
<body><h1>Hello</h1><a href="/about.php">about</a></body></html>
