<?php
header('X-Powered-By: PHP/7.2.5');
header('Server: Apache/2.4.29 (Ubuntu) PHP/7.2.5');
setcookie('PHPSESSID', 'abc123', 0, '/');
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
// Deliberately expose sensitive files (simulating a misconfigured server).
$serve = [
  '/.env' => ["DB_PASSWORD=supersecret123\nAPP_KEY=base64:xxxx\n", 'text/plain'],
  '/.git/config' => ["[core]\n\trepositoryformatversion = 0\n", 'text/plain'],
  '/.git/HEAD' => ["ref: refs/heads/main\n", 'text/plain'],
  '/composer.json' => ['{"require":{"laravel/framework":"5.4"}}', 'application/json'],
  '/phpinfo.php' => ["<html><title>phpinfo()</title>PHP Version 7.2.5 Zend Engine</html>", 'text/html'],
];
if (isset($serve[$uri])) {
  header('Content-Type: ' . $serve[$uri][1]);
  echo $serve[$uri][0];
  exit;
}
if ($uri === '/wp-login.php') { echo '<form>user_login</form>'; exit; }
?>
<!doctype html><html><head>
<meta name="generator" content="WordPress 5.4.1">
<title>My PHP Site</title></head><body>
<h1>Welcome</h1><p>Powered by wp-content and wp-includes.</p>
<a href="/index.php?p=1">home</a> <a href="/login.php">login</a>
<pre>Warning: include(config.php): failed to open stream on line 42</pre>
</body></html>
