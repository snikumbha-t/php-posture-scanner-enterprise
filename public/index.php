<?php
declare(strict_types=1);

/**
 * PHP Posture Scanner — single-file front controller.
 *
 * Routes:
 *   GET  /            → the form
 *   POST / (url=...)  → run scan, render HTML report
 *   POST /?format=json → run scan, return JSON
 *
 * Only passive checks are performed. See src/Scanner.php.
 */

use PvC\Scanner;
use PvC\Target;

require __DIR__ . '/../src/Scanner.php';

const RATE_LIMIT = 20;        // scans per window
const RATE_WINDOW = 3600;     // seconds

function rate_limited(): bool
{
    $dir = sys_get_temp_dir() . '/pvc_rate';
    @mkdir($dir, 0700, true);
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $file = $dir . '/' . preg_replace('/[^a-z0-9]/i', '_', $ip);
    $now = time();
    $hits = [];
    if (is_file($file)) {
        $hits = array_filter(
            (array)json_decode((string)@file_get_contents($file), true),
            fn($t) => $t > $now - RATE_WINDOW
        );
    }
    if (count($hits) >= RATE_LIMIT) return true;
    $hits[] = $now;
    @file_put_contents($file, json_encode(array_values($hits)), LOCK_EX);
    return false;
}

$report = null;
$error = null;
$input = '';
$wantJson = ($_GET['format'] ?? '') === 'json' || str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json');
$allowPrivate = getenv('PVC_ALLOW_PRIVATE') === '1';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = trim((string)($_POST['url'] ?? ''));
    try {
        if (rate_limited()) {
            throw new RuntimeException('Rate limit reached. Please wait before scanning again.');
        }
        $target = Target::parse($input, $allowPrivate);
        $scanner = new Scanner();
        $report = $scanner->scan($target);
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

if ($wantJson) {
    header('Content-Type: application/json');
    echo json_encode($report ?? ['error' => $error], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/* ---------- presentation helpers ---------- */
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

const SEV_META = [
    'critical' => ['Critical', '#dc2626'],
    'high'     => ['High',     '#ea580c'],
    'medium'   => ['Medium',   '#d97706'],
    'low'      => ['Low',      '#ca8a04'],
    'info'     => ['Info',     '#2563eb'],
    'good'     => ['Pass',     '#16a34a'],
];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP Posture Scanner</title>
<style>
  :root{
    --bg:#0f172a; --panel:#1e293b; --panel2:#273449; --line:#334155;
    --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; --accent2:#818cf8;
  }
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
       background:linear-gradient(180deg,#0b1220,#0f172a);color:var(--text);min-height:100vh}
  a{color:var(--accent)}
  .wrap{max-width:900px;margin:0 auto;padding:32px 20px 80px}
  header h1{font-size:28px;margin:0 0 4px;letter-spacing:-.02em}
  header p{color:var(--muted);margin:0 0 24px}
  .logo{display:inline-flex;align-items:center;gap:10px}
  .logo .mark{width:34px;height:34px;border-radius:9px;
    background:conic-gradient(from 210deg,var(--accent),var(--accent2));
    display:grid;place-items:center;font-weight:800;color:#0b1220}
  form.search{display:flex;gap:10px;background:var(--panel);border:1px solid var(--line);
    padding:10px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.3)}
  form.search input{flex:1;background:var(--panel2);border:1px solid var(--line);color:var(--text);
    padding:14px 16px;border-radius:10px;font-size:16px;outline:none}
  form.search input:focus{border-color:var(--accent)}
  form.search button{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#07101f;
    border:0;padding:0 24px;border-radius:10px;font-weight:700;font-size:16px;cursor:pointer}
  .notice{font-size:13px;color:var(--muted);margin:14px 2px 0;display:flex;gap:8px;align-items:flex-start}
  .notice b{color:#cbd5e1}
  .err{background:#3b1113;border:1px solid #7f1d1d;color:#fecaca;padding:14px 16px;border-radius:12px;margin-top:20px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;margin-top:22px}
  .scoreline{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
  .grade{width:92px;height:92px;border-radius:20px;display:grid;place-items:center;
    font-size:46px;font-weight:800;color:#07101f;flex:none}
  .scoremeta{flex:1;min-width:220px}
  .scoremeta h2{margin:0 0 4px;font-size:20px;word-break:break-all}
  .scoremeta .sub{color:var(--muted);font-size:13px}
  .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
  .chip{font-size:12px;padding:5px 10px;border-radius:999px;border:1px solid var(--line);
    background:var(--panel2);color:var(--muted)}
  .chip b{color:var(--text)}
  .bars{display:flex;gap:6px;margin-top:16px;flex-wrap:wrap}
  .bar{font-size:12px;padding:6px 10px;border-radius:8px;font-weight:600;color:#07101f}
  h3.section{margin:28px 0 10px;font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  .finding{border:1px solid var(--line);border-left-width:4px;border-radius:12px;
    padding:14px 16px;margin:10px 0;background:var(--panel2)}
  .finding .top{display:flex;gap:10px;align-items:center;justify-content:space-between}
  .finding .title{font-weight:650}
  .sev{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;
    padding:3px 8px;border-radius:6px;color:#07101f;flex:none}
  .finding .detail{color:#cbd5e1;margin:8px 0 0;font-size:14px}
  .finding .rec{margin-top:10px;font-size:14px;background:#0b1526;border:1px solid var(--line);
    border-radius:9px;padding:10px 12px}
  .finding .rec b{color:var(--accent)}
  .finding .ev{margin-top:8px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;color:var(--muted);
    white-space:pre-wrap;word-break:break-word;background:#0b1526;border-radius:8px;padding:8px 10px}
  .cat{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
  .toolbar{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
  .toolbar a{font-size:13px;text-decoration:none;border:1px solid var(--line);
    padding:8px 14px;border-radius:9px;color:var(--text);background:var(--panel2)}
  footer{color:var(--muted);font-size:12px;margin-top:40px;text-align:center}
  .legal{font-size:12px;color:var(--muted);background:var(--panel);border:1px dashed var(--line);
    padding:12px 14px;border-radius:12px;margin-top:22px}
  @media print{body{background:#fff;color:#000}.card,.finding{break-inside:avoid}
    form.search,.toolbar,.notice{display:none}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo"><span class="mark">φ</span><h1>PHP Posture Scanner</h1></div>
    <p>Passive security assessment for PHP-based websites — fingerprint, version/EOL, headers, cookies, exposed files.</p>
  </header>

  <form class="search" method="post" action="/">
    <input type="url" name="url" placeholder="https://example.com" value="<?= h($input) ?>"
           autocomplete="off" autofocus required>
    <button type="submit">Scan</button>
  </form>
  <div class="notice">
    <span>🔒</span>
    <span><b>Scan only sites you own or are explicitly authorised to test.</b>
    This tool makes a small number of ordinary GET/HEAD requests and reads only publicly served responses —
    no exploits, no brute-forcing. Scanning systems without permission may be unlawful.</span>
  </div>

  <?php if ($error): ?>
    <div class="err"><strong>Could not scan:</strong> <?= h($error) ?></div>
  <?php endif; ?>

  <?php if ($report): $m = $report['meta']; ?>
    <?php
      $gradeColor = match($report['grade']){
        'A'=>'#16a34a','B'=>'#65a30d','C'=>'#d97706','D'=>'#ea580c',default=>'#dc2626'};
    ?>
    <div class="card">
      <div class="scoreline">
        <div class="grade" style="background:<?= $gradeColor ?>"><?= h($report['grade']) ?></div>
        <div class="scoremeta">
          <h2><?= h($m['target']) ?></h2>
          <div class="sub">
            Score <?= (int)$report['score'] ?>/100 ·
            IP <?= h((string)($m['ip'] ?? '?')) ?> ·
            <?= (int)($m['requests'] ?? 0) ?> requests ·
            <?= h(substr((string)$m['scanned_at'],0,19)) ?>
          </div>
          <div class="chips">
            <span class="chip">PHP: <b><?= $m['is_php'] ? 'detected' : 'not detected' ?></b></span>
            <?php if (!empty($m['php_version'])): ?>
              <span class="chip">Version: <b><?= h((string)$m['php_version']) ?></b></span>
            <?php endif; ?>
            <?php if (!empty($m['server'])): ?>
              <span class="chip">Server: <b><?= h((string)$m['server']) ?></b></span>
            <?php endif; ?>
            <?php if (!empty($m['cms'])): ?>
              <span class="chip">CMS: <b><?= h((string)$m['cms']) ?></b></span>
            <?php endif; ?>
          </div>
          <div class="bars">
            <?php foreach (['critical','high','medium','low','good'] as $sev):
              $n=$report['counts'][$sev]??0; if(!$n) continue; [$lbl,$col]=SEV_META[$sev]; ?>
              <span class="bar" style="background:<?= $col ?>"><?= $n ?> <?= h($lbl) ?></span>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
      <div class="toolbar">
        <a href="#plan">↓ Action plan</a>
        <a href="/?format=json" onclick="this.href='/?format=json';">JSON (re-submit)</a>
        <a href="#" onclick="window.print();return false">🖨 Print / save PDF</a>
      </div>
    </div>

    <!-- ACTION PLAN -->
    <h3 class="section" id="plan">Recommended actions (<?= count($report['action_plan']) ?>)</h3>
    <?php if (!$report['action_plan']): ?>
      <div class="finding" style="border-left-color:#16a34a">
        <div class="title">No issues found in the passive checks. 🎉</div>
        <div class="detail">Nothing actionable surfaced. This is not a guarantee of security — it only means the passive checks passed. Consider a full authenticated audit for sensitive applications.</div>
      </div>
    <?php else: foreach ($report['action_plan'] as $i => $f): [$lbl,$col]=SEV_META[$f['severity']]; ?>
      <div class="finding" style="border-left-color:<?= $col ?>">
        <div class="top">
          <span class="title"><?= ($i+1) ?>. <?= h($f['title']) ?></span>
          <span class="sev" style="background:<?= $col ?>"><?= h($lbl) ?></span>
        </div>
        <div class="cat"><?= h($f['category']) ?></div>
        <div class="detail"><?= h($f['detail']) ?></div>
        <?php if ($f['recommendation']): ?>
          <div class="rec"><b>Fix:</b> <?= h($f['recommendation']) ?></div>
        <?php endif; ?>
        <?php if ($f['evidence']): ?><div class="ev"><?= h($f['evidence']) ?></div><?php endif; ?>
      </div>
    <?php endforeach; endif; ?>

    <!-- FULL RESULTS incl. passes -->
    <h3 class="section">All checks (<?= count($report['findings']) ?>)</h3>
    <?php foreach ($report['findings'] as $f): if(in_array($f['severity'],['good','info'],true)):
      [$lbl,$col]=SEV_META[$f['severity']]; ?>
      <div class="finding" style="border-left-color:<?= $col ?>">
        <div class="top">
          <span class="title"><?= h($f['title']) ?></span>
          <span class="sev" style="background:<?= $col ?>"><?= h($lbl) ?></span>
        </div>
        <div class="cat"><?= h($f['category']) ?></div>
        <?php if ($f['detail']): ?><div class="detail"><?= h($f['detail']) ?></div><?php endif; ?>
        <?php if ($f['evidence']): ?><div class="ev"><?= h($f['evidence']) ?></div><?php endif; ?>
      </div>
    <?php endif; endforeach; ?>

  <?php else: ?>
    <div class="legal">
      <strong>How it works.</strong> Enter a URL and the scanner fetches the homepage, detects whether PHP is in use
      (via <code>X-Powered-By</code>, <code>Server</code>, <code>PHPSESSID</code>, framework cookies and <code>.php</code> links),
      checks the PHP version against the official end-of-life schedule, inspects security headers and cookie flags,
      looks for information disclosure (phpinfo, error output, debug pages), and probes a short list of well-known
      sensitive paths (<code>.env</code>, <code>.git</code>, backups). It then grades the result and lists prioritised fixes.
    </div>
  <?php endif; ?>

  <footer>
    PHP Posture Scanner · passive checks only · EOL data from php.net (2026-10-24).
    Not a substitute for a full penetration test.
  </footer>
</div>
</body>
</html>
