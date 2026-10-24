#!/usr/bin/env php
<?php
declare(strict_types=1);
/**
 * CLI: php bin/scan.php https://example.com [--json] [--allow-private]
 */
require __DIR__ . '/../src/Scanner.php';

use PvC\Scanner;
use PvC\Target;

$args = array_slice($argv, 1);
$json = in_array('--json', $args, true);
$allowPrivate = in_array('--allow-private', $args, true);
$url = null;
foreach ($args as $a) {
    if ($a[0] !== '-') { $url = $a; break; }
}
if (!$url) {
    fwrite(STDERR, "Usage: php bin/scan.php <url> [--json] [--allow-private]\n");
    exit(2);
}

try {
    $target = Target::parse($url, $allowPrivate);
    $report = (new Scanner())->scan($target);
} catch (Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
    exit(1);
}

if ($json) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

$c = fn($code, $s) => (stream_isatty(STDOUT)) ? "\033[{$code}m{$s}\033[0m" : $s;
$col = ['critical'=>'1;31','high'=>'31','medium'=>'33','low'=>'2;33','info'=>'36','good'=>'32'];
$m = $report['meta'];

echo "\n", str_repeat('─', 64), "\n";
echo "  {$m['target']}  (IP {$m['ip']})\n";
echo "  Grade " . $c($report['grade']==='A'||$report['grade']==='B'?'32':'1;31', $report['grade'])
   . "   Score {$report['score']}/100   "
   . "PHP: " . ($m['is_php']?'yes':'no')
   . ($m['php_version'] ? " ({$m['php_version']})" : '')
   . ($m['cms'] ? "   CMS: {$m['cms']}" : '')
   . "   {$m['requests']} requests\n";
echo str_repeat('─', 64), "\n\n";

echo "RECOMMENDED ACTIONS\n\n";
if (!$report['action_plan']) {
    echo "  No issues found in passive checks.\n";
}
foreach ($report['action_plan'] as $i => $f) {
    printf("  %2d. %s  %s\n", $i+1, $c($col[$f['severity']], '['.strtoupper($f['severity']).']'), $f['title']);
    echo "      " . wordwrap($f['detail'], 72, "\n      ", true) . "\n";
    if ($f['recommendation']) echo "      → " . wordwrap($f['recommendation'], 70, "\n        ", true) . "\n";
    if ($f['evidence']) echo "      " . $c('2;37', $f['evidence']) . "\n";
    echo "\n";
}
echo "PASSED\n";
foreach ($report['findings'] as $f) {
    if (in_array($f['severity'], ['good','info'], true)) {
        echo "  " . $c($col[$f['severity']], '✓') . " {$f['title']}\n";
    }
}
echo "\n";
