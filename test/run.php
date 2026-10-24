<?php
require __DIR__ . '/../src/Scanner.php';
use PvC\{Scanner, Target};
foreach (['http://127.0.0.1:8081' => 'VULNERABLE', 'http://127.0.0.1:8082' => 'HARDENED'] as $url => $label) {
    $t = Target::parse($url, true);           // allowPrivate=true for localhost test
    $r = (new Scanner())->scan($t);
    echo str_repeat('=', 60) . "\n$label  $url\n" . str_repeat('=', 60) . "\n";
    printf("Grade %s  Score %d/100  | PHP=%s ver=%s cms=%s | %d requests\n",
        $r['grade'], $r['score'], $r['meta']['is_php']?'yes':'no',
        $r['meta']['php_version'] ?? '-', $r['meta']['cms'] ?? '-', $r['meta']['requests']);
    echo "Counts: " . json_encode($r['counts']) . "\n\nACTION PLAN:\n";
    foreach ($r['action_plan'] as $i => $f)
        printf("  %2d. [%-8s] %s\n", $i+1, strtoupper($f['severity']), $f['title']);
    echo "\nPASSES:\n";
    foreach ($r['findings'] as $f) if (in_array($f['severity'],['good','info']))
        printf("   - [%-4s] %s\n", $f['severity'], $f['title']);
    echo "\n";
}
