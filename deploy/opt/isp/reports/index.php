<?php
// Zabbix report downloader: pick hosts, items, a time range and a step (30 s, 1 min, ...) and export CSV.
// Users log in with their own Zabbix account; the item list and every export go through the Zabbix API
// with that user's token, so nobody can export an item they cannot see in Zabbix. Numbers are then
// aggregated straight from the Zabbix history tables (much faster than history.get for long ranges).
declare(strict_types=1);

date_default_timezone_set('Asia/Kolkata');
ini_set('memory_limit', '2048M');
set_time_limit(300);

const API = 'http://127.0.0.1/zabbix/api_jsonrpc.php';
const ZBX_CONF = '/etc/zabbix/web/zabbix.conf.php';
const TZ_OFFSET = 19800;            // IST, so 1 h / 1 day buckets start on the IST hour / midnight
const MAX_ITEMS = 300;
const MAX_CELLS = 2000000;          // rows x columns (or raw samples) per export
const MAX_DAYS = 180;               // history retention is 180 days (Zabbix housekeeping override)
const PREVIEW_ROWS = 60;
const STEPS = ['raw' => 'Raw (every sample)', '30' => '30 seconds', '60' => '1 minute', '120' => '2 minutes', '300' => '5 minutes',
               '900' => '15 minutes', '1800' => '30 minutes', '3600' => '1 hour', '86400' => '1 day'];
const AGGS = ['avg' => 'Average', 'min' => 'Minimum', 'max' => 'Maximum'];
const WEB_SERVICE = 'http://127.0.0.1:10053/report';     // zabbix-web-service (headless Chrome), also used by Zabbix scheduled reports
const FRONTEND = 'http://127.0.0.1/zabbix/';             // port 80 is not redirected to HTTPS for 127.0.0.1
const CHROME = '/usr/bin/google-chrome';
const PDF_MAX_TABLE_ROWS = 20000;   // data table rows in a PDF (~45 rows per A4 page)
const PDF_COLS_PER_TABLE = 8;       // value columns per table block, so tables fit A4 landscape
const CHART_POINTS = 1500;          // charts with more steps than this are drawn per pixel column (min/avg/max kept)

// daily-email.php includes this file from the command line as a library (REPORTS_LIB): no web session, no routing.
if (!defined('REPORTS_LIB')) {
    session_name('ispreports');
    session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES); }

class AuthExpired extends RuntimeException {}

function api(string $method, array $params, bool $auth = true): mixed {
    $headers = ['Content-Type: application/json-rpc'];
    if ($auth) {
        $headers[] = 'Authorization: Bearer ' . ($_SESSION['token'] ?? '');
    }
    $ch = curl_init(API);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 60,
        CURLOPT_POSTFIELDS => json_encode(['jsonrpc' => '2.0', 'method' => $method, 'params' => $params, 'id' => 1])]);
    $raw = curl_exec($ch);
    if ($raw === false) {
        throw new RuntimeException('Zabbix API unreachable: ' . curl_error($ch));
    }
    $resp = json_decode($raw, true);
    if (isset($resp['error'])) {
        $msg = trim(($resp['error']['data'] ?? '') ?: $resp['error']['message']);
        if ($auth && preg_match('/session|re-login|not authori[sz]ed/i', $msg)) {
            throw new AuthExpired($msg);
        }
        throw new RuntimeException($msg);
    }
    return $resp['result'];
}

function db(): mysqli {
    if (!defined('IMAGE_FORMAT_PNG')) define('IMAGE_FORMAT_PNG', 'PNG');
    $DB = [];
    include ZBX_CONF;
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $port = (int)$DB['PORT'] ?: null;
    $m = new mysqli($DB['SERVER'], $DB['USER'], $DB['PASSWORD'], $DB['DATABASE'], $port);
    $m->set_charset('utf8mb4');
    $m->query('SET SESSION group_concat_max_len = 4096');
    return $m;
}

function delaySeconds(string $d): int {
    if (!preg_match('/^(\d+)([smhdw]?)/', $d, $m) || (int)$m[1] === 0) return 60;   // dependent/calculated: assume 1 min
    return (int)$m[1] * ['' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800][$m[2]];
}

// Unit conversion so the CSV is readable: bps -> Mbps, s -> ms (latency), B -> GB for memory.
function unitConv(string $units, bool $friendly): array {
    $u = ltrim($units, '!');
    if ($friendly) {
        if ($u === 'bps') return ['Mbps', 1e-6];
        if ($u === 's') return ['ms', 1000.0];
        if ($u === 'B') return ['GB', 1 / 1073741824];
    }
    return [$u, 1.0];
}

function fmt(?float $v): string {
    if ($v === null) return '';
    $s = number_format($v, abs($v) >= 100 ? 2 : 4, '.', '');
    return str_contains($s, '.') ? rtrim(rtrim($s, '0'), '.') : $s;
}

function label(array $item, $v): string {
    if ($v === null) return '';
    foreach ($item['valuemap']['mappings'] ?? [] as $m) {
        if ((string)$m['value'] === (string)(int)$v) return "{$m['newvalue']} ({$m['value']})";
    }
    return fmt((float)$v);
}

function parseTime(string $s): int {
    $t = DateTime::createFromFormat('Y-m-d\TH:i', $s) ?: DateTime::createFromFormat('Y-m-d\TH:i:s', $s);
    if (!$t) throw new InvalidArgumentException('Invalid date/time.');
    return $t->getTimestamp();
}

// ---- Request validation shared by preview and download ------------------------------------------------
function readRequest(): array {
    $ids = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['items'] ?? [])))));
    if (!$ids) throw new InvalidArgumentException('Select at least one item.');
    if (count($ids) > MAX_ITEMS) throw new InvalidArgumentException('Select at most ' . MAX_ITEMS . ' items per report.');
    $from = parseTime((string)($_POST['from'] ?? ''));
    $to = parseTime((string)($_POST['to'] ?? ''));
    if ($to > time()) $to = time();
    if ($from >= $to) throw new InvalidArgumentException('"From" must be before "To".');
    if ($to - $from > MAX_DAYS * 86400) throw new InvalidArgumentException('Maximum range is ' . MAX_DAYS . ' days.');
    $step = (string)($_POST['step'] ?? '60');
    if (!isset(STEPS[$step])) throw new InvalidArgumentException('Invalid step.');
    $aggs = array_values(array_intersect(array_keys(AGGS), (array)($_POST['agg'] ?? [])));
    if (!$aggs) $aggs = ['avg'];
    $type = ($_POST['type'] ?? 'series') === 'summary' ? 'summary' : 'series';
    $format = ($_POST['format'] ?? 'csv') === 'pdf' ? 'pdf' : 'csv';
    $title = trim(preg_replace('/\s+/', ' ', (string)($_POST['title'] ?? ''))) ?: 'Network data report';
    $title = mb_substr($title, 0, 80);
    $table = !empty($_POST['table']);
    if ($format === 'pdf' && $step === 'raw') throw new InvalidArgumentException('PDF reports need a step (30 seconds or more), not Raw.');
    if ($format === 'pdf' && $table && ($to - $from) / (int)$step > PDF_MAX_TABLE_ROWS) {
        throw new InvalidArgumentException(sprintf('The PDF data table would have %s rows (limit %s, about %d pages). Choose a larger step or shorter period, or untick "Include data table" to get the summary and charts only.',
            number_format((int)ceil(($to - $from) / (int)$step)), number_format(PDF_MAX_TABLE_ROWS), PDF_MAX_TABLE_ROWS / 45));
    }

    // Permission check: the API returns only items this user may read.
    $items = api('item.get', ['itemids' => $ids, 'output' => ['itemid', 'name', 'units', 'delay', 'value_type', 'key_'],
        'selectHosts' => ['name'], 'selectValueMap' => ['mappings'], 'filter' => ['value_type' => [0, 3]]]);
    if (!$items) throw new InvalidArgumentException('None of the selected items are available to your account.');
    $friendly = !empty($_POST['friendly']);
    foreach ($items as &$it) {
        $it['host'] = $it['hosts'][0]['name'] ?? '';
        $it['mapped'] = !empty($it['valuemap']['mappings']);
        [$it['unit'], $it['factor']] = $it['mapped'] ? ['', 1.0] : unitConv($it['units'], $friendly);
        $hasUnit = $it['unit'] === '' || str_ends_with($it['name'], "({$it['unit']})");
        $it['title'] = $it['host'] . ' | ' . $it['name'] . ($hasUnit ? '' : " ({$it['unit']})");
    }
    unset($it);
    usort($items, fn($a, $b) => [$a['host'], $a['name']] <=> [$b['host'], $b['name']]);
    return compact('items', 'from', 'to', 'step', 'aggs', 'type', 'friendly', 'format', 'title', 'table');
}

function bucketStart(int $t, int $step): int { return intdiv($t + TZ_OFFSET, $step) * $step - TZ_OFFSET; }

function estimateCells(array $r): int {
    $span = $r['to'] - $r['from'];
    if ($r['step'] === 'raw') {
        return (int)array_sum(array_map(fn($i) => $span / delaySeconds($i['delay']), $r['items']));
    }
    $cols = array_sum(array_map(fn($i) => $i['mapped'] ? 1 : count($r['aggs']), $r['items']));
    return (int)ceil($span / (int)$r['step']) * max(1, $cols);
}

function byTable(array $items): array {
    $t = [];
    foreach ($items as $it) $t[$it['value_type'] === '0' ? 'history' : 'history_uint'][] = (int)$it['itemid'];
    return $t;
}

// Bucketed values: [itemid][bucket] = [avg, min, max, last]
function fetchBuckets(mysqli $db, array $r): array {
    $s = (int)$r['step'];
    $out = [];
    foreach (byTable($r['items']) as $table => $ids) {
        $in = implode(',', $ids);
        // $r['trends']: read the hourly trends instead (steps of 1 h or more over long periods; much faster)
        $cols = empty($r['trends']) ? "AVG(value), MIN(value), MAX(value), SUBSTRING_INDEX(GROUP_CONCAT(value ORDER BY clock DESC, ns DESC), ',', 1)"
            : "AVG(value_avg), MIN(value_min), MAX(value_max), SUBSTRING_INDEX(GROUP_CONCAT(value_avg ORDER BY clock DESC), ',', 1)";
        if (!empty($r['trends'])) $table = $table === 'history' ? 'trends' : 'trends_uint';
        $res = $db->query("SELECT itemid, FLOOR((clock + " . TZ_OFFSET . ") / $s) * $s - " . TZ_OFFSET . " AS b, $cols
            FROM $table WHERE itemid IN ($in) AND clock >= {$r['from']} AND clock < {$r['to']}
            GROUP BY itemid, b", MYSQLI_USE_RESULT);
        while ($row = $res->fetch_row()) {
            $out[$row[0]][(int)$row[1]] = [(float)$row[2], (float)$row[3], (float)$row[4], (float)$row[5]];
        }
        $res->free();
    }
    return $out;
}

function seriesHeader(array $r): array {
    $hdr = ['Time (IST)'];
    foreach ($r['items'] as $it) {
        if ($it['mapped']) { $hdr[] = $it['title'] . ($r['step'] === 'raw' ? '' : ' [last]'); continue; }
        foreach ($r['aggs'] as $a) $hdr[] = $it['title'] . (count($r['aggs']) > 1 ? " [$a]" : '');
    }
    return $hdr;
}

// Yields table rows for the time-series report (bucket grid, empty cells where there was no data).
function seriesRows(mysqli $db, array $r, ?array $data = null): Generator {
    if ($r['step'] === 'raw') {
        // Raw: one row per distinct timestamp, one column per item.
        $byItem = [];
        foreach ($r['items'] as $it) $byItem[$it['itemid']] = $it;
        $col = array_flip(array_keys($byItem));
        foreach (byTable($r['items']) as $table => $ids) {
            $res = $db->query("SELECT clock, itemid, value FROM $table WHERE itemid IN (" . implode(',', $ids) . ")
                AND clock >= {$r['from']} AND clock < {$r['to']}", MYSQLI_USE_RESULT);
            while ($row = $res->fetch_row()) $grid[(int)$row[0]][$col[$row[1]]] = $row[2];
            $res->free();
        }
        $grid ??= [];
        ksort($grid);
        $items = array_values($byItem);
        foreach ($grid as $t => $vals) {
            $line = [date('Y-m-d H:i:s', $t)];
            foreach ($items as $i => $it) {
                $v = $vals[$i] ?? null;
                $line[] = $it['mapped'] ? label($it, $v) : ($v === null ? '' : fmt($v * $it['factor']));
            }
            yield $line;
        }
        return;
    }
    $s = (int)$r['step'];
    $data ??= fetchBuckets($db, $r);
    $aggIdx = ['avg' => 0, 'min' => 1, 'max' => 2];
    for ($b = bucketStart($r['from'], $s); $b < $r['to']; $b += $s) {
        $line = [date('Y-m-d H:i:s', $b)];
        foreach ($r['items'] as $it) {
            $v = $data[$it['itemid']][$b] ?? null;
            if ($it['mapped']) { $line[] = label($it, $v[3] ?? null); continue; }
            foreach ($r['aggs'] as $a) $line[] = $v === null ? '' : fmt($v[$aggIdx[$a]] * $it['factor']);
        }
        yield $line;
    }
}

function percentile(array $sorted, float $p): ?float {
    $n = count($sorted);
    return $n ? $sorted[max(0, (int)ceil($p * $n) - 1)] : null;
}

// Summary: one row per item. With a step selected the statistics are taken over the step averages
// (e.g. 95th percentile of 5-minute averages, the usual bandwidth-billing method); with "Raw" over every sample.
function summaryRows(mysqli $db, array $r, ?array $buckets = null): array {
    $raw = $r['step'] === 'raw';
    $rows = [];
    $tables = [];
    foreach ($r['items'] as $it) $tables[$it['itemid']] = $it['value_type'] === '0' ? 'history' : 'history_uint';
    $buckets = $raw ? [] : ($buckets ?? fetchBuckets($db, $r));
    foreach ($r['items'] as $it) {
        $id = (int)$it['itemid'];
        if ($raw) {
            $vals = [];
            $res = $db->query("SELECT clock, value FROM {$tables[$id]} WHERE itemid = $id
                AND clock >= {$r['from']} AND clock < {$r['to']}", MYSQLI_USE_RESULT);
            while ($row = $res->fetch_row()) $vals[(int)$row[0]] = (float)$row[1];
            $res->free();
        } else {
            $vals = array_map(fn($v) => $v[0], $buckets[$id] ?? []);
        }
        $n = count($vals);
        if ($it['mapped']) {
            // State items: share of samples / steps in each state.
            $counts = array_count_values(array_map(fn($v) => (string)(int)round($v), $vals));
            $parts = [];
            foreach ($counts as $v => $c) $parts[] = label($it, $v) . ': ' . fmt(100 * $c / $n) . '%';
            $rows[] = [$it['host'], $it['name'], '', $n, '', '', '', '', '', implode('; ', $parts)];
            continue;
        }
        if (!$n) { $rows[] = [$it['host'], $it['name'], $it['unit'], 0, '', '', '', '', '', 'no data']; continue; }
        $sorted = array_values($vals);
        sort($sorted);
        $max = end($sorted);
        $f = $it['factor'];
        $rows[] = [$it['host'], $it['name'], $it['unit'], $n, fmt($sorted[0] * $f), fmt(array_sum($sorted) / $n * $f),
            fmt($max * $f), fmt(percentile($sorted, 0.95) * $f), date('Y-m-d H:i:s', (int)array_search($max, $vals, true)), ''];
    }
    return $rows;
}

const SUMMARY_HDR = ['Host', 'Item', 'Unit', 'Samples', 'Minimum', 'Average', 'Maximum', '95th percentile', 'Time of maximum (IST)', 'States'];

function describe(array $r): string {
    return date('d M Y H:i', $r['from']) . ' to ' . date('d M Y H:i', $r['to']) . ' IST, step ' . STEPS[$r['step']];
}

function download(mysqli $db, array $r): void {
    $name = 'zabbix-' . $r['type'] . '-' . date('Ymd-Hi', $r['from']) . '-to-' . date('Ymd-Hi', $r['to'])
        . '-' . ($r['step'] === 'raw' ? 'raw' : $r['step'] . 's') . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"$name\"");
    header('Cache-Control: no-store');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");   // BOM so Excel opens UTF-8 correctly
    if ($r['type'] === 'summary') {
        fputcsv($out, ['Zabbix summary report', describe($r), 'Generated ' . date('d M Y H:i') . ' by ' . $_SESSION['user']]);
        fputcsv($out, []);
        fputcsv($out, SUMMARY_HDR);
        foreach (summaryRows($db, $r) as $row) fputcsv($out, $row);
    } else {
        fputcsv($out, seriesHeader($r));
        $n = 0;
        foreach (seriesRows($db, $r) as $row) {
            fputcsv($out, $row);
            if (++$n % 5000 === 0) flush();
        }
    }
    fclose($out);
}

// ---- Data report PDF -------------------------------------------------------------------------------
// Same data as the CSV export at the chosen step, laid out for printing: cover, summary table, one chart per item
// and (optionally) the full table of step values. Rendered to PDF by headless Chrome.

function htmlToPdf(string $html): string {
    $dir = sys_get_temp_dir() . '/zbxreport-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    try {
        file_put_contents("$dir/report.html", $html);
        run([CHROME, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-pdf-header-footer', '--user-data-dir=' . "$dir/chrome",
            "--print-to-pdf=$dir/report.pdf", "file://$dir/report.html"], ['HOME' => $dir, 'PATH' => '/usr/bin:/bin']);
        return file_get_contents("$dir/report.pdf");
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

function niceStep(float $range, int $ticks): float {
    $raw = $range / $ticks;
    $mag = 10 ** floor(log10($raw));
    foreach ([1, 2, 2.5, 5, 10] as $m) {
        if ($m * $mag >= $raw) return $m * $mag;
    }
    return 10 * $mag;
}

// Y range for a chart. Positive data starts at 0. A (nearly) flat series - e.g. steady negative dBm, whose step
// averages differ only by float noise - gets a range wide enough that the tick step is not lost to rounding
// (a step below the precision of the value made the tick loop endless and exhausted memory).
function axisRange(float $lo, float $hi): array {
    if (!is_finite($lo) || !is_finite($hi)) return [0.0, 1.0];
    if ($lo >= 0) $lo = 0.0;
    $min = max(abs($lo), abs($hi)) * 1e-6;
    if ($hi - $lo <= $min) {
        $pad = $lo != 0.0 ? abs($lo) * 0.05 : 1.0;
        [$lo, $hi] = [$lo - $pad, $hi + $pad];
        if ($lo < 0 && $hi > 0 && $lo + $pad >= 0) $lo = 0.0;
    }
    return [$lo, $hi];
}

function axisNum(float $v): string {
    $a = abs($v);
    return $a >= 1000 ? number_format($v, 0) : ($a >= 10 ? fmt(round($v, 1)) : fmt(round($v, 3)));
}

// One SVG line chart per item: step average as a line, min-max of each step as a shaded band when Minimum or
// Maximum was selected. State items (with a value map) are drawn as the state at the end of each step.
function chartSvg(array $it, array $data, array $r): string {
    [$W, $H, $L, $R, $T, $B] = [1000, 165, 78, 14, 8, 26];
    [$pw, $ph] = [$W - $L - $R, $H - $T - $B];
    $f = $it['factor'];
    $band = !$it['mapped'] && array_intersect(['min', 'max'], $r['aggs']);
    $span = $r['to'] - $r['from'];
    ksort($data);
    if (!$data) return '<div class="nodata">No data in this period</div>';

    // Decimate to pixel columns when there are more steps than the chart can show.
    $gap = 1.5 * (int)$r['step'];
    $pts = [];
    if (count($data) > CHART_POINTS) {
        $colW = $span / CHART_POINTS;
        $gap = max($gap, 2.5 * $colW);
        foreach ($data as $t => $v) {
            $c = (int)(($t - $r['from']) / $colW);
            $p = &$pts[$c];
            $p ??= [$r['from'] + ($c + 0.5) * $colW, 0.0, INF, -INF, 0, 0.0];
            $p[1] += $v[0]; $p[2] = min($p[2], $v[1]); $p[3] = max($p[3], $v[2]); $p[4]++; $p[5] = $v[3];
            unset($p);
        }
        $pts = array_map(fn($p) => [$p[0], ($it['mapped'] ? $p[5] : $p[1] / $p[4]) * $f, $p[2] * $f, $p[3] * $f], array_values($pts));
    } else {
        foreach ($data as $t => $v) $pts[] = [$t + (int)$r['step'] / 2, ($it['mapped'] ? $v[3] : $v[0]) * $f, $v[1] * $f, $v[2] * $f];
    }

    $vals = array_merge(array_column($pts, 1), $band ? array_column($pts, 2) : [], $band ? array_column($pts, 3) : []);
    [$lo, $hi] = [min($vals), max($vals)];
    $yt = [];
    if ($it['mapped'] && $hi - $lo <= 12) {   // state items: one tick per state
        $lo = floor($lo); $hi = ceil($hi);
        for ($v = $lo; $v <= $hi; $v++) $yt[] = $v;
        [$lo, $hi] = [$lo - 0.3, $hi + 0.3];
    } else {
        [$lo, $hi] = axisRange($lo, $hi);
        $st = niceStep($hi - $lo, 4);
        [$lo, $hi] = [floor($lo / $st) * $st, ceil($hi / $st) * $st];
        for ($v = $lo, $n = 0; $v <= $hi + $st / 2 && $n < 20; $v += $st, $n++) $yt[] = $v;
    }
    $x = fn($t) => round($L + ($t - $r['from']) / $span * $pw, 1);
    $y = fn($v) => round($T + $ph - ($v - $lo) / ($hi - $lo) * $ph, 1);

    $svg = "<svg viewBox=\"0 0 $W $H\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"Noto Sans, DejaVu Sans, sans-serif\" font-size=\"11\">";
    foreach ($yt as $v) {
        $yy = $y($v);
        $lab = $it['mapped'] ? preg_replace('/ \(.*$/', '', label($it, $v)) : axisNum($v);
        $svg .= "<line x1=\"$L\" x2=\"" . ($W - $R) . "\" y1=\"$yy\" y2=\"$yy\" stroke=\"#e3e8ee\"/>"
            . "<text x=\"" . ($L - 6) . "\" y=\"" . ($yy + 4) . "\" text-anchor=\"end\" fill=\"#616e7c\">" . h($lab) . '</text>';
    }
    // Time ticks aligned to IST.
    foreach ([60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800] as $tick) {
        if ($span / $tick <= 8) break;
    }
    $fmtT = $tick >= 86400 ? 'd M' : ($span > 86400 ? 'd M H:i' : 'H:i');
    for ($t = bucketStart($r['from'], $tick) + ($tick >= 604800 ? 0 : $tick); $t < $r['to']; $t += $tick) {
        if ($t <= $r['from']) continue;
        $xx = $x($t);
        $svg .= "<line x1=\"$xx\" x2=\"$xx\" y1=\"$T\" y2=\"" . ($T + $ph) . "\" stroke=\"#eef1f4\"/>"
            . "<text x=\"$xx\" y=\"" . ($H - 10) . "\" text-anchor=\"middle\" fill=\"#616e7c\">" . date($fmtT, $t) . '</text>';
    }
    $svg .= "<line x1=\"$L\" x2=\"" . ($W - $R) . "\" y1=\"" . ($T + $ph) . "\" y2=\"" . ($T + $ph) . "\" stroke=\"#9aa5b1\"/>";

    // Split into segments where data is missing.
    $segs = [];
    $prev = null;
    foreach ($pts as $p) {
        if ($prev === null || $p[0] - $prev > $gap) $segs[] = [];
        $segs[count($segs) - 1][] = $p;
        $prev = $p[0];
    }
    foreach ($segs as $seg) {
        if ($band) {
            $up = implode(' ', array_map(fn($p) => $x($p[0]) . ',' . $y($p[3]), $seg));
            $dn = implode(' ', array_map(fn($p) => $x($p[0]) . ',' . $y($p[2]), array_reverse($seg)));
            $svg .= "<polygon points=\"$up $dn\" fill=\"#0b6bcb\" fill-opacity=\"0.16\"/>";
        }
        if (count($seg) === 1) {
            $svg .= '<circle cx="' . $x($seg[0][0]) . '" cy="' . $y($seg[0][1]) . '" r="2" fill="#0b6bcb"/>';
            continue;
        }
        $line = implode(' ', array_map(fn($p) => $x($p[0]) . ',' . $y($p[1]), $seg));
        $svg .= "<polyline points=\"$line\" fill=\"none\" stroke=\"#0b6bcb\" stroke-width=\"1.4\" stroke-linejoin=\"round\"/>";
    }
    return $svg . '</svg>';
}

function dataPdf(mysqli $db, array $r): string {
    $data = fetchBuckets($db, $r);
    $summary = summaryRows($db, $r, $data);
    $period = date('d M Y, H:i', $r['from']) . ' – ' . date('d M Y, H:i', $r['to']) . ' IST';
    $stepTxt = STEPS[$r['step']];
    $aggTxt = implode(', ', array_map(fn($a) => AGGS[$a], $r['aggs']));
    $hosts = array_values(array_unique(array_column($r['items'], 'host')));

    ob_start(); ?>
<!doctype html><html><head><meta charset="utf-8"><style>
@page { size: A4 landscape; margin: 12mm 11mm 12mm; }
* { box-sizing: border-box; }
body { margin: 0; font: 9.5pt/1.4 "Noto Sans", "DejaVu Sans", sans-serif; color: #1f2933; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.cover { height: 186mm; position: relative; break-after: page; }
.band { background: #0b4f8a; color: #fff; padding: 34mm 18mm 14mm; margin: -12mm -11mm 0; }
.kicker { font-size: 11pt; letter-spacing: .14em; text-transform: uppercase; opacity: .8; }
.cover h1 { font-size: 32pt; margin: 8pt 0 0; }
.facts { display: grid; grid-template-columns: 1fr 1fr; gap: 6mm 16mm; padding: 12mm 7mm 0; }
.label { font-size: 8pt; text-transform: uppercase; letter-spacing: .1em; color: #616e7c; margin: 0 0 2pt; }
.value { font-size: 13pt; margin: 0; }
.foot { position: absolute; bottom: 0; left: 7mm; right: 7mm; font-size: 8pt; color: #9aa5b1; border-top: 1px solid #d9e0e7; padding-top: 3mm; }
h2 { font-size: 14pt; margin: 0 0 3mm; color: #0b4f8a; }
.section { break-before: page; }
.sub { color: #616e7c; font-size: 8.5pt; margin: -2mm 0 4mm; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th { background: #eef3f8; text-align: left; font-weight: 600; padding: 4pt 5pt; border-bottom: 1px solid #c5d0db; vertical-align: bottom; }
td { padding: 2.5pt 5pt; border-bottom: 1px solid #e6ebf0; }
td.n, th.n { text-align: right; white-space: nowrap; }
.summary td, .summary th { font-size: 8.5pt; }
.data { table-layout: fixed; }
.data th, .data td { font-size: 7.5pt; }
.data td { padding: 1.2pt 5pt; }
.data th { overflow-wrap: anywhere; white-space: normal; font-size: 7pt; }
.data th:first-child, .data td:first-child { width: 27mm; white-space: nowrap; }
.data th .host { display: block; font-weight: 400; color: #616e7c; }
.chart { break-inside: avoid; border: 1px solid #e3e8ee; border-radius: 4pt; padding: 2mm 4mm 0; margin-bottom: 3mm; }
.chart .t { display: flex; justify-content: space-between; gap: 6mm; align-items: baseline; }
.chart .name { font-weight: 600; font-size: 10pt; }
.chart .host { color: #616e7c; font-size: 8.5pt; }
.chart .st { color: #616e7c; font-size: 8pt; white-space: nowrap; }
.chart .st b { color: #1f2933; font-weight: 600; }
.chart svg { width: 100%; height: auto; display: block; }
.nodata { color: #9aa5b1; padding: 8mm 0; text-align: center; }
.legend { font-size: 8pt; color: #616e7c; margin-bottom: 3mm; }
.sw { display: inline-block; width: 14pt; height: 7pt; vertical-align: middle; margin: 0 3pt 0 10pt; }
</style></head><body>
<div class="cover">
  <div class="band"><div class="kicker">Network monitoring report</div><h1><?= h($r['title']) ?></h1></div>
  <div class="facts">
    <div><p class="label">Reporting period</p><p class="value"><?= h($period) ?></p></div>
    <div><p class="label">Duration</p><p class="value"><?= h(duration($r['to'] - $r['from'])) ?></p></div>
    <div><p class="label">Data step</p><p class="value"><?= h($stepTxt) ?> (<?= h(strtolower($aggTxt)) ?> per step)</p></div>
    <div><p class="label">Generated</p><p class="value"><?= h(date('d M Y, H:i')) ?> IST by <?= h($_SESSION['user']) ?></p></div>
    <div><p class="label">Devices</p><p class="value"><?= h(implode(', ', $hosts)) ?></p></div>
    <div><p class="label">Contents</p><p class="value"><?= count($r['items']) ?> metrics: summary, charts<?= $r['table'] ? ', data table at ' . h(strtolower($stepTxt)) . ' steps' : '' ?></p></div>
  </div>
  <div class="foot">Source: Zabbix &middot; isp.picloud.in &middot; statistics are calculated over the <?= h(strtolower($stepTxt)) ?> step averages; 95th percentile = value exceeded in only 5% of steps</div>
</div>

<h2>Summary</h2>
<p class="sub"><?= h($period) ?> &middot; step <?= h($stepTxt) ?></p>
<table class="summary"><thead><tr><th>Device</th><th>Metric</th><th class="n">Minimum</th><th class="n">Average</th><th class="n">Maximum</th><th class="n">95th pct</th><th class="n">Time of maximum</th><th class="n">Steps with data</th></tr></thead><tbody>
<?php foreach ($summary as $row): [$host, $name, $unit, $n, $min, $avg, $max, $p95, $tmax, $states] = $row; $u = $unit !== '' ? " $unit" : ''; ?>
<tr><td><?= h($host) ?></td><td><?= h($name) ?></td>
<?php if ($states !== '' && $states !== 'no data'): ?><td colspan="5"><?= h($states) ?></td>
<?php else: ?><td class="n"><?= $min !== '' ? h($min . $u) : '–' ?></td><td class="n"><?= $avg !== '' ? h($avg . $u) : '–' ?></td><td class="n"><?= $max !== '' ? h($max . $u) : '–' ?></td><td class="n"><?= $p95 !== '' ? h($p95 . $u) : '–' ?></td><td class="n"><?= h($tmax !== '' ? date('d M H:i:s', strtotime($tmax)) : '–') ?></td><?php endif; ?>
<td class="n"><?= number_format((int)$n) ?></td></tr>
<?php endforeach; ?>
</tbody></table>

<div class="section">
<h2>Charts</h2>
<div class="legend">Line: average per <?= h(strtolower($stepTxt)) ?><?php if (array_intersect(['min', 'max'], $r['aggs'])): ?><span class="sw" style="background:rgba(11,107,203,.16)"></span>shaded: minimum–maximum within each step<?php endif; ?>. Gaps mean no data was collected.</div>
<?php foreach ($r['items'] as $i => $it): $row = $summary[$i]; $u = $it['unit'] !== '' ? ' ' . $it['unit'] : ''; ?>
<div class="chart">
  <div class="t"><div><span class="name"><?= h($it['name']) ?></span> <span class="host">&middot; <?= h($it['host']) ?><?= $it['unit'] !== '' ? ' &middot; ' . h($it['unit']) : '' ?></span></div>
  <div class="st"><?php if (!$it['mapped'] && $row[3]): ?>min <b><?= h($row[4] . $u) ?></b> &nbsp; avg <b><?= h($row[5] . $u) ?></b> &nbsp; max <b><?= h($row[6] . $u) ?></b> &nbsp; 95th <b><?= h($row[7] . $u) ?></b><?php elseif ($it['mapped']): ?><?= h($row[9]) ?><?php endif; ?></div></div>
  <?= chartSvg($it, $data[$it['itemid']] ?? [], $r) ?>
</div>
<?php endforeach; ?>
</div>

<?php if ($r['table']):
    $hdr = seriesHeader($r);
    $rows = iterator_to_array(seriesRows($db, $r, $data), false);
    // Drop leading/trailing steps where no metric has data (e.g. before monitoring of a device started).
    $hasData = fn($line) => count(array_filter(array_slice($line, 1), fn($c) => $c !== '')) > 0;
    while ($rows && !$hasData($rows[0])) array_shift($rows);
    while ($rows && !$hasData(end($rows))) array_pop($rows);
    $trimmed = $rows ? date('d M Y H:i:s', strtotime($rows[0][0])) . ' – ' . date('d M Y H:i:s', strtotime(end($rows)[0])) : '';
    // Column metadata for the header: host on a separate line, metric + aggregate below.
    $cols = [];
    foreach ($r['items'] as $it) {
        $aggs = $it['mapped'] ? ['state'] : $r['aggs'];
        foreach ($aggs as $a) {
            $unit = $it['unit'] !== '' && !str_ends_with($it['name'], "({$it['unit']})") ? " ({$it['unit']})" : '';
            $cols[] = ['host' => $it['host'], 'name' => $it['name'] . $unit . (count($aggs) > 1 ? ' · ' . $a : '')];
        }
    }
    $blocks = array_chunk(array_keys($cols), PDF_COLS_PER_TABLE);
    foreach ($blocks as $bi => $block): ?>
<div class="section">
<h2>Data table<?= count($blocks) > 1 ? ' (' . ($bi + 1) . ' of ' . count($blocks) . ')' : '' ?></h2>
<p class="sub">One row per <?= h(strtolower($stepTxt)) ?> (<?= h(strtolower($aggTxt)) ?>) &middot; <?= $trimmed !== '' ? 'data from ' . h($trimmed) . ' IST' : 'no data in this period' ?> &middot; empty cell = no data in that step</p>
<table class="data"><thead><tr><th>Time (IST)</th><?php foreach ($block as $c): ?><th class="n"><span class="host"><?= h($cols[$c]['host']) ?></span><?= h($cols[$c]['name']) ?></th><?php endforeach; ?></tr></thead><tbody>
<?php foreach ($rows as $line): ?><tr><td><?= date('d M H:i:s', strtotime($line[0])) ?></td><?php foreach ($block as $c): ?><td class="n"><?= h($line[$c + 1]) ?></td><?php endforeach; ?></tr>
<?php endforeach; ?></tbody></table>
</div>
<?php endforeach; endif; ?>
</body></html>
<?php
    return htmlToPdf(ob_get_clean());
}

// ---- Dashboard PDF ---------------------------------------------------------------------------------
// Zabbix's own print view of a dashboard (zabbix.php?action=dashboard.print, the page Zabbix scheduled reports use) is
// rendered by zabbix-web-service as the logged-in user: their API session id is put in a zbx_session cookie signed with
// the frontend session key, exactly as the Zabbix server does for scheduled reports. One PDF page per dashboard page.

function run(array $cmd, array $env = []): void {
    $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env ?: null);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    if (proc_close($p) !== 0) throw new RuntimeException('PDF tool failed: ' . trim(substr($out, 0, 300)));
}

function duration(int $s): string {
    $parts = [];
    foreach (['day' => 86400, 'hour' => 3600, 'minute' => 60] as $u => $n) {
        if ($s >= $n) { $v = intdiv($s, $n); $s %= $n; $parts[] = "$v $u" . ($v > 1 ? 's' : ''); }
    }
    return implode(' ', array_slice($parts, 0, 2)) ?: 'under a minute';
}

// $contents: [title, first PDF page number] per section
function coverHtml(array $dash, array $contents, int $from, int $to): string {
    $rows = '';
    foreach ($contents as [$name, $pageNo]) {
        $rows .= '<tr><td>' . h($name !== '' ? $name : $dash['name']) . '</td><td>' . $pageNo . '</td></tr>';
    }
    $period = h(date('d M Y, H:i', $from)) . ' &ndash; ' . h(date('d M Y, H:i', $to)) . ' IST';
    return '<!doctype html><html><head><meta charset="utf-8"><style>
@page { size: 1470pt 1048pt; margin: 0; }
* { box-sizing: border-box; }
body { margin: 0; width: 1470pt; height: 1048pt; font-family: "Noto Sans", "DejaVu Sans", sans-serif; color: #1f2933;
       -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.band { background: #0b4f8a; color: #fff; padding: 150pt 110pt 70pt; }
.kicker { font-size: 20pt; letter-spacing: .14em; text-transform: uppercase; opacity: .8; }
h1 { font-size: 64pt; margin: 18pt 0 0; font-weight: 700; }
.body { padding: 60pt 110pt; display: grid; grid-template-columns: 1fr 1fr; gap: 80pt; }
.label { font-size: 15pt; text-transform: uppercase; letter-spacing: .1em; color: #616e7c; margin: 0 0 8pt; }
.value { font-size: 26pt; margin: 0 0 34pt; }
table { width: 100%; border-collapse: collapse; font-size: 20pt; }
td { padding: 10pt 0; border-bottom: 1pt solid #d9e0e7; }
td:last-child { text-align: right; color: #616e7c; width: 80pt; }
.foot { position: absolute; bottom: 50pt; left: 110pt; right: 110pt; font-size: 14pt; color: #9aa5b1;
        border-top: 1pt solid #d9e0e7; padding-top: 14pt; }
</style></head><body>
<div class="band"><div class="kicker">Network monitoring report</div><h1>' . h($dash['name']) . '</h1></div>
<div class="body"><div>
<p class="label">Reporting period</p><p class="value">' . $period . '</p>
<p class="label">Duration</p><p class="value">' . h(duration($to - $from)) . '</p>
<p class="label">Generated</p><p class="value">' . h(date('d M Y, H:i')) . ' IST by ' . h($_SESSION['user']) . '</p>
</div><div><p class="label">Contents</p><table>' . $rows . '</table></div></div>
<div class="foot">Source: Zabbix &middot; isp.picloud.in &middot; values and graphs cover the reporting period above</div>
</body></html>';
}

// $details: 'active' / 'all' adds per-port and per-item charts after each page with item lists (see detailPdf), 'none' does not.
function dashboardPdf(mysqli $db, array $dash, array $pick, int $from, int $to, string $details = 'active'): string {
    $sid = (string)$_SESSION['token'];
    $key = (string)$db->query('SELECT session_key FROM config')->fetch_row()[0];
    $cookie = base64_encode(json_encode(['sessionid' => $sid, 'sign' => hash_hmac('sha256', json_encode(['sessionid' => $sid]), $key)]));
    $url = FRONTEND . 'zabbix.php?' . http_build_query(['action' => 'dashboard.print', 'dashboardid' => $dash['dashboardid'],
        'from' => date('Y-m-d H:i:s', $from), 'to' => date('Y-m-d H:i:s', $to)]);
    $ch = curl_init(WEB_SERVICE);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 120,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['url' => $url, 'headers' => ['Cookie' => "zbx_session=$cookie"],
            'parameters' => ['width' => '1920', 'height' => '1080']])]);
    $pdf = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($pdf === false || $code !== 200 || !str_starts_with($pdf, '%PDF')) {
        $detail = is_string($pdf) ? (json_decode($pdf, true)['detail'] ?? substr($pdf, 0, 200)) : curl_error($ch);
        throw new RuntimeException("Dashboard rendering failed ($code): $detail");
    }

    $dir = sys_get_temp_dir() . '/zbxreport-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700);
    try {
        file_put_contents("$dir/dash.pdf", $pdf);
        run(['pdfseparate', "$dir/dash.pdf", "$dir/p-%d.pdf"]);
        $files = glob("$dir/p-*.pdf");
        natsort($files);
        $files = array_values($files);
        $names = array_column($dash['pages'], 'name');
        $parts = $contents = [];
        $pageNo = 2;                                    // page 1 is the cover
        if (count($files) === count($names)) {          // one PDF page per dashboard page: keep the chosen ones
            foreach ($pick ?: array_keys($names) as $k) {
                $label = $names[$k] !== '' ? $names[$k] : $dash['name'];
                $parts[] = $files[$k];
                $contents[] = [$label, $pageNo++];
                $extra = $details === 'none' ? null : detailPdf($db, $label, $dash['pages'][$k], $from, $to, $details);
                if ($extra !== null) {
                    file_put_contents("$dir/d-$k.pdf", $extra);
                    $parts[] = "$dir/d-$k.pdf";
                    $contents[] = ["$label – port and item charts", $pageNo];
                    $pageNo += preg_match('/^Pages:\s+(\d+)/m', (string)shell_exec('pdfinfo ' . escapeshellarg("$dir/d-$k.pdf")), $m) ? (int)$m[1] : 1;
                }
            }
        } else {
            $parts = $files;
            foreach ($files as $i => $_) $contents[] = [$dash['name'], $i + 2];
        }
        file_put_contents("$dir/cover.html", coverHtml($dash, $contents, $from, $to));
        run([CHROME, '--headless=new', '--no-sandbox', '--disable-gpu', '--no-pdf-header-footer', '--user-data-dir=' . "$dir/chrome",
            "--print-to-pdf=$dir/cover.pdf", "file://$dir/cover.html"], ['HOME' => $dir, 'PATH' => '/usr/bin:/bin']);
        run(array_merge(['pdfunite', "$dir/cover.pdf"], $parts, ["$dir/out.pdf"]));
        return file_get_contents("$dir/out.pdf");
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

// ---- Per-port and per-item charts for the Dashboard PDF ------------------------------------------------
// The print view shows an item navigator ("Interfaces ... by port", "Health and hardware", "Items on this page") only as
// a list of current values. For every dashboard page with such lists, detail pages are added after it: one panel per
// interface (traffic in/out chart, errors/discards chart, speed, time up) and one chart per other item.

const PORT_ROLES = ['Bits received' => 'in', 'Bits sent' => 'out', 'Inbound packets with errors' => 'inerr',
    'Outbound packets with errors' => 'outerr', 'Inbound packets discarded' => 'indisc', 'Outbound packets discarded' => 'outdisc',
    'Operational status' => 'oper', 'Port state' => 'state', 'Speed' => 'speed'];
const PORT_SKIP = ['Admin status', 'Interface type', 'Duplex status'];   // static, shown via Port state / not charted
const PORT_STATE = [1 => 'up', 2 => 'down', 3 => 'testing', 5 => 'dormant', 6 => 'no module', 7 => 'lower layer down', 8 => 'shutdown'];
const ERR_SERIES = [['inerr', 'In errors', '#e5484d'], ['outerr', 'Out errors', '#f97316'],
                    ['indisc', 'In discards', '#7c3aed'], ['outdisc', 'Out discards', '#0ea5e9']];

// Step for the detail charts: about 300 points; up to ~1 day from history (a whole switch fabric then takes ~2 min),
// beyond that from hourly trends.
function detailStep(int $span): array {
    if ($span <= 26 * 3600) {
        foreach ([60, 120, 300, 600, 900, 1800, 3600] as $s) if ($span / $s <= 300) return [$s, false];
        return [3600, false];
    }
    return [max(1, (int)ceil($span / 300 / 3600)) * 3600, true];
}

function patternRegex(string $p): string {
    return '/^' . str_replace('\\*', '.*', preg_quote($p, '/')) . '$/i';
}

// Items listed by the item navigators on one dashboard page (as the logged-in user may see them).
function navigatorItems(array $page): array {
    $out = [];
    foreach ($page['widgets'] ?? [] as $w) {
        if ($w['type'] !== 'itemnavigator') continue;
        $hostids = $groupids = $pats = [];
        foreach ($w['fields'] as $f) {
            if (preg_match('/^hostids\\.\\d+$/', $f['name'])) $hostids[] = $f['value'];
            elseif (preg_match('/^groupids\\.\\d+$/', $f['name'])) $groupids[] = $f['value'];
            elseif (preg_match('/^items\\.\\d+$/', $f['name'])) $pats[] = patternRegex($f['value']);
        }
        if (!$hostids && !$groupids) continue;
        $sel = $hostids ? ['hostids' => $hostids] : ['groupids' => $groupids];
        $items = api('item.get', $sel + ['output' => ['itemid', 'hostid', 'name', 'units', 'value_type', 'lastvalue', 'trends'],
            'selectHosts' => ['name'], 'selectValueMap' => ['mappings'],
            'filter' => ['status' => 0, 'value_type' => [0, 3]], 'monitored' => true]);
        foreach ($items as $it) {
            if ($pats && !array_filter($pats, fn($re) => preg_match($re, $it['name']))) continue;
            $it['host'] = $it['hosts'][0]['name'] ?? '';
            $it['mapped'] = !empty($it['valuemap']['mappings']);
            [$it['unit'], $it['factor']] = $it['mapped'] ? ['', 1.0] : ($it['units'] === 'uptime' ? ['days', 1 / 86400] : unitConv($it['units'], true));
            $out[$it['itemid']] = $it;
        }
    }
    return array_values($out);
}

// Interface items grouped per port; everything else stays a single-item chart.
function splitPorts(array $items): array {
    $ports = $others = [];
    foreach ($items as $it) {
        if (preg_match('/^Interface (.+?): (.+)$/', $it['name'], $m)) {
            if (in_array($m[2], PORT_SKIP, true)) continue;
            if (isset(PORT_ROLES[$m[2]])) {
                $k = $it['host'] . "\x00" . $m[1];
                $ports[$k] ??= ['host' => $it['host'], 'port' => $m[1]];
                $ports[$k][PORT_ROLES[$m[2]]] = $it;
                continue;
            }
        }
        $others[] = $it;
    }
    uasort($ports, fn($a, $b) => [$a['host'], 0] <=> [$b['host'], 0] ?: strnatcasecmp($a['port'], $b['port']));
    usort($others, fn($a, $b) => [$a['host'], $a['name']] <=> [$b['host'], $b['name']]);
    return [array_values($ports), $others];
}

// Several numeric series on one chart (bucket averages as lines).
function multiSvg(array $series, array $r, int $H): string {
    [$W, $L, $R, $T, $B] = [1000, 70, 12, 8, 24];
    [$pw, $ph] = [$W - $L - $R, $H - $T - $B];
    $span = $r['to'] - $r['from'];
    $vals = [0.0];
    foreach ($series as $s) foreach ($s['data'] as $v) $vals[] = $v[0] * $s['factor'];
    $hi = max($vals);
    if ($hi <= 0 || !is_finite($hi)) $hi = 1;
    $st = niceStep($hi, 4);
    $hi = ceil($hi / $st) * $st;
    $x = fn($t) => round($L + ($t - $r['from']) / $span * $pw, 1);
    $y = fn($v) => round($T + $ph - $v / $hi * $ph, 1);
    $svg = "<svg viewBox=\"0 0 $W $H\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"Noto Sans, DejaVu Sans, sans-serif\" font-size=\"12\">";
    for ($v = 0, $n = 0; $v <= $hi + $st / 2 && $n < 20; $v += $st, $n++) {
        $yy = $y($v);
        $svg .= "<line x1=\"$L\" x2=\"" . ($W - $R) . "\" y1=\"$yy\" y2=\"$yy\" stroke=\"#e3e8ee\"/><text x=\"" . ($L - 6) . "\" y=\"" . ($yy + 4)
            . "\" text-anchor=\"end\" fill=\"#616e7c\">" . h(axisNum($v)) . '</text>';
    }
    foreach ([300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 1209600] as $tick) {
        if ($span / $tick <= 8) break;
    }
    $fmtT = $tick >= 86400 ? 'd M' : ($span > 86400 ? 'd M H:i' : 'H:i');
    for ($t = bucketStart($r['from'], $tick) + $tick; $t < $r['to']; $t += $tick) {
        $xx = $x($t);
        $svg .= "<line x1=\"$xx\" x2=\"$xx\" y1=\"$T\" y2=\"" . ($T + $ph) . "\" stroke=\"#eef1f4\"/><text x=\"$xx\" y=\"" . ($H - 8)
            . "\" text-anchor=\"middle\" fill=\"#616e7c\">" . date($fmtT, $t) . '</text>';
    }
    $svg .= "<line x1=\"$L\" x2=\"" . ($W - $R) . "\" y1=\"" . ($T + $ph) . "\" y2=\"" . ($T + $ph) . "\" stroke=\"#9aa5b1\"/>";
    $gap = 1.5 * (int)$r['step'];
    foreach ($series as $s) {
        ksort($s['data']);
        $segs = [];
        $prev = null;
        foreach ($s['data'] as $t => $v) {
            if ($prev === null || $t - $prev > $gap) $segs[] = [];
            $segs[count($segs) - 1][] = $x($t + (int)$r['step'] / 2) . ',' . $y($v[0] * $s['factor']);
            $prev = $t;
        }
        foreach ($segs as $seg) {
            $svg .= count($seg) === 1
                ? '<circle cx="' . explode(',', $seg[0])[0] . '" cy="' . explode(',', $seg[0])[1] . "\" r=\"2\" fill=\"{$s['color']}\"/>"
                : '<polyline points="' . implode(' ', $seg) . "\" fill=\"none\" stroke=\"{$s['color']}\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/>";
        }
    }
    return $svg . '</svg>';
}

function avgMax(array $data, float $f): array {   // [avg, max] of the bucket averages
    if (!$data) return [null, null];
    $a = array_column($data, 0);
    return [array_sum($a) / count($a) * $f, max($a) * $f];
}

function rate(?float $v, string $unit): string {
    if ($v === null) return '–';
    if ($unit === 'Mbps') return $v >= 1000 ? fmt(round($v / 1000, 2)) . ' Gbps' : fmt(round($v, 2)) . ' Mbps';
    return fmt(round($v, 2)) . ($unit !== '' ? " $unit" : '');
}

function portPanel(array $p, array $data, array $r): string {
    $d = fn($role) => isset($p[$role]) ? ($data[$p[$role]['itemid']] ?? []) : [];
    [$name, $alias] = preg_match('/^(.*?)\\((.*)\\)$/', $p['port'], $m) ? [$m[1], $m[2]] : [$p['port'], ''];
    $facts = [];
    if (isset($p['speed']) && (float)$p['speed']['lastvalue'] > 0) $facts[] = 'speed ' . rate((float)$p['speed']['lastvalue'] / 1e6, 'Mbps');
    $oper = $d('oper');
    if ($oper) {
        $up = count(array_filter($oper, fn($v) => (int)round($v[3]) === 1));
        $facts[] = 'up ' . fmt(round(100 * $up / count($oper), 1)) . '% of the period';
    }
    if (isset($p['state'])) $facts[] = 'now ' . (PORT_STATE[(int)$p['state']['lastvalue']] ?? $p['state']['lastvalue']);
    $in = $p['in'] ?? null;
    $out = $p['out'] ?? null;
    $f = $in['factor'] ?? ($out['factor'] ?? 1.0);
    $unit = $in['unit'] ?? ($out['unit'] ?? '');
    $series = [];
    if ($in) $series[] = ['data' => $d('in'), 'factor' => $f, 'color' => '#0b6bcb'];
    if ($out) $series[] = ['data' => $d('out'), 'factor' => $f, 'color' => '#f59e0b'];
    [$ia, $im] = avgMax($d('in'), $f);
    [$oa, $om] = avgMax($d('out'), $f);
    $html = '<div class="port"><div class="ph"><span class="pn">' . h($name) . '</span>' . ($alias !== '' ? ' <span class="pa">' . h($alias) . '</span>' : '')
        . ' <span class="ho">· ' . h($p['host']) . '</span><span class="pf">' . h(implode(' · ', $facts)) . '</span></div>';
    if ($series && ($d('in') || $d('out'))) {
        $html .= '<div class="lg"><span class="sw" style="background:#0b6bcb"></span>in avg <b>' . rate($ia, $unit) . '</b> max <b>' . rate($im, $unit)
            . '</b><span class="sw" style="background:#f59e0b"></span>out avg <b>' . rate($oa, $unit) . '</b> max <b>' . rate($om, $unit) . '</b></div>'
            . multiSvg($series, $r, 150);
    } else {
        $html .= '<div class="nodata">No traffic data in this period</div>';
    }
    $err = [];
    $tot = [];
    foreach (ERR_SERIES as [$role, $label, $color]) {
        if (!isset($p[$role])) continue;
        $err[] = ['data' => $d($role), 'factor' => 1.0, 'color' => $color, 'label' => $label];
        $tot[] = $label . ' max <b>' . fmt(round(avgMax($d($role), 1.0)[1] ?? 0, 2)) . '/s</b>';
    }
    $any = array_filter($err, fn($s) => $s['data'] && max(array_column($s['data'], 0)) > 0);
    if ($any) {
        $html .= '<div class="lg">' . implode('', array_map(fn($s, $t) => "<span class=\"sw\" style=\"background:{$s['color']}\"></span>$t", $err, $tot))
            . '</div>' . multiSvg($err, $r, 95);
    } elseif ($err) {
        $html .= '<div class="ok">No errors or discards in this period</div>';
    }
    return $html . '</div>';
}

function itemPanel(array $it, array $data, array $r): string {
    $st = '';
    if ($data && !$it['mapped']) {
        $a = array_column($data, 0);
        $u = $it['unit'] !== '' ? ' ' . $it['unit'] : '';
        $v = fn(float $x) => h(fmt(round($x * $it['factor'], 2)) . $u);
        $st = 'min <b>' . $v(min(array_column($data, 1))) . '</b> avg <b>' . $v(array_sum($a) / count($a)) . '</b> max <b>' . $v(max(array_column($data, 2))) . '</b>';
    } elseif ($data) {
        $st = 'now <b>' . h(label($it, $it['lastvalue'])) . '</b>';
    }
    return '<div class="item"><div class="ph"><span class="pn">' . h($it['name']) . '</span> <span class="ho">· ' . h($it['host'])
        . ($it['unit'] !== '' ? ' · ' . h($it['unit']) : '') . '</span></div><div class="lg">' . $st . '</div>' . chartSvg($it, $data, $r) . '</div>';
}

// Detail pages for one dashboard page, or null when the page has no item lists (or nothing to show).
function detailPdf(mysqli $db, string $title, array $page, int $from, int $to, string $mode): ?string {
    [$ports, $others] = splitPorts(navigatorItems($page));
    if (!$ports && !$others) return null;
    [$step, $trends] = detailStep($to - $from);
    $r = ['from' => $from, 'to' => $to, 'step' => (string)$step, 'trends' => $trends, 'aggs' => ['avg']];
    $all = $others;
    foreach ($ports as $p) foreach (PORT_ROLES as $role) if (isset($p[$role]) && $role !== 'speed' && $role !== 'state') $all[] = $p[$role];
    // Items that keep no trends (most status items) always come from history.
    $noTrends = array_filter($all, fn($i) => $trends && preg_match('/^0[smhdw]?$/', $i['trends']));
    $data = $all ? fetchBuckets($db, ['items' => array_diff_key($all, $noTrends)] + $r) : [];
    if ($noTrends) $data += fetchBuckets($db, ['items' => $noTrends, 'trends' => false] + $r);
    if ($mode === 'active') {   // ports that carried traffic in the period
        $busy = fn($p) => array_filter(['in', 'out'], fn($k) => isset($p[$k]) && array_filter($data[$p[$k]['itemid']] ?? [], fn($v) => $v[2] > 0));
        $total = count($ports);
        $ports = array_values(array_filter($ports, $busy));
        $skipped = $total - count($ports);
    }
    $stepTxt = $trends ? ($step / 3600) . '-hour averages from hourly trends' : duration($step) . ' averages';
    $period = date('d M Y, H:i', $from) . ' – ' . date('d M Y, H:i', $to) . ' IST';
    $html = '<!doctype html><html><head><meta charset="utf-8"><style>
@page { size: 1470pt 1048pt; margin: 34pt 40pt; }
* { box-sizing: border-box; }
body { margin: 0; font: 11pt/1.35 "Noto Sans", "DejaVu Sans", sans-serif; color: #1f2933; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
h2 { font-size: 20pt; color: #0b4f8a; margin: 0 0 2pt; }
.sub { color: #616e7c; margin: 0 0 12pt; }
h3 { font-size: 14pt; margin: 6pt 0 8pt; color: #0b4f8a; break-after: avoid; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10pt 14pt; }
.grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10pt 14pt; }
.port, .item { break-inside: avoid; border: 1pt solid #e3e8ee; border-radius: 5pt; padding: 6pt 9pt 2pt; }
.ph { display: flex; gap: 6pt; align-items: baseline; flex-wrap: wrap; }
.pn { font-weight: 700; font-size: 12pt; } .pa { font-weight: 600; color: #0b4f8a; } .ho { color: #616e7c; font-size: 9.5pt; }
.pf { margin-left: auto; color: #616e7c; font-size: 9.5pt; }
.lg { color: #616e7c; font-size: 9pt; margin: 2pt 0 0; } .lg b { color: #1f2933; font-weight: 600; margin-right: 6pt; }
.sw { display: inline-block; width: 12pt; height: 5pt; vertical-align: middle; margin: 0 4pt 0 2pt; border-radius: 2pt; }
svg { width: 100%; height: auto; display: block; }
.nodata, .ok { color: #9aa5b1; font-size: 9.5pt; padding: 4pt 0 6pt; } .ok { color: #2e9e5b; }
</style></head><body>
<h2>' . h($title) . ' – charts per ' . ($ports ? 'port and item' : 'item') . '</h2>
<p class="sub">' . h($period) . ' · ' . h($stepTxt) . ($mode === 'active' && !empty($skipped) ? ' · ' . $skipped . ' port(s) without traffic in this period left out' : '')
        . ' · lines show the average of each step; gaps mean no data</p>';
    if ($ports) {
        $html .= '<h3>Interfaces (' . count($ports) . ')</h3><div class="grid">';
        foreach ($ports as $p) $html .= portPanel($p, $data, $r);
        $html .= '</div>';
    }
    if ($others) {
        $html .= '<h3>Items (' . count($others) . ')</h3><div class="grid3">';
        foreach ($others as $it) $html .= itemPanel($it, $data[$it['itemid']] ?? [], $r);
        $html .= '</div>';
    }
    return htmlToPdf($html . '</body></html>');
}

// ---- Routing ------------------------------------------------------------------------------------------
if (defined('REPORTS_LIB')) return;

$error = null;

if (isset($_GET['logout'])) {
    if (!empty($_SESSION['token'])) { try { api('user.logout', []); } catch (Throwable) {} }
    $_SESSION = [];
    session_destroy();
    header('Location: ./');
    exit;
}

if (($_POST['action'] ?? '') === 'login') {
    try {
        if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) throw new RuntimeException('Session expired, please try again.');
        $user = trim((string)($_POST['username'] ?? ''));
        $token = api('user.login', ['username' => $user, 'password' => (string)($_POST['password'] ?? '')], false);
        session_regenerate_id(true);
        $_SESSION['token'] = $token;
        $_SESSION['user'] = $user;
        header('Location: ./');
        exit;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$loggedIn = !empty($_SESSION['token']);

try {
    if ($loggedIn && isset($_GET['ajax']) && $_GET['ajax'] === 'items') {
        header('Content-Type: application/json');
        $hostids = array_values(array_filter(array_map('intval', explode(',', (string)($_GET['hostids'] ?? '')))));
        $items = $hostids ? api('item.get', ['hostids' => $hostids, 'output' => ['itemid', 'hostid', 'name', 'key_', 'delay', 'units'],
            'filter' => ['status' => 0, 'value_type' => [0, 3]], 'sortfield' => 'name']) : [];
        echo json_encode(array_map(fn($i) => [$i['itemid'], $i['hostid'], $i['name'], $i['key_'], $i['delay'], ltrim($i['units'], '!')], $items));
        exit;
    }

    $preview = null;
    if ($loggedIn && ($_POST['action'] ?? '') === 'pdf') {
        try {
            if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) throw new RuntimeException('Session expired, please reload the page.');
            $from = parseTime((string)($_POST['from'] ?? ''));
            $to = min(parseTime((string)($_POST['to'] ?? '')), time());
            if ($from >= $to) throw new InvalidArgumentException('"From" must be before "To".');
            if ($to - $from > 366 * 86400) throw new InvalidArgumentException('Maximum range is one year.');
            $dash = api('dashboard.get', ['dashboardids' => [(int)($_POST['dashboardid'] ?? 0)], 'output' => ['dashboardid', 'name'],
                'selectPages' => 'extend'])[0] ?? null;
            if (!$dash) throw new InvalidArgumentException('Choose a dashboard.');
            $pick = array_values(array_unique(array_filter(array_map('intval', (array)($_POST['pages'] ?? [])), fn($i) => $i >= 0 && $i < count($dash['pages']))));
            if (count($dash['pages']) > 1 && !$pick) throw new InvalidArgumentException('Select at least one dashboard page.');
            $details = in_array($_POST['details'] ?? '', ['active', 'all', 'none'], true) ? $_POST['details'] : 'active';
            session_write_close();
            set_time_limit(600);
            $pdf = dashboardPdf(db(), $dash, $pick, $from, $to, $details);
            $fname = preg_replace('/[^A-Za-z0-9]+/', '-', $dash['name']) . '-' . date('Ymd-Hi', $from) . '-to-' . date('Ymd-Hi', $to) . '.pdf';
            header('Content-Type: application/pdf');
            header("Content-Disposition: attachment; filename=\"$fname\"");
            header('Content-Length: ' . strlen($pdf));
            header('Cache-Control: no-store');
            echo $pdf;
            exit;
        } catch (InvalidArgumentException | RuntimeException $e) {
            if ($e instanceof AuthExpired) throw $e;
            $error = $e->getMessage();
        }
    }
    if ($loggedIn && ($_POST['action'] ?? '') === 'export') {
        try {
            if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) throw new RuntimeException('Session expired, please reload the page.');
            $r = readRequest();
            $cells = estimateCells($r);
            if ($cells > MAX_CELLS) {
                throw new InvalidArgumentException(sprintf('That report would have about %s values (limit %s). Choose a larger step, a shorter range or fewer items.',
                    number_format($cells), number_format(MAX_CELLS)));
            }
            $db = db();
            if (($_POST['mode'] ?? '') === 'download') {
                session_write_close();
                if ($r['format'] === 'pdf') {
                    $pdf = dataPdf($db, $r);
                    $fname = preg_replace('/[^A-Za-z0-9]+/', '-', $r['title']) . '-' . date('Ymd-Hi', $r['from']) . '-to-'
                        . date('Ymd-Hi', $r['to']) . '-' . $r['step'] . 's.pdf';
                    header('Content-Type: application/pdf');
                    header("Content-Disposition: attachment; filename=\"$fname\"");
                    header('Content-Length: ' . strlen($pdf));
                    header('Cache-Control: no-store');
                    echo $pdf;
                } else {
                    download($db, $r);
                }
                exit;
            }
            $preview = ['r' => $r];
            if ($r['type'] === 'summary') {
                $preview['hdr'] = SUMMARY_HDR;
                $preview['rows'] = summaryRows($db, $r);
                $preview['total'] = count($preview['rows']);
            } else {
                $preview['hdr'] = seriesHeader($r);
                $preview['rows'] = [];
                $total = 0;
                foreach (seriesRows($db, $r) as $row) {
                    if ($total++ < PREVIEW_ROWS) $preview['rows'][] = $row;
                }
                $preview['total'] = $total;
            }
        } catch (InvalidArgumentException | RuntimeException $e) {
            if ($e instanceof AuthExpired) throw $e;
            $error = $e->getMessage();
        }
    }

    if ($loggedIn) {
        $groups = api('hostgroup.get', ['output' => ['name'], 'with_monitored_items' => true,
            'selectHosts' => ['hostid', 'name'], 'sortfield' => 'name']);
        $dashboards = api('dashboard.get', ['output' => ['dashboardid', 'name'], 'selectPages' => ['name'], 'sortfield' => 'name']);
    }
} catch (AuthExpired) {
    $_SESSION = [];
    session_destroy();
    session_start();
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
    $loggedIn = false;
    $error = 'Your Zabbix session expired. Please log in again.';
}

$post = fn(string $k, string $d = '') => h((string)($_POST[$k] ?? $d));
$now = time();
$tab = $_GET['tab'] ?? (($_POST['action'] ?? '') === 'export' ? 'csv' : 'pdf');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zabbix Reports</title>
<style>
:root { --bg:#f4f6f8; --card:#fff; --text:#1f2933; --muted:#616e7c; --line:#d9e0e7; --accent:#0b6bcb; --accent-2:#e8f1fb; --err:#b42318; --err-bg:#fdecea; }
@media (prefers-color-scheme: dark) { :root { --bg:#14181c; --card:#1d2329; --text:#e4e9ee; --muted:#9aa5b1; --line:#323b44; --accent:#5aa4f0; --accent-2:#1d3247; --err:#ffb4ab; --err-bg:#3d1f1c; } }
* { box-sizing: border-box; }
body { margin:0; font:14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background:var(--bg); color:var(--text); }
header { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:12px 20px; background:var(--card); border-bottom:1px solid var(--line); }
header h1 { margin:0; font-size:17px; }
header nav { display:flex; gap:14px; align-items:center; color:var(--muted); font-size:13px; }
a { color:var(--accent); }
main { max-width:1280px; margin:0 auto; padding:16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; margin-bottom:14px; }
.card h2 { margin:0 0 10px; font-size:14px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.grid { display:grid; grid-template-columns: 280px 1fr; gap:14px; }
@media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
.list { border:1px solid var(--line); border-radius:6px; overflow:auto; max-height:420px; }
.list label { display:flex; gap:8px; align-items:flex-start; padding:5px 10px; border-bottom:1px solid var(--line); cursor:pointer; }
.list label:last-child { border-bottom:0; }
.list label:hover { background:var(--accent-2); }
.list .grp { padding:6px 10px; font-weight:600; font-size:12px; color:var(--muted); background:var(--bg); position:sticky; top:0; }
.meta { color:var(--muted); font-size:12px; white-space:nowrap; margin-left:auto; padding-left:8px; }
.row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:10px; }
input[type=text], input[type=password], input[type=datetime-local], select { font:inherit; color:var(--text); background:var(--card); border:1px solid var(--line); border-radius:6px; padding:6px 8px; }
input[type=text].search { flex:1; min-width:200px; }
button, .btn { font:inherit; border:1px solid var(--line); background:var(--card); color:var(--text); padding:6px 12px; border-radius:6px; cursor:pointer; }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
button.chip { padding:3px 10px; border-radius:20px; font-size:12px; }
button:hover { filter:brightness(.97); }
.opts { display:grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap:14px; }
.opts fieldset { border:1px solid var(--line); border-radius:6px; margin:0; padding:10px 12px; }
.opts legend { font-weight:600; padding:0 4px; }
.opts label { display:block; margin:3px 0; }
.err { background:var(--err-bg); color:var(--err); border-radius:6px; padding:10px 12px; margin-bottom:14px; }
.hint { color:var(--muted); font-size:12px; }
.tablewrap { overflow:auto; max-height:520px; border:1px solid var(--line); border-radius:6px; }
table { border-collapse:collapse; font-size:12px; font-variant-numeric: tabular-nums; }
th, td { padding:5px 8px; border-bottom:1px solid var(--line); white-space:nowrap; text-align:right; }
th { position:sticky; top:0; background:var(--bg); text-align:left; font-weight:600; max-width:260px; white-space:normal; }
td:first-child, th:first-child { text-align:left; }
.login { max-width:360px; margin:60px auto; }
.login input { width:100%; margin-bottom:10px; }
.count { font-weight:600; }
.tabs { display:flex; gap:4px; margin-bottom:14px; border-bottom:1px solid var(--line); }
.tabs a { padding:8px 16px; text-decoration:none; color:var(--muted); border-bottom:2px solid transparent; font-weight:600; }
.tabs a.on { color:var(--accent); border-bottom-color:var(--accent); }
.pages label { display:inline-flex; gap:6px; align-items:center; margin:3px 14px 3px 0; }
#busy { display:none; }
</style>
</head>
<body>
<header>
  <h1>Zabbix Reports</h1>
  <nav><a href="/zabbix/">Zabbix</a><?php if ($loggedIn): ?><span><?= h($_SESSION['user']) ?></span><a href="?logout=1">Log out</a><?php endif; ?></nav>
</header>
<main>
<?php if ($error): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

<?php if (!$loggedIn): ?>
  <form class="card login" method="post" autocomplete="on">
    <h2>Log in with your Zabbix account</h2>
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
    <input type="text" name="username" placeholder="Username" required autofocus>
    <input type="password" name="password" placeholder="Password" required>
    <button class="primary" type="submit">Log in</button>
  </form>
<?php else: ?>
<nav class="tabs"><a href="?tab=pdf" class="<?= $tab === 'pdf' ? 'on' : '' ?>">Dashboard PDF</a><a href="?tab=csv" class="<?= $tab === 'csv' ? 'on' : '' ?>">Data report (PDF / CSV)</a></nav>
<?php if ($tab === 'pdf'): ?>
<form method="post" id="pf" class="card">
  <h2>Dashboard report (PDF)</h2>
  <input type="hidden" name="action" value="pdf">
  <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
  <div class="row">
    <label>Dashboard <select name="dashboardid" id="dash">
      <?php foreach ($dashboards as $d): ?><option value="<?= h($d['dashboardid']) ?>" <?= ($_POST['dashboardid'] ?? '') === $d['dashboardid'] ? 'selected' : '' ?>><?= h($d['name']) ?></option><?php endforeach; ?>
    </select></label>
  </div>
  <div class="row pages" id="pages"></div>
  <div class="row">
    <label>From <input type="datetime-local" name="from" id="from" required value="<?= $post('from', date('Y-m-d\TH:i', $now - 86400)) ?>"></label>
    <label>To <input type="datetime-local" name="to" id="to" required value="<?= $post('to', date('Y-m-d\TH:i', $now)) ?>"></label>
    <span class="hint">IST</span>
  </div>
  <div class="row" id="ranges"></div>
  <div class="row">
    <label>Charts for every port and item in the page's lists
      <select name="details">
        <?php $det = $_POST['details'] ?? 'active'; foreach (['active' => 'Yes – ports that carried traffic, plus all items', 'all' => 'Yes – all ports, plus all items', 'none' => 'No – dashboard pages only'] as $k => $v): ?>
          <option value="<?= $k ?>" <?= $det === $k ? 'selected' : '' ?>><?= h($v) ?></option>
        <?php endforeach; ?>
      </select></label>
    <span class="hint">Pages with interface, hardware or item lists get extra pages after them: one panel per port (traffic in/out, errors/discards, speed, time up) and one chart per other item.</span>
  </div>
  <div class="row" style="margin-top:14px">
    <button type="submit" class="primary">Download PDF</button>
    <span class="hint" id="busy">Rendering the dashboard and charts, this takes up to a few minutes for switch pages…</span>
    <span class="hint" id="idle">A cover page with the reporting period, then each dashboard tab exactly as in Zabbix, followed by its port and item charts.</span>
  </div>
</form>
<script>
const DASH = <?= json_encode(array_column(array_map(fn($d) => [$d['dashboardid'], array_column($d['pages'], 'name')], $dashboards), 1, 0)) ?>;
const PICKED = new Set(<?= json_encode(array_map('strval', (array)($_POST['pages'] ?? []))) ?>);
</script>
<?php else: ?>
<form method="post" id="f">
  <input type="hidden" name="action" value="export">
  <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
  <input type="hidden" name="mode" id="mode" value="preview">

  <div class="card">
    <h2>Quick picks</h2>
    <div class="row" id="presets"></div>
    <div class="hint">A quick pick selects the matching hosts and items. You can still add or remove items below.</div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>1 · Hosts</h2>
      <div class="list" id="hosts">
        <?php foreach ($groups as $g): if (!$g['hosts']) continue; ?>
          <div class="grp"><?= h($g['name']) ?></div>
          <?php usort($g['hosts'], fn($a, $b) => strcmp($a['name'], $b['name'])); foreach ($g['hosts'] as $hst): ?>
            <label><input type="checkbox" class="host" value="<?= h($hst['hostid']) ?>" data-name="<?= h($hst['name']) ?>"> <?= h($hst['name']) ?></label>
          <?php endforeach; ?>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="card">
      <h2>2 · Items</h2>
      <div class="row">
        <input type="text" class="search" id="q" placeholder="Filter items, e.g. Airtel download, Port-Channel51, latency">
        <button type="button" id="selAll">Select shown</button>
        <button type="button" id="selNone">Clear</button>
        <span class="hint"><span class="count" id="cnt">0</span> selected</span>
      </div>
      <div class="list" id="items"><div class="grp">Select one or more hosts</div></div>
      <div class="hint" style="margin-top:6px">The poll interval is shown next to each item. A step shorter than the poll interval leaves empty rows for that item.</div>
    </div>
  </div>

  <div class="card">
    <h2>3 · Time range and format</h2>
    <div class="row">
      <label>From <input type="datetime-local" name="from" id="from" required value="<?= $post('from', date('Y-m-d\TH:i', $now - 3600)) ?>"></label>
      <label>To <input type="datetime-local" name="to" id="to" required value="<?= $post('to', date('Y-m-d\TH:i', $now)) ?>"></label>
      <span class="hint">IST</span>
    </div>
    <div class="row" id="ranges"></div>
    <div class="opts">
      <fieldset><legend>Step</legend>
        <select name="step" id="step">
          <?php foreach (STEPS as $k => $v): ?><option value="<?= h((string)$k) ?>" <?= (string)($_POST['step'] ?? '60') === (string)$k ? 'selected' : '' ?>><?= h($v) ?></option><?php endforeach; ?>
        </select>
      </fieldset>
      <fieldset><legend>Values per step</legend>
        <?php $sel = (array)($_POST['agg'] ?? ['avg']); foreach (AGGS as $k => $v): ?>
          <label><input type="checkbox" name="agg[]" value="<?= $k ?>" <?= in_array($k, $sel, true) ? 'checked' : '' ?>> <?= $v ?></label>
        <?php endforeach; ?>
        <div class="hint">Status items always export the state at the end of each step.</div>
      </fieldset>
      <fieldset><legend>Output</legend>
        <?php $fmt = $_POST['format'] ?? 'pdf'; ?>
        <label><input type="radio" name="format" value="pdf" <?= $fmt !== 'csv' ? 'checked' : '' ?>> PDF report (summary, charts, data table)</label>
        <label><input type="radio" name="format" value="csv" <?= $fmt === 'csv' ? 'checked' : '' ?>> CSV for Excel</label>
        <div class="pdfopt">
          <label><input type="checkbox" name="table" value="1" <?= ($_POST['action'] ?? '') !== 'export' || !empty($_POST['table']) ? 'checked' : '' ?>> Include data table (one row per step)</label>
          <label>Title <input type="text" name="title" maxlength="80" placeholder="Network data report" value="<?= $post('title') ?>" style="width:100%"></label>
        </div>
      </fieldset>
      <fieldset class="csvopt"><legend>CSV layout</legend>
        <?php $type = $_POST['type'] ?? 'series'; ?>
        <label><input type="radio" name="type" value="series" <?= $type !== 'summary' ? 'checked' : '' ?>> Time series (one row per step)</label>
        <label><input type="radio" name="type" value="summary" <?= $type === 'summary' ? 'checked' : '' ?>> Summary (min / avg / max / 95th percentile per item)</label>
      </fieldset>
      <fieldset><legend>Units</legend>
        <label><input type="checkbox" name="friendly" value="1" <?= ($_POST['action'] ?? '') !== 'export' || !empty($_POST['friendly']) ? 'checked' : '' ?>> bps → Mbps, seconds → ms, bytes → GB</label>
      </fieldset>
    </div>
    <div class="row" style="margin-top:14px">
      <button type="submit" class="primary" id="dl" onclick="document.getElementById('mode').value='download'">Download CSV</button>
      <button type="submit" onclick="document.getElementById('mode').value='preview'">Preview</button>
      <span class="hint">CSV opens directly in Excel. Data is kept for 180 days; up to <?= MAX_ITEMS ?> items per report.</span>
    </div>
  </div>
</form>

<?php if ($preview): ?>
  <div class="card" id="preview">
    <h2>Preview</h2>
    <p><?= h(describe($preview['r'])) ?> — <?= number_format($preview['total']) ?> rows<?= $preview['total'] > count($preview['rows']) ? ', first ' . count($preview['rows']) . ' shown' : '' ?>.</p>
    <div class="tablewrap"><table>
      <thead><tr><?php foreach ($preview['hdr'] as $c): ?><th><?= h((string)$c) ?></th><?php endforeach; ?></tr></thead>
      <tbody><?php foreach ($preview['rows'] as $row): ?><tr><?php foreach ($row as $c): ?><td><?= h((string)$c) ?></td><?php endforeach; ?></tr><?php endforeach; ?></tbody>
    </table></div>
  </div>
<?php endif; ?>

<script>
const selected = new Set(<?= json_encode(array_values(array_map('strval', (array)($_POST['items'] ?? [])))) ?>);
const selectedHosts = new Set(<?= json_encode(array_values(array_map('strval', (array)($_POST['hostsel'] ?? [])))) ?>);
const PRESETS = [
  {label: 'ISP bandwidth (Mbps)', hosts: /A10/i, keys: /^isp\.(mbps\.(in|out)|total\.(in|out))/},
  {label: 'ISP utilisation %', hosts: /A10/i, keys: /^isp\.util\./},
  {label: 'ISP latency & loss', hosts: /A10/i, keys: /^icmpping(sec|loss)\[/},
  {label: 'ISP link status', hosts: /A10/i, keys: /^(isp\.linkup|isp\.net\.if\.status|a10\.llb\.status)\[/},
  {label: 'A10 sessions & conn/s', hosts: /A10/i, keys: /^a10\.llb\.(cps|conns)\[/},
  {label: 'WAN switch uplinks traffic', hosts: /WAN-Switch/i, keys: /^net\.if\.(in|out)\[/, names: /Port-Channel5[12]\b/},
  {label: 'Device CPU & memory', hosts: null, keys: /(cpu\.util|memory\.util|mem\.pused|system\.cpu\.util|vm\.memory\.util)/},
];
const RANGES = [['Last 15 min', 900], ['Last 1 hour', 3600], ['Last 6 hours', 21600], ['Last 24 hours', 86400],
                ['Today', 'today'], ['Yesterday', 'yesterday'], ['Last 7 days', 604800], ['Last 30 days', 2592000],
                ['Last 90 days', 7776000], ['Last 180 days', 15552000]];

let items = [];
const $ = s => document.querySelector(s);
const hostBoxes = () => [...document.querySelectorAll('input.host')];
const pad = n => String(n).padStart(2, '0');
const local = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;

function hostName(id) { const b = hostBoxes().find(b => b.value === id); return b ? b.dataset.name : ''; }

async function loadItems() {
  const ids = hostBoxes().filter(b => b.checked).map(b => b.value);
  if (!ids.length) { items = []; render(); return; }
  $('#items').innerHTML = '<div class="grp">Loading…</div>';
  const r = await fetch('?ajax=items&hostids=' + ids.join(','));
  if (!r.ok) { $('#items').innerHTML = '<div class="grp">Could not load items (session expired? reload the page)</div>'; return; }
  items = (await r.json()).map(([id, hostid, name, key, delay, units]) => ({id, hostid, name, key, delay, units}));
  render();
}

function render() {
  const q = $('#q').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const box = $('#items');
  const shown = items.filter(i => q.every(w => (hostName(i.hostid) + ' ' + i.name + ' ' + i.key).toLowerCase().includes(w)));
  if (!items.length) { box.innerHTML = '<div class="grp">Select one or more hosts</div>'; updateCount(); return; }
  const frag = document.createDocumentFragment();
  let lastHost = null, n = 0;
  for (const i of shown) {
    if (n++ > 3000) { const d = document.createElement('div'); d.className = 'grp'; d.textContent = 'Too many items, refine the filter…'; frag.append(d); break; }
    if (i.hostid !== lastHost) { const d = document.createElement('div'); d.className = 'grp'; d.textContent = hostName(i.hostid); frag.append(d); lastHost = i.hostid; }
    const l = document.createElement('label');
    const c = document.createElement('input'); c.type = 'checkbox'; c.value = i.id; c.checked = selected.has(i.id);
    c.onchange = () => { c.checked ? selected.add(i.id) : selected.delete(i.id); updateCount(); };
    const t = document.createElement('span'); t.textContent = i.name;
    const m = document.createElement('span'); m.className = 'meta'; m.textContent = `every ${i.delay === '0' ? 'calc' : i.delay}${i.units ? ' · ' + i.units : ''}`;
    l.append(c, t, m); frag.append(l);
  }
  box.replaceChildren(frag);
  box.dataset.shown = JSON.stringify(shown.slice(0, 3000).map(i => i.id));
  updateCount();
}

function updateCount() { $('#cnt').textContent = [...selected].filter(id => items.some(i => i.id === id)).length; }

async function applyPreset(p) {
  hostBoxes().forEach(b => { if (!p.hosts || p.hosts.test(b.dataset.name)) b.checked = true; });
  await loadItems();
  selected.clear();
  items.forEach(i => { if ((!p.hosts || p.hosts.test(hostName(i.hostid))) && p.keys.test(i.key) && (!p.names || p.names.test(i.name))) selected.add(i.id); });
  $('#q').value = '';
  render();
}

PRESETS.forEach(p => { const b = document.createElement('button'); b.type = 'button'; b.className = 'chip'; b.textContent = p.label; b.onclick = () => applyPreset(p); $('#presets').append(b); });
RANGES.forEach(([label, v]) => {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'chip'; b.textContent = label;
  b.onclick = () => {
    const now = new Date(); let from, to = now;
    if (v === 'today') { from = new Date(now); from.setHours(0, 0, 0, 0); }
    else if (v === 'yesterday') { to = new Date(now); to.setHours(0, 0, 0, 0); from = new Date(to - 86400000); }
    else from = new Date(now - v * 1000);
    $('#from').value = local(from); $('#to').value = local(to);
  };
  $('#ranges').append(b);
});

hostBoxes().forEach(b => { if (selectedHosts.has(b.value)) b.checked = true; b.onchange = loadItems; });
$('#q').oninput = render;
$('#selAll').onclick = () => { JSON.parse($('#items').dataset.shown || '[]').forEach(id => selected.add(id)); render(); };
$('#selNone').onclick = () => { selected.clear(); render(); };
const syncFormat = () => {
  const pdf = document.querySelector('input[name=format]:checked').value === 'pdf';
  $('#dl').textContent = pdf ? 'Download PDF' : 'Download CSV';
  document.querySelector('.pdfopt').style.display = pdf ? '' : 'none';
  document.querySelector('.csvopt').style.display = pdf ? 'none' : '';
};
document.querySelectorAll('input[name=format]').forEach(r => r.onchange = syncFormat);
syncFormat();
$('#f').onsubmit = e => {
  document.querySelectorAll('#f input.gen').forEach(x => x.remove());
  if (!selected.size) { e.preventDefault(); alert('Select at least one item.'); return; }
  const add = (n, v) => { const x = document.createElement('input'); x.type = 'hidden'; x.className = 'gen'; x.name = n; x.value = v; $('#f').append(x); };
  selected.forEach(id => add('items[]', id));
  hostBoxes().filter(b => b.checked).forEach(b => add('hostsel[]', b.value));
};
if (selectedHosts.size) loadItems();
<?php if ($preview): ?>document.getElementById('preview').scrollIntoView();<?php endif; ?>
</script>
<?php endif; ?>
<script>
// Shared by both tabs: quick time ranges; PDF tab: dashboard page picker.
(() => {
  const $ = s => document.querySelector(s);
  const pad = n => String(n).padStart(2, '0');
  const local = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (!$('#pf')) return;
  [['Last 1 hour', 3600], ['Last 6 hours', 21600], ['Last 24 hours', 86400], ['Today', 'today'], ['Yesterday', 'yesterday'],
   ['Last 7 days', 604800], ['This month', 'month'], ['Last month', 'lastmonth'], ['Last 30 days', 2592000]].forEach(([label, v]) => {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'chip'; b.textContent = label;
    b.onclick = () => {
      const now = new Date(); let from, to = now;
      const midnight = d => { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; };
      if (v === 'today') from = midnight(now);
      else if (v === 'yesterday') { to = midnight(now); from = new Date(to - 86400000); }
      else if (v === 'month') from = new Date(now.getFullYear(), now.getMonth(), 1);
      else if (v === 'lastmonth') { from = new Date(now.getFullYear(), now.getMonth() - 1, 1); to = new Date(now.getFullYear(), now.getMonth(), 1); }
      else from = new Date(now - v * 1000);
      $('#from').value = local(from); $('#to').value = local(to);
    };
    $('#ranges').append(b);
  });
  const pages = () => {
    const names = DASH[$('#dash').value] || [];
    const box = $('#pages'); box.replaceChildren();
    if (names.length < 2) return;
    const t = document.createElement('span'); t.className = 'hint'; t.textContent = 'Pages:'; box.append(t);
    names.forEach((n, i) => {
      const l = document.createElement('label'); const c = document.createElement('input');
      c.type = 'checkbox'; c.name = 'pages[]'; c.value = i; c.checked = !PICKED.size || PICKED.has(String(i));
      l.append(c, n || `Page ${i + 1}`); box.append(l);
    });
    PICKED.clear();
  };
  $('#dash').onchange = pages; pages();
  $('#pf').onsubmit = () => {
    $('#busy').style.display = 'inline'; $('#idle').style.display = 'none';
    setTimeout(() => { $('#busy').style.display = 'none'; $('#idle').style.display = 'inline'; }, 300000);
  };
})();
</script>
<?php endif; ?>
</main>
</body>
</html>
