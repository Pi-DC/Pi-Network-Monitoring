<?php
// Command-line Dashboard PDF for the daily e-mails (send_daily_reports.py): the same PDF as https://isp.picloud.in/reports/
// "Dashboard PDF" with "all ports, plus all items" - every dashboard page followed by one chart panel per port and per item.
// Zabbix's own scheduled reports print only the dashboard as shown on screen, so item lists there are cut off.
//   php daily_pdf.php <dashboardid> <from Y-m-d\TH:i> <to Y-m-d\TH:i> <out.pdf> [all|active|none]
declare(strict_types=1);
if (PHP_SAPI !== 'cli') exit;

const REPORTS_LIB = true;
require '/opt/isp/reports/index.php';
set_time_limit(0);

[, $dashid, $fromS, $toS, $out] = $argv + array_fill(0, 5, '');
$details = $argv[5] ?? 'all';
if (!ctype_digit($dashid) || $out === '' || !in_array($details, ['all', 'active', 'none'], true)) {
    fwrite(STDERR, "usage: php daily_pdf.php <dashboardid> <from> <to> <out.pdf> [all|active|none]\n");
    exit(2);
}

$_SESSION['token'] = api('user.login', ['username' => 'Admin', 'password' => trim(file_get_contents('/root/.credentials/zabbix_admin'))], false);
$_SESSION['user'] = 'daily e-mail schedule';
try {
    $dash = api('dashboard.get', ['dashboardids' => [(int)$dashid], 'output' => ['dashboardid', 'name'], 'selectPages' => 'extend'])[0] ?? null;
    if (!$dash) throw new RuntimeException("dashboard $dashid not found");
    file_put_contents($out, dashboardPdf(db(), $dash, [], parseTime($fromS), parseTime($toS), $details));
} finally {
    try { api('user.logout', []); } catch (Throwable) {}
}
