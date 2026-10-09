// Injected by Apache (zabbix-print-nolinks.conf) into Zabbix's dashboard print view, which zabbix-web-service turns
// into PDFs (/reports Dashboard PDF and Zabbix scheduled reports). Widgets wrap graphs/values in links such as
// history.php?action=showgraph; Chrome keeps those as clickable link areas in the PDF, so strip every href.
(function () {
    function strip(root) {
        root.querySelectorAll('a[href], a[*|href], [onclick]').forEach(function (el) {
            el.removeAttribute('href');
            el.removeAttributeNS('http://www.w3.org/1999/xlink', 'href');
            el.removeAttribute('onclick');
        });
    }
    strip(document);
    new MutationObserver(function () { strip(document); })
        .observe(document.documentElement, {childList: true, subtree: true, attributes: true, attributeFilter: ['href']});
})();
