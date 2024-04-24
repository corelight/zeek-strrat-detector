signature dpd_strrat {
    ip-proto == tcp
    payload /^[0-9]+\x0d\x0a\x0d\x0a[a-z0-9\-]{4,}\|STRRAT\|/i
    enable "STRRAT"
}
