<?php
// Plain-PHP tests for the pure functions. Run: php tests/run.php
define( 'WP_STRICT_CSP_TESTING', true );
require __DIR__ . '/../wp-strict-csp.php';

$fail = 0;
function check( $name, $cond ) {
	global $fail;
	echo ( $cond ? 'ok   ' : 'FAIL ' ) . $name . "\n";
	if ( ! $cond ) {
		$fail++;
	}
}

$cfg = WP_Strict_CSP::defaults();
$n   = 'abc123';

// Policy
$p = WP_Strict_CSP::build_policy( $cfg, $n );
check( 'policy has nonce + strict-dynamic', false !== strpos( $p, "script-src 'nonce-abc123' 'strict-dynamic'" ) );
check( 'policy has no https: fallback', false === strpos( $p, 'https:' ) );
check( 'policy has no unsafe-inline', false === strpos( $p, 'unsafe-inline' ) );
check( 'policy locks object-src', false !== strpos( $p, "object-src 'none'" ) );
$c               = $cfg;
$c['style_hosts'] = array( 'https://fonts.googleapis.com' );
$c['report_uri']  = 'https://r.example/csp';
$p2              = WP_Strict_CSP::build_policy( $c, $n );
check( 'style host emitted', false !== strpos( $p2, "style-src 'self' 'nonce-abc123' https://fonts.googleapis.com" ) );
check( 'report-uri emitted', false !== strpos( $p2, 'report-uri https://r.example/csp' ) );

// Nonce stable within a request
check( 'nonce stable', WP_Strict_CSP::nonce() === WP_Strict_CSP::nonce() && 32 === strlen( WP_Strict_CSP::nonce() ) );

// with_nonce replaces an existing nonce
check( 'with_nonce replaces', '<script nonce="abc123" src="/a.js">' === WP_Strict_CSP::with_nonce( '<script nonce="old" src="/a.js">', $n ) );
check( 'with_nonce adds', '<style nonce="abc123">' === WP_Strict_CSP::with_nonce( '<style>', $n ) );

// Integrity: known hash applied, unknown host skipped, existing integrity kept
$c                     = $cfg;
$c['integrity_hosts']  = array( 'cdn.example' );
$c['integrity_hashes'] = array( 'https://cdn.example/x.js' => 'sha384-HASH' );
check( 'integrity added', false !== strpos( WP_Strict_CSP::with_integrity( '<script src="https://cdn.example/x.js">', $c ), 'integrity="sha384-HASH" crossorigin="anonymous"' ) );
check( 'other host skipped', '<script src="https://other.example/x.js">' === WP_Strict_CSP::with_integrity( '<script src="https://other.example/x.js">', $c ) );
$t = '<script src="https://cdn.example/x.js" integrity="keep">';
check( 'existing integrity kept', $t === WP_Strict_CSP::with_integrity( $t, $c ) );
// learning mode fetches, hashes, and applies
$c2                     = $c;
$c2['integrity_hashes'] = array();
$c2['learn_integrity']  = true;
$got                    = WP_Strict_CSP::with_integrity( '<script src="https://cdn.example/x.js">', $c2, static function () { return 'body'; } );
check( 'learning computes sha384', false !== strpos( $got, 'sha384-' . base64_encode( hash( 'sha384', 'body', true ) ) ) );
$off                    = $c2;
$off['learn_integrity'] = false;
check( 'learning off leaves tag', '<script src="https://cdn.example/x.js">' === WP_Strict_CSP::with_integrity( '<script src="https://cdn.example/x.js">', $off, static function () { return 'body'; } ) );

// rewrite_html
$html = '<html><head><script>a()</script><script type="application/ld+json">{}</script><link rel="stylesheet" href="/s.css"><link rel="icon" href="/i.png"><style>p{}</style></head><body><p>x</p></body></html>';
$out  = WP_Strict_CSP::rewrite_html( $html, $n, $cfg );
check( 'inline script nonced', false !== strpos( $out, '<script nonce="abc123">a()' ) );
check( 'json script untouched', false !== strpos( $out, '<script type="application/ld+json">' ) );
check( 'stylesheet link nonced', false !== strpos( $out, '<link nonce="abc123" rel="stylesheet"' ) );
check( 'icon link untouched', false !== strpos( $out, '<link rel="icon"' ) );
check( 'style nonced', false !== strpos( $out, '<style nonce="abc123">' ) );
check( 'non-HTML untouched', '{"a":"<script>"}' === WP_Strict_CSP::rewrite_html( '{"a":"<script>"}', $n, $cfg ) );

// hoist_styles
$h   = '<html><head></head><body><p style="color:red;background:url(data:image/png;base64,AA)">a</p><p style="color:red; background:url(data:image/png;base64,AA)" class="k">b</p><div style="margin:0 !important">c</div><script>var s=\'<p style="x:y">\';</script></body></html>';
$out = WP_Strict_CSP::hoist_styles( $h, $n );
check( 'no style attributes remain outside script', 1 === preg_match_all( '/\sstyle=/', $out ) ); // only the one inside the script string
check( 'script content preserved', false !== strpos( $out, '\'<p style="x:y">\'' ) );
check( 'identical styles share a class', 3 === preg_match_all( '/wpcsp-1\b/', $out ) ); // two elements + one rule
check( 'existing class merged', 1 === preg_match( '/class="k wpcsp-1"/', $out ) );
check( 'important appended once', false !== strpos( $out, 'margin:0 !important' ) && false === strpos( $out, '!important !important' ) );
check( 'data: URI semicolon kept', false !== strpos( $out, 'background:url(data:image/png;base64,AA) !important' ) );
check( 'nonced style block in head', 1 === preg_match( '/<style nonce="abc123" id="wp-strict-csp-hoisted">.*<\/style>\n<\/head>/s', $out ) );

exit( $fail ? 1 : 0 );
