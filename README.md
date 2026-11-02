# WP Strict CSP

A nonce-based, strict Content Security Policy for WordPress front ends, as a single must-use plugin.
Companion code for the post [Strict CSP for WordPress](https://ryan-iguchi.com/blog/fixing-wordpress-for-csp).

## What it does

- Sends `Content-Security-Policy` on front-end requests (skips `is_admin()`), with one random nonce per request.
- Policy: `default-src 'self'`; `script-src 'nonce-…' 'strict-dynamic'`; `style-src 'self' 'nonce-…'`; `object-src 'none'`; `base-uri`, `form-action` and `frame-ancestors` locked to `'self'`. No `unsafe-inline`, no `https:` fallback. `connect-src` is `'self'` plus whatever you add.
- Adds the nonce to scripts and styles printed through WordPress APIs (`script_loader_tag`, `style_loader_tag`, `wp_script_attributes`, `wp_inline_script_attributes`).
- Adds `sha384` Subresource Integrity to `<script src>` from CDN hosts you list. Hashes can be supplied, or pinned automatically in learning mode.
- Optional compat mode for plugins that echo raw `<script>`/`<style>` tags (see the trade-off below).

## Install

Copy `wp-strict-csp.php` to `wp-content/mu-plugins/`. Start in report-only mode:

```php
// wp-content/mu-plugins/wp-strict-csp-config.php
add_filter( 'wp_strict_csp_config', function ( $c ) {
	$c['report_only']     = true;
	$c['style_hosts']     = array( 'https://fonts.googleapis.com' );
	$c['font_hosts']      = array( 'https://fonts.gstatic.com' );
	$c['integrity_hosts'] = array( 'cdnjs.cloudflare.com' );
	return $c;
} );
```

Watch the browser console, add the origins you need, then set `report_only` to `false`.

## Config keys

| Key | Default | Meaning |
|---|---|---|
| `report_only` | `false` | Send the report-only header instead of enforcing |
| `report_uri` | `''` | Reporting endpoint |
| `script_hosts` | `[]` | Reserved. `strict-dynamic` makes browsers ignore script host lists |
| `style_hosts`, `font_hosts`, `img_hosts`, `frame_hosts`, `connect_hosts` | `[]` | Extra allowed origins for that directive |
| `integrity_hosts` | `[]` | Hostnames whose scripts get an `integrity` attribute |
| `integrity_hashes` | `[]` | `url => 'sha384-…'` |
| `learn_integrity` | `false` | Download unknown scripts once and pin their hash in the `wp_strict_csp_integrity` option. Turn off once stable |
| `rewrite_output` | `false` | Compat mode: nonce every `<script>`, `<style>` and stylesheet `<link>` in the final HTML |
| `hoist_inline_styles` | `false` | With `rewrite_output`: move `style=""` attributes into one nonced `<style>` block |

## Compat mode trade-off

`rewrite_output` fixes plugins that print inline code without a nonce. It also nonces a `<script>` an attacker manages to inject into the page, which removes most of what CSP gives you against XSS. Prefer fixing or replacing the plugin; use compat mode as a stopgap, and keep it off where you can.

## Not included

- The post's footer script that injects `wp_nonce_field()` into forms. WordPress already provides nonce fields; add them in the form template.
- jQuery re-registration. Core already serves jQuery from `'self'`; fix the plugin that swaps it for a CDN copy.

## Tests

```bash
docker run --rm -v "$PWD":/w -w /w php:8.2-cli php tests/run.php
```

Covers the policy builder, nonce handling, integrity, the output rewriter and the style hoister. It does not boot WordPress; test the plugin on a staging site in report-only mode first.

## License

GPL-2.0-only. See `LICENSE`.
