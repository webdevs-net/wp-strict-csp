<?php
/**
 * Plugin Name: WP Strict CSP
 * Description: Nonce-based strict Content Security Policy for WordPress front ends, with SRI for CDN scripts and optional output rewriting for plugins that print raw inline code.
 * Version:     0.1.0
 * License:     GPL-2.0-only
 * License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 * Install as a must-use plugin: copy this file to wp-content/mu-plugins/.
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'WP_STRICT_CSP_TESTING' ) ) {
	exit;
}

final class WP_Strict_CSP {

	private static $nonce = null;

	/** Defaults. Override with the `wp_strict_csp_config` filter. */
	public static function defaults() {
		return array(
			// Send Content-Security-Policy-Report-Only instead of enforcing.
			'report_only'        => false,
			// Optional reporting endpoint (https URL).
			'report_uri'         => '',
			// Extra allowed origins per directive (besides 'self').
			'script_hosts'       => array(),
			'style_hosts'        => array(),
			'font_hosts'         => array(),
			'img_hosts'          => array(),
			'frame_hosts'        => array(),
			'connect_hosts'      => array(),
			// Hosts whose <script src> gets a sha384 integrity attribute.
			'integrity_hosts'    => array(),
			// Known hashes: array( 'https://cdn/x.js' => 'sha384-...' ).
			'integrity_hashes'   => array(),
			// Fetch and pin unknown hashes on first sight. Turn off once stable.
			'learn_integrity'    => false,
			// Compat mode: add the nonce to EVERY <script>/<style>/<link rel=stylesheet>
			// in the final HTML. Fixes plugins that echo raw tags, but a script injected
			// by an attacker gets a nonce too. Leave off unless you need it.
			'rewrite_output'     => false,
			// Compat mode: move style="" attributes into one nonced <style> block.
			'hoist_inline_styles' => false,
		);
	}

	public static function config() {
		$config = self::defaults();
		if ( function_exists( 'apply_filters' ) ) {
			$config = apply_filters( 'wp_strict_csp_config', $config );
		}
		return $config;
	}

	/** One nonce per request. The header and every rewritten tag share it. */
	public static function nonce() {
		if ( null === self::$nonce ) {
			self::$nonce = bin2hex( random_bytes( 16 ) );
		}
		return self::$nonce;
	}

	/** Pure: build the header value. */
	public static function build_policy( array $config, $nonce ) {
		$list = static function ( $hosts ) {
			return $hosts ? ' ' . implode( ' ', array_map( 'trim', $hosts ) ) : '';
		};
		$n = "'nonce-" . $nonce . "'";

		$directives = array(
			"default-src 'self'",
			// 'strict-dynamic' trusts scripts loaded by a nonced script. Browsers that
			// support it ignore host lists, so none are emitted here.
			"script-src $n 'strict-dynamic'",
			"style-src 'self' $n" . $list( $config['style_hosts'] ),
			"font-src 'self' data:" . $list( $config['font_hosts'] ),
			"img-src 'self' data:" . $list( $config['img_hosts'] ),
			"frame-src 'self'" . $list( $config['frame_hosts'] ),
			"connect-src 'self'" . $list( $config['connect_hosts'] ),
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'self'",
		);
		if ( ! empty( $config['report_uri'] ) ) {
			$directives[] = 'report-uri ' . $config['report_uri'];
		}
		return implode( '; ', $directives );
	}

	public static function send_header() {
		if ( headers_sent() || ( function_exists( 'is_admin' ) && is_admin() ) ) {
			return;
		}
		$config = self::config();
		$name   = $config['report_only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
		header( $name . ': ' . self::build_policy( $config, self::nonce() ) );
	}

	/* ---------- Tag rewriting ---------- */

	/** Pure: set the nonce attribute on one opening tag, replacing any existing one. */
	public static function with_nonce( $open_tag, $nonce ) {
		$open_tag = preg_replace( '/\snonce\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $open_tag );
		return preg_replace( '/^<(\w+)/', '<$1 nonce="' . $nonce . '"', $open_tag, 1 );
	}

	/** Pure: add integrity + crossorigin to a <script src> whose hash is known. */
	public static function with_integrity( $open_tag, array $config, $fetch = null ) {
		if ( ! preg_match( '/\ssrc\s*=\s*(["\'])(.*?)\1/i', $open_tag, $m ) ) {
			return $open_tag;
		}
		$url  = html_entity_decode( $m[2] );
		$host = parse_url( $url, PHP_URL_HOST );
		if ( ! $host || ! in_array( $host, $config['integrity_hosts'], true ) ) {
			return $open_tag;
		}
		if ( preg_match( '/\sintegrity\s*=/i', $open_tag ) ) {
			return $open_tag;
		}
		$hash = isset( $config['integrity_hashes'][ $url ] ) ? $config['integrity_hashes'][ $url ] : null;
		if ( ! $hash && $config['learn_integrity'] && $fetch ) {
			$body = call_user_func( $fetch, $url );
			if ( is_string( $body ) && '' !== $body ) {
				$hash = 'sha384-' . base64_encode( hash( 'sha384', $body, true ) );
				if ( function_exists( 'update_option' ) ) {
					$known         = get_option( 'wp_strict_csp_integrity', array() );
					$known[ $url ] = $hash;
					update_option( 'wp_strict_csp_integrity', $known, false );
				}
			}
		}
		if ( ! $hash ) {
			return $open_tag;
		}
		$open_tag = preg_replace( '/\scrossorigin\s*=\s*(?:"[^"]*"|\'[^\']*\')/i', '', $open_tag );
		return preg_replace( '/^<script/', '<script integrity="' . $hash . '" crossorigin="anonymous"', $open_tag, 1 );
	}

	/** Pure: compat rewrite of a whole HTML document. */
	public static function rewrite_html( $html, $nonce, array $config, $fetch = null ) {
		// Leave content that is not an HTML page (JSON, feeds, XML) alone.
		if ( false === stripos( $html, '</head>' ) && false === stripos( $html, '<body' ) ) {
			return $html;
		}
		$html = preg_replace_callback(
			'/<script\b[^>]*>/i',
			static function ( $m ) use ( $nonce, $config, $fetch ) {
				// JSON/ld+json and other data blocks are not executed; no nonce needed.
				if ( preg_match( '/\stype\s*=\s*["\']?(?:application\/(?:ld\+)?json|importmap|speculationrules)/i', $m[0] ) ) {
					return $m[0];
				}
				return self::with_nonce( self::with_integrity( $m[0], $config, $fetch ), $nonce );
			},
			$html
		);
		$html = preg_replace_callback(
			'/<style\b[^>]*>/i',
			static function ( $m ) use ( $nonce ) {
				return self::with_nonce( $m[0], $nonce );
			},
			$html
		);
		$html = preg_replace_callback(
			'/<link\b[^>]*\brel\s*=\s*["\']?stylesheet[^>]*>/i',
			static function ( $m ) use ( $nonce ) {
				return self::with_nonce( $m[0], $nonce );
			},
			$html
		);
		if ( $config['hoist_inline_styles'] ) {
			$html = self::hoist_styles( $html, $nonce );
		}
		return $html;
	}

	/** Append !important to each declaration so the class rule matches inline-style priority. */
	private static function important( $css ) {
		$parts = preg_split( '/;(?![^(]*\))/', $css );
		$out   = array();
		foreach ( $parts as $decl ) {
			$decl = trim( $decl );
			if ( '' === $decl || false === strpos( $decl, ':' ) ) {
				continue;
			}
			$out[] = preg_match( '/!\s*important\s*$/i', $decl ) ? $decl : $decl . ' !important';
		}
		return implode( '; ', $out );
	}

	/** Pure: replace style="" attributes with generated classes and one nonced <style> block. */
	public static function hoist_styles( $html, $nonce ) {
		// Do not touch text inside script/style/textarea/pre/template.
		$protected = array();
		$html      = preg_replace_callback(
			'/<(script|style|textarea|pre|template)\b.*?<\/\1>/is',
			static function ( $m ) use ( &$protected ) {
				$key         = '<!--wpcsp-keep-' . count( $protected ) . '-->';
				$protected[ $key ] = $m[0];
				return $key;
			},
			$html
		);

		$classes = array();
		$html    = preg_replace_callback(
			'/<(?!\/)([a-z][a-z0-9-]*)\b([^>]*?)\sstyle\s*=\s*(?:"([^"]*)"|\'([^\']*)\')([^>]*)>/i',
			static function ( $m ) use ( &$classes ) {
				$css = html_entity_decode( '' !== $m[3] ? $m[3] : $m[4] );
				$css = self::important( $css );
				if ( '' === $css ) {
					return '<' . $m[1] . $m[2] . $m[5] . '>';
				}
				if ( ! isset( $classes[ $css ] ) ) {
					$classes[ $css ] = 'wpcsp-' . ( count( $classes ) + 1 );
				}
				$cls   = $classes[ $css ];
				$attrs = $m[2] . $m[5];
				if ( preg_match( '/\sclass\s*=\s*(["\'])(.*?)\1/i', $attrs ) ) {
					$attrs = preg_replace( '/(\sclass\s*=\s*)(["\'])(.*?)\2/i', '$1$2$3 ' . $cls . '$2', $attrs, 1 );
				} else {
					$attrs .= ' class="' . $cls . '"';
				}
				return '<' . $m[1] . $attrs . '>';
			},
			$html
		);

		if ( $classes ) {
			$rules = '';
			foreach ( $classes as $css => $cls ) {
				$rules .= 'html body .' . $cls . '{' . $css . "}\n";
			}
			$block = '<style nonce="' . $nonce . '" id="wp-strict-csp-hoisted">' . "\n" . $rules . '</style>';
			$html  = preg_replace( '/<\/head>/i', $block . "\n</head>", $html, 1 );
		}
		return strtr( $html, $protected );
	}

	/* ---------- WordPress wiring ---------- */

	public static function boot() {
		add_action( 'send_headers', array( __CLASS__, 'send_header' ), 100 );

		// Enqueued and inline scripts/styles printed through core APIs get the nonce
		// without rewriting the page.
		add_filter(
			'script_loader_tag',
			static function ( $tag ) {
				$config = WP_Strict_CSP::config();
				$config['integrity_hashes'] = array_merge( get_option( 'wp_strict_csp_integrity', array() ), $config['integrity_hashes'] );
				return preg_replace_callback(
					'/<script\b[^>]*>/i',
					static function ( $m ) use ( $config ) {
						return WP_Strict_CSP::with_nonce( WP_Strict_CSP::with_integrity( $m[0], $config, array( 'WP_Strict_CSP', 'fetch' ) ), WP_Strict_CSP::nonce() );
					},
					$tag
				);
			},
			100
		);
		add_filter(
			'style_loader_tag',
			static function ( $tag ) {
				return preg_replace_callback(
					'/<link\b[^>]*>/i',
					static function ( $m ) {
						return WP_Strict_CSP::with_nonce( $m[0], WP_Strict_CSP::nonce() );
					},
					$tag
				);
			},
			100
		);
		foreach ( array( 'wp_inline_script_attributes', 'wp_script_attributes' ) as $hook ) {
			add_filter(
				$hook,
				static function ( $attrs ) {
					$attrs['nonce'] = WP_Strict_CSP::nonce();
					return $attrs;
				},
				100
			);
		}

		$config = self::config();
		if ( $config['rewrite_output'] ) {
			add_action(
				'template_redirect',
				static function () {
					ob_start(
						static function ( $html ) {
							$config                     = WP_Strict_CSP::config();
							$config['integrity_hashes'] = array_merge( get_option( 'wp_strict_csp_integrity', array() ), $config['integrity_hashes'] );
							return WP_Strict_CSP::rewrite_html( $html, WP_Strict_CSP::nonce(), $config, array( 'WP_Strict_CSP', 'fetch' ) );
						}
					);
				},
				0
			);
		}
	}

	/** Download a script body for hashing (learning mode only). */
	public static function fetch( $url ) {
		if ( 0 !== strpos( $url, 'https://' ) ) {
			return null;
		}
		$res = wp_remote_get( $url, array( 'timeout' => 5 ) );
		return is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ? null : wp_remote_retrieve_body( $res );
	}
}

if ( defined( 'ABSPATH' ) ) {
	WP_Strict_CSP::boot();
}
