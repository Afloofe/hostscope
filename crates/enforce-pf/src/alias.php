<?php
/*
 * HEMOSTAT alias.php (RFC-002 §2 step 4): add or remove one entry of
 * HEMOSTAT_OUT or HEMOSTAT_IN in config.xml through pfSense's own functions,
 * write one revision that says so, and reload the filter.
 *
 * Fed on stdin to `php -n -q -- OP ALIAS CIDR NONCE8`, with an explicit,
 * verified extension list. It edits the one alias by path and nothing else:
 * it never copies a section, a backup or another config over this one.
 *
 * Output: lines beginning "HEMOSTAT ", which the agent reads; anything else
 * (pfSense's own warnings) goes to stderr.
 */
ini_set('display_errors', 'stderr');
error_reporting(E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR);
set_include_path('/etc/inc:/usr/local/pfSense/include:/usr/local/share/pear');

function hs_out($s) {
	echo 'HEMOSTAT ', str_replace(array("\n", "\r"), ' ', $s), "\n";
}

function hs_files() {
	foreach (get_included_files() as $f) {
		hs_out('included ' . $f);
	}
}

function hs_stop($why) {
	hs_out('refused ' . $why);
	exit(2);
}

if ($argc !== 5) {
	hs_stop('usage: OP ALIAS CIDR NONCE8');
}
$op = $argv[1];
$name = $argv[2];
$cidr = $argv[3];
$nonce = $argv[4];
if ($op !== 'add' && $op !== 'remove') {
	hs_stop('OP is add or remove');
}
if ($name !== 'HEMOSTAT_OUT' && $name !== 'HEMOSTAT_IN') {
	hs_stop('only HEMOSTAT_OUT and HEMOSTAT_IN are enrolled');
}
if (!preg_match('/^[0-9a-f]{8}$/', $nonce)) {
	hs_stop('NONCE8 is eight lowercase hex digits');
}
if (!preg_match('#^[0-9a-f.:]+/[0-9]{1,3}$#', $cidr)) {
	hs_stop('CIDR is an address, a slash and a prefix');
}

/* What /etc/rc.filter_configure_sync loads, so filter_configure_sync() has
 * every function it calls. */
require_once('/etc/inc/globals.inc');
require_once('/etc/inc/config.inc');
require_once('/etc/inc/functions.inc');
require_once('/etc/inc/util.inc');
require_once('/etc/inc/filter.inc');
require_once('/etc/inc/shaper.inc');
require_once('/etc/inc/ipsec.inc');
require_once('/etc/inc/vpn.inc');

global $config;
/* From disk, immediately before the write: the GUI and packages write this
 * file last-writer-wins, so whatever was cached is not what is there. */
$config = parse_config(true);

$marker = 'HEMOSTAT ' . $nonce;
$found = array();
foreach (config_get_path('aliases/alias', array()) as $i => $a) {
	if (is_array($a) && isset($a['name']) && $a['name'] === $name) {
		$found[] = $i;
	}
}
if (count($found) !== 1) {
	hs_stop(count($found) . ' aliases are named ' . $name);
}
$base = 'aliases/alias/' . $found[0];
if (config_get_path($base . '/type') !== 'network') {
	hs_stop($name . ' is not of type network');
}
$a = trim((string)config_get_path($base . '/address', ''));
$addrs = ($a === '') ? array() : preg_split('/\s+/', $a);
$d = (string)config_get_path($base . '/detail', '');
$details = ($d === '') ? array() : explode('||', $d);
while (count($details) < count($addrs)) {
	$details[] = '';
}
$details = array_slice($details, 0, count($addrs));
$at = array_search($cidr, $addrs, true);
$before = (string)config_get_path('revision/time', '');

if ($op === 'add') {
	if ($at !== false) {
		if ($details[$at] === $marker) {
			hs_out('already op=add rev=' . $before);
			hs_files();
			exit(0);
		}
		hs_stop($cidr . ' is in ' . $name . ' already, under "' . $details[$at] . '"');
	}
	$addrs[] = $cidr;
	$details[] = $marker;
	$desc = 'HEMOSTAT block ' . $cidr . ' ' . $nonce;
} else {
	if ($at === false) {
		hs_out('already op=remove rev=' . $before);
		hs_files();
		exit(0);
	}
	if ($details[$at] !== $marker) {
		hs_stop($cidr . ' in ' . $name . ' is under "' . $details[$at] . '", not ' . $marker);
	}
	array_splice($addrs, $at, 1);
	array_splice($details, $at, 1);
	$desc = 'HEMOSTAT lift ' . $cidr . ' ' . $nonce;
}

config_set_path($base . '/address', implode(' ', $addrs));
config_set_path($base . '/detail', implode('||', $details));
$w = write_config($desc);
if (!is_array($w)) {
	hs_stop('write_config did not write config.xml');
}
$r = filter_configure_sync();
hs_out('ok op=' . $op . ' rev=' . config_get_path('revision/time', '') . ' before=' . $before . ' filter=' . var_export($r, true));
hs_files();
exit(0);
