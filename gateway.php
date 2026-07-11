<?php
header('Content-Type: application/json');
require 'vendor/autoload.php';
require_once __DIR__ . '/GPBMetadata/Authentication.php';
require_once __DIR__ . '/GPBMetadata/Tokenresp.php';
require_once __DIR__ . '/GPBMetadata/Accessrequest.php';
require_once __DIR__ . '/Vanguard/AuthenticationRequest.php';
require_once __DIR__ . '/Vanguard/AuthenticationResponse.php';
require_once __DIR__ . '/Vanguard/AccessRequest.php';
require_once __DIR__ . '/Vanguard/Sub2.php';
require_once __DIR__ . '/Vanguard/vg_version.php';

use Vanguard\AuthenticationRequest;
use Vanguard\AuthenticationResponse;
use Vanguard\AccessRequest;
use Vanguard\Sub2;
use Vanguard\vg_version;
use phpseclib3\Crypt\RSA;

$GAME_IDS = [
    "valo"   => "com.riotgames.valorant",
    "league" => "com.riotgames.league",
];

// Session storage directory
$SESSIONS_DIR = __DIR__ . '/sessions';
if (!is_dir($SESSIONS_DIR)) mkdir($SESSIONS_DIR, 0777, true);

// GC old sessions (older than 30 min)
foreach (glob($SESSIONS_DIR . '/*.json') as $f) {
    if (time() - filemtime($f) > 1800) unlink($f);
}

function encode_varint(int $n): string {
    $out = '';
    while (true) {
        $b = $n & 0x7F; $n >>= 7;
        $out .= $n ? chr($b | 0x80) : chr($b);
        if (!$n) break;
    }
    return $out;
}

function fail(int $code, string $message): never {
    http_response_code($code);
    die(json_encode(["success" => false, "message" => $message]));
}

function decrypt_resp(string $payload): string {
    $minLength = 9 + 256 + 12 + 16;
    if (strlen($payload) < $minLength) throw new \InvalidArgumentException('payload too short');

    static $privKey = null;
    if (!$privKey) {
        $pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAutPehyLkACaJKLPX1kbohorWz1R10qF7r/cSagCvGQYRtPHl\na4JDkSj2YKVdrpMR/Tl83uK1F44DlX9j8TTo32duE2fDu+8mkr4Ewq+F0LP5j4JX\nNg6PbhBq4zpeiZthkZk+o3IlPDasJUj8KlvbUArc+dDiNlR1gMAjrlV4B6ezFqNM\nFrMfiJh0+dohxGVKIwa2PP3Z+0x5cSB3QboMLCg+zM0yko7HGqNEgWbD5cOeidCP\nO+QJAa3Qfb6/Dr707cLfUb6Vdz6LJdEUTWpqgm8v41ZKtPhaTnhwwK5QWitDQVSX\nwerBM1PstvlvdKWBox3lw9oUvWIE0jwcNsRdXQIDAQABAoIBAAkCHkC11fiL4yEr\nSsTyNlQGbcUhdWzqjGQ3rZOe5NJ4EHKBF2bPqSJer0KJtrKsNLnZA8Rbeg/gsRuM\nQO1od7IN8qjM4As3xMxejSw1+mXNx8K7rijVGuVbtUuvjM9lxpaWpQaMgm8c08AY\nfNAuDa0WWQFSqRWljOTgXtgRFvCHeEGfuQ8SERHkyUA/7aXA2Tmrr2ozqd4gSUSK\nRVOlpDj188Z9sINkEulRfVIAgQnFlrrmWzRuCm/5lJh4b4+CEOlY7EXQU2jPbzm4\nQk56jad9y6S4k+8H5TaxsM+NAFtXZD+MM5hV/u5Jx9BnvRQuU7+LLy31vdTuVAPA\nn4/WSwECgYEA9+chc4i/w96zVVpxYMUIKD0/05wxoc6/HpTTu/i1RoQgh/mEGHVa\n8eBhzRvo9BmM3n/eHg/k5qF7+8ez1pzFUM3aRiVcoptrcLc190es4MxCdic3FA1s\nPQGLR+Ndm5Vnjpbap6wBAo4nyfokK6jLUyJiW39pZDYlavsrhT1291UCgYEAwO4M\n+GjBcWDVUHhtdgFuENfE2l+8+8Fw4zgLH0Lx/NuzubS0xHooTfxUXyJD4miEe0zw\nANMbGCq5j9ih6b73qa5Xnc/6zS1BRw66i01JMWd5mHpSXEarhw4mO48SfvLMz/jc\nMdMHneSg8pnfMK8PVOnPvBQVAAc5SKisg35WPekCgYEA1IQpoxeZ/VnOtt7/zwtZ\nwNUxAEEoMyQ/pwHCuaOuEzN1h9uZKDaCrlPCw8inXYsBvkQzr+XEPwo0dVVvkA15\nAZpXAkdJMIS4CDqnYsLpKxUv7IYVq3UOUwYd1pTNTHE6A3zDGXZUr1IaPgXYOC1N\nkIkrdHC3cpcQYLPNTT2x3LkCgYEAof8AqxCi5UWOt9v25XA78C6M32QmNipuVIv5\nYs1+jXgZCCTA6H0+HIV0ftExuQlTvIiUucyI4pj1aOBYzAGKyVJXxW4eRGvsdPLc\nFh3WCIK/KhYD0/GPE38BAV+YAzpyWWq30apFqgGQV0R2kNVdhUoyINWn8HcgVW80\nM9FALwkCgYEA9F47ghAgK8doX4/phq4jqGQF+6ROE+eV/pSAi52LP19iCtLYES8P\nz5LhSuqXxYnwQyGNSBwtKAk02xTaw2VOEfXfP/aOp/xoyMNZEGgHsK78lsqHNAF0\nLDNRI/0aFGoWKz18fUbUlG7oGICsUdxwos2QgsUgyNrAPZ1z4mB5bm4=\n-----END RSA PRIVATE KEY-----";
        $privKey = RSA::loadPrivateKey($pem)->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha512')->withMGFHash('sha512');
    }

    $offset = 9;
    $encryptedKey = substr($payload, $offset, 256); $offset += 256;
    $iv = substr($payload, $offset, 12); $offset += 12;
    $tag = substr($payload, -16);
    $ciphertext = substr($payload, $offset, strlen($payload) - $offset - 16);

    $aesKey = $privKey->decrypt($encryptedKey);
    if ($aesKey === false || strlen($aesKey) !== 32) throw new \RuntimeException('not inso generated session');

    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);
    if ($plaintext === false) throw new \RuntimeException('failed to decrypt');
    return $plaintext;
}

function build_payload(string $data, string $pubkey, string $type): string {
    $key = random_bytes(32);
    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    $rsa = RSA::loadPublicKey($pubkey)->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha512')->withMGFHash('sha512');
    $rsaEncKey = $rsa->encrypt($key);
    $rito_payload = hex2bin("52470100") . $rsaEncKey . $iv . $ciphertext . $tag;
    $outerWrapper = "\x08" . $type . "\x12" . encode_varint(strlen($rito_payload));
    return $outerWrapper . $rito_payload;
}

function build_auth_payload(string $gameToken, string $sid, string $gameId): string {
    $msg = new AuthenticationRequest();
    $msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");

    $f2 = new Sub2();
    $f2->setA(1); $f2->setB(2); $f2->setVersion("10.0.19045");
    $msg->setField2($f2);
    $msg->setGameToken($gameToken);
    if ($sid) $msg->setExternalSid($sid);

    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutPehyLkACaJKLPX1kbohorWz1R10qF7r/cSagCvGQYRtPHla4JDkSj2YKVdrpMR/Tl83uK1F44DlX9j8TTo32duE2fDu+8mkr4Ewq+F0LP5j4JXNg6PbhBq4zpeiZthkZk+o3IlPDasJUj8KlvbUArc+dDiNlR1gMAjrlV4B6ezFqNMFrMfiJh0+dohxGVKIwa2PP3Z+0x5cSB3QboMLCg+zM0yko7HGqNEgWbD5cOeidCPO+QJAa3Qfb6/Dr707cLfUb6Vdz6LJdEUTWpqgm8v41ZKtPhaTnhwwK5QWitDQVSXwerBM1PstvlvdKWBox3lw9oUvWIE0jwcNsRdXQIDAQAB");
    $msg->setGameId($gameId);
    $msg->setBootState(3);

    $vg_ver = new vg_version();
    $vg_ver->setA(1); $vg_ver->setB(18); $vg_ver->setC(3); $vg_ver->setD(77);
    $msg->setVersion1($vg_ver);
    $msg->setVersion2($vg_ver);

    $pubKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";
    return build_payload($msg->serializeToString(), $pubKey, "\x03");
}

// ── Main ──
$input = json_decode(file_get_contents("php://input"), true);
if (!is_array($input)) fail(400, "invalid input -- check docs for info");

$action = $input["action"] ?? "auth";
$requested_game = $input["game"] ?? null;
$sid = $input["sid"] ?? null;
$gameToken = $input["gametoken"] ?? null;
$response_b64 = $input["response"] ?? null;
$token = $input["token"] ?? null;
$region = $input["region"] ?? "eu";
$session_id = $input["session_id"] ?? null;

if ($action === "auth") {
    if (!$gameToken || !$requested_game) fail(400, "invalid input");
    if ($requested_game === "valo" && !$sid) fail(400, "invalid input");
    if (!isset($GAME_IDS[$requested_game])) fail(400, "unknown game type");

    $finalPayload = build_auth_payload($gameToken, (string)$sid, $GAME_IDS[$requested_game]);
    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "access" || $action === "heartbeat") {
    if (!$response_b64) fail(400, "invalid input");

    $responseBytes = base64_decode($response_b64, true);
    if ($responseBytes === false || strlen($responseBytes) === 0) fail(400, "invalid response encoding");

    try { $decrypted = decrypt_resp($responseBytes); }
    catch (\Exception $e) { fail(400, "not inso generated session"); }

    $msg = new AuthenticationResponse();
    $msg->mergeFromString($decrypted);

    $serverPublicKey = $msg->getServerRsaPublicKey();
    if (!$serverPublicKey) fail(400, "broken resp / api needs update");

    $access = new AccessRequest();
    $access->setToken($msg->getToken());
    $type = $action === "access" ? "\x04" : "\x07";
    $finalPayload = build_payload($access->serializeToString(), $serverPublicKey, $type);

    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "refresh") {
    // Store session data for no-restart flow
    if (!$token || !$sid || !$requested_game) fail(400, "refresh requires token, sid, and game");
    if (!isset($GAME_IDS[$requested_game])) fail(400, "unknown game type");

    $sessId = $session_id ?: bin2hex(random_bytes(16));
    $sessFile = $SESSIONS_DIR . '/' . $sessId . '.json';

    $gameId = $GAME_IDS[$requested_game];
    $authPayload = build_auth_payload($token, $sid, $gameId);

    $data = [
        'session_id' => $sessId,
        'game'       => $requested_game,
        'token'      => $token,
        'sid'        => $sid,
        'game_id'    => $gameId,
        'region'     => $region,
        'status'     => 'ready',
        'ticket'     => base64_encode($authPayload),
        'created_at' => time(),
    ];
    file_put_contents($sessFile, json_encode($data), LOCK_EX);

    die(json_encode(["success" => true, "session_id" => $sessId]));

} elseif ($action === "poll") {
    if (!$session_id) fail(400, "session_id required");

    $sessFile = $SESSIONS_DIR . '/' . $session_id . '.json';
    if (!file_exists($sessFile)) fail(404, "session not found");

    $data = json_decode(file_get_contents($sessFile), true);
    if (!$data) fail(500, "corrupt session");

    // Auto-cleanup old sessions
    if (time() - ($data['created_at'] ?? 0) > 1800) {
        unlink($sessFile);
        fail(404, "session expired");
    }

    $status = $data['status'] ?? 'pending';
    $resp = ["status" => $status, "session_id" => $session_id];

    if ($status === 'ready') {
        $resp['ticket'] = $data['ticket'] ?? '';
        // Mark as consumed so it's not reused
        $data['status'] = 'consumed';
        file_put_contents($sessFile, json_encode($data), LOCK_EX);
    } elseif ($status === 'failed') {
        $resp['error'] = $data['error'] ?? 'unknown error';
    }

    die(json_encode($resp));

} else {
    fail(400, "unknown action");
}
