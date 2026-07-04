<?php
error_reporting(0);
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

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
    "valo" => "com.riotgames.valorant",
    "league" => "com.riotgames.league",
];

$VANGUARD_SERVERS = [
    "na" => "na.vg.ac.pvp.net",
    "eu" => "eu.vg.ac.pvp.net",
    "ap" => "ap.vg.ac.pvp.net",
    "kr" => "kr.vg.ac.pvp.net",
];

$BOT_USER_AGENTS = [
    "RiotClient/63.0.9.4783202.7781241 %s (Windows; 10;;Computer; 64-bit)",
    "RiotClient/64.0.0.4580489.9040132 %s (Windows; 10;;Computer; 64-bit)",
    "RiotClient/65.0.3.4644449.9050260 %s (Windows; 10;;Computer; 64-bit)",
];

function random_delay(): void {
    usleep(random_int(50000, 200000));
}

function get_machine_id(): string {
    $chars = '0123456789abcdef';
    $segments = [];
    for ($s = 0; $s < 4; $s++) {
        $seg = '';
        for ($i = 0; $i < 8; $i++) {
            $seg .= $chars[random_int(0, 15)];
        }
        $segments[] = $seg;
    }
    return implode('-', $segments);
}

function get_client_version(): string {
    $versions = [
        ["a" => 1, "b" => 18, "c" => 3, "d" => 77],
        ["a" => 1, "b" => 20, "c" => 1, "d" => 84],
        ["a" => 1, "b" => 22, "c" => 5, "d" => 91],
    ];
    return $versions[array_rand($versions)];
}

function sanitize_log($data): string {
    if (is_string($data)) {
        if (strlen($data) > 100) {
            return substr($data, 0, 50) . '...' . substr($data, -20);
        }
        return preg_replace('/"token"\s*:\s*"[^"]+"/', '"token":"***"', $data);
    }
    return json_encode($data);
}

function encode_varint(int $n): string
{
    $out = '';
    while (true) {
        $b = $n & 0x7F;
        $n >>= 7;
        if ($n) {
            $out .= chr($b | 0x80);
        } else {
            $out .= chr($b);
            break;
        }
    }
    return $out;
}

function fail(int $code, string $message): never
{
    http_response_code($code);
    $msgs = [
        "invalid input" => "Invalid request parameters",
        "missing" => "Required parameter missing",
        "unknown game" => "Unsupported game",
        "broken resp" => "Server communication error",
        "not inso" => "Session initialization failed",
        "forward failed" => "Unable to reach authentication server",
    ];
    foreach ($msgs as $k => $v) {
        if (strpos($message, $k) !== false) {
            $message = $v;
            break;
        }
    }
    die(json_encode(["success" => false, "message" => $message]));
}

function decrypt_resp(string $payload): string
{
    $minLength = 9 + 256 + 12 + 16;
    if (strlen($payload) < $minLength) {
        throw new \InvalidArgumentException('payload too short');
    }

    $privateKeyPem = <<<'PEM'
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDF4TUhjNTJos4ZI0ZblpZbQTy17d8l8F/wFiKZqmb8fr1g0GXb1kJJ/Se3LLo8ypdwRcaKbk18OMnoJZr3Lr4EbX8qk1ZgF7eovDe75l2Dgt2SRUA1aJI8Bxoj8wilWydWO97vHO4eTVkCWKXeFoDavYLSYEgdfgQgmjM2haT0zg7OxEdY2YqHiJyMdMmgT7m1f8PVE2AKY+cpUZL7jRxfpxdapfQjW/x4hXaTq4f17pS3xpJVB5XTW6lrYqrVZiOwPobD1IzcL3zS0/Vxe+qOY4o6q/XYPOjyfAFWvwxu4Lzpcge1P0204UHiiAXb7nke0Iv49QZ1/RL90YztzvjpAgMBAAECggEASrHErwnspsJkXtvQarEwx3icNKZ6heUzKbsJS40lu+kRjnKMCIxb0HcVn1DsahclTBWiqM2TRTFgkddkJCtKQfydNJKSV8qMIs8NkMmYAhULk3O9lYuIK82YgfpzCIwckLIf6I24msqirz6MOgWvlSJVOBltD2jqoO3kKBARoPBfUlQz5d3CqN5PM0ArpIUAy+3BosrEdpMv5/p5XZ4LG7/8XifQhdT2AN34pCTzG1Wsv7fVh2wOLWjBLe9pAg1ydM721agOIqgmv8vEP8GSrp06mqxlFxXWxMWfNjL7g8V0AbE39Fj/mwlBxXU0mkgNyzAfGXkRAHbdPT6B7A4nkwKBgQDXMyRyog3u+YckHdo+qvPK4VgvdIMaTeyJ3upF72ly/W/uboXhxznMb1N2WmfYCy7KclUEfIRwfBqbM4SAKCnL6ratzd6TbR7Jg4dqdZHhki0pnHWvcak3YE+cET5gOW5HwKUeiXHbuSkAvvKGDpFGXYb2nd9Bq6s9Rwy+E/ThHwKBgQDrZWzXwCNe7Z5f/SbtnIc+Ak6mEntdxtwJmPakKcRrVSJicQ0/FV9Xn/mCfcjLRQY60I8vCFH+8FoWRw2OnC1WewjTlrt2XbFXo/E5cI0T1Vm63GJfDjrDKW9QCz7Eh5olPQdnGnWYJbGSTEykTPN61qBbCt/ERHTIreCIzum89wKBgQC/4fYp0J2j7BK3/XZQUpY23F+JUNZlaf3zoTQ7T5Iy2hAoBZyTCNVcmBdPfKUDWlVKZk+wRGbC9aWzpWgL7cP28z4YE2zW/4FoJUNlhZeiDnj+lWfKHArKObJCco2vtwXCLOAOLne7d4o8BAazyeF3YIWq+HHNWIjDhsqx4ZGD+QKBgElSuIqj4OCq55BCzKNrBH1+Pn1geGkHjna23OzZzcMZK7K6QEQMJjynKhNJlwgqIfykBlXCI7hjqcwSqdhoMX8kp+UwqIgAO0NvX65irq8k3+RizYmKZydveqrWNeEF1DARSIMHLOYNp7hIZ/8tsRHsVNrHEliSckYoUy6KNSiVAoGAV5ZzRU0OCI06XZlW7SQk63JAcO+OZCzfiUjjQYyIf93e70GB+LdCbLvwreP/t627bIXH5955emiDXHsHlalYZ7ChFPI2edmwYUKUvxmnO042IrTBewT9vKyAz7rLG/WPnpdS6aTwkUBnupzrLSi6Qx6o3OFmLA/lXEe87Kh+H+A=
-----END RSA PRIVATE KEY-----
PEM;

    $offset = 9;
    $encryptedKey = substr($payload, $offset, 256);
    $offset += 256;
    $iv = substr($payload, $offset, 12);
    $offset += 12;
    $tag = substr($payload, -16);
    $ciphertext = substr($payload, $offset, strlen($payload) - $offset - 16);

    $rsa = RSA::loadPrivateKey($privateKeyPem)->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha512')->withMGFHash('sha512');
    $aesKey = $rsa->decrypt($encryptedKey);

    if ($aesKey === false || strlen($aesKey) !== 32) {
        throw new \RuntimeException('not inso generated session');
    }

    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

    if ($plaintext === false) {
        throw new \RuntimeException('failed to decrypt');
    }

    return $plaintext;
}

function build_payload(string $data, string $pubkey, string $type): string
{
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

function forward_to_vanguard(string $payload, array $servers): ?string
{
    $ua = $GLOBALS['BOT_USER_AGENTS'][array_rand($GLOBALS['BOT_USER_AGENTS'])];
    $region = isset($GLOBALS['region']) ? $GLOBALS['region'] : 'en_US';
    $userAgent = sprintf($ua, $region);
    
    foreach ($servers as $host) {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-protobuf\r\nUser-Agent: {$userAgent}\r\n",
                'content' => $payload,
                'timeout' => 10,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]
        ]);

        $url = "https://{$host}:8443/vanguard/v1/gateway";
        random_delay();
        $resp = @file_get_contents($url, false, $context);
        if ($resp !== false && strlen($resp) > 0) {
            return $resp;
        }
        random_delay();
    }
    return null;
}

function session_store(string $session_id, array $data): void
{
    $dir = __DIR__ . '/sessions';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $path = $dir . '/' . preg_replace('/[^a-zA-Z0-9_-]/', '', $session_id) . '.json';
    $data['stored_at'] = time();
    file_put_contents($path, json_encode($data), LOCK_EX);
}

function session_load(string $session_id): ?array
{
    $path = __DIR__ . '/sessions/' . preg_replace('/[^a-zA-Z0-9_-]/', '', $session_id) . '.json';
    if (!file_exists($path)) return null;
    $data = json_decode(file_get_contents($path), true);
    if (!is_array($data)) return null;
    if (isset($data['stored_at']) && (time() - $data['stored_at']) > 300) {
        @unlink($path);
        return null;
    }
    return $data;
}

function session_cleanup(): void
{
    $dir = __DIR__ . '/sessions';
    if (!is_dir($dir)) return;
    foreach (glob($dir . '/*.json') as $file) {
        $data = json_decode(file_get_contents($file), true);
        if (isset($data['stored_at']) && (time() - $data['stored_at']) > 600) {
            @unlink($file);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'HEAD') {
    http_response_code(200);
    die("OK");
}

$input = json_decode(file_get_contents("php://input"), true);
if (!is_array($input)) {
    fail(400, "invalid input -- check docs for info");
}

$action = isset($input["action"]) && is_string($input["action"]) ? $input["action"] : "auth";
$requested_game = isset($input["game"]) && is_string($input["game"]) ? $input["game"] : null;
$sid = isset($input["sid"]) && is_string($input["sid"]) ? $input["sid"] : null;
$gameToken = isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : (isset($input["response"]) ? $input["response"] : null);
$response_b64 = isset($input["response"]) && is_string($input["response"]) ? $input["response"] : null;
$session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : null;
$region = isset($input["region"]) && is_string($input["region"]) ? $input["region"] : null;

if ($action === "auth") {

    if (!$gameToken || !$requested_game) {
        fail(400, "invalid input -- check docs for info");
    }

    if ($requested_game === "valo" && !$sid) {
        fail(400, "invalid input -- check docs for info");
    }

    if (!isset($GAME_IDS[$requested_game])) {
        fail(400, "unknown game type");
    }

    $gameId = $GAME_IDS[$requested_game];

    $msg = new AuthenticationRequest();
    $msg->setMachineId(get_machine_id());

    $f2 = new Sub2();
    $f2->setA(1);
    $f2->setB(2);
    $f2->setVersion("10.0.19045");
    $msg->setField2($f2);

    $msg->setGameToken($gameToken);

    if ($requested_game === "valo") {
        $msg->setExternalSid($sid);
    }

    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxeE1IYzUyaLOGSNGW5aWW0E8te3f\nJfBf8BYimapm/H69YNBl29ZCSf0ntyy6PMqXcEXGim5NfDjJ6CWa9y6+BG1/KpNWYBe3qLw3\nu+Zdg4LdkkVANWiSPAcaI/MIpVsnVjve7xzuHk1ZAlil3haA2r2C0mBIHX4EIJozNoWk9M4O\nzsRHWNmKh4icjHTJoE+5tX/D1RNgCmPnKVGS+40cX6cXWqX0I1v8eIV2k6uH9e6Ut8aSVQeV\n01upa2Kq1WYjsD6Gw9SM3C980tP1cXvqjmOKOqv12Dzo8nwBVr8MbuC86XIHtT9NtOFB4ogF\n2+55HtCL+PUGdf0S/dGM7c746QIDAQAB\n");
    $msg->setGameId($gameId);
    $msg->setBootState(3);

    $vg_ver = new vg_version();
    $vgData = get_client_version();
    $vg_ver->setA($vgData["a"]);
    $vg_ver->setB($vgData["b"]);
    $vg_ver->setC($vgData["c"]);
    $vg_ver->setD($vgData["d"]);
    $msg->setVersion1($vg_ver);
    $msg->setVersion2($vg_ver);

    $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";

    $finalPayload = build_payload($msg->serializeToString(), $publicKey, "\x03");
    random_delay();
    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "forward") {
    if (!$response_b64) {
        $response_b64 = isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : null;
    }
    if (!$response_b64) {
        fail(400, "missing payload");
    }
    
    $payload = base64_decode($response_b64, true);
    if ($payload === false || strlen($payload) === 0) {
        fail(400, "invalid payload encoding");
    }
    
    $responseData = forward_to_vanguard($payload, $VANGUARD_SERVERS);
    
    if ($responseData === null) {
        fail(502, "Vanguard forward failed: all servers failed");
    }
    
    die(json_encode(["success" => true, "data" => base64_encode($responseData)]));

} elseif ($action === "heartbeat") {
    if (!$response_b64) {
        fail(400, "invalid input");
    }
    $payload = base64_decode($response_b64, true);
    if ($payload === false || strlen($payload) === 0) {
        fail(400, "invalid payload encoding");
    }
    $resp = forward_to_vanguard($payload, $VANGUARD_SERVERS);
    if ($resp === null) {
        fail(502, "forward failed");
    }
    random_delay();
    die(json_encode(["success" => true, "data" => base64_encode($resp)]));

} elseif ($action === "access") {
    if (!$response_b64) {
        fail(400, "invalid input -- check docs for info");
    }

    $responseBytes = base64_decode($response_b64, true);
    if ($responseBytes === false || strlen($responseBytes) === 0) {
        fail(400, "invalid response encoding");
    }

    try {
        $decrypted = decrypt_resp($responseBytes);
    } catch (\InvalidArgumentException $e) {
        fail(400, "not inso generated session");
    } catch (\RuntimeException $e) {
        fail(400, "not inso generated session");
    }

    $msg = new AuthenticationResponse();
    $msg->mergeFromString($decrypted);

    $serverPublicKey = $msg->getServerRsaPublicKey();
    if (!$serverPublicKey) {
        fail(400, "broken resp / api needs update");
    }

    $access = new AccessRequest();
    $access->setToken($msg->getToken());

    $type = "\x04";
    $finalPayload = build_payload($access->serializeToString(), $serverPublicKey, $type);

    random_delay();
    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "refresh") {
    if (!$session_id || !$gameToken || !$sid || $requested_game === null) {
        fail(400, "missing session_id, token, sid, or game");
    }

    // Build auth payload
    $gameId = $GAME_IDS[$requested_game] ?? null;
    if (!$gameId) {
        fail(400, "unknown game type");
    }

    $msg = new AuthenticationRequest();
    $msg->setMachineId(get_machine_id());

    $f2 = new Sub2();
    $f2->setA(1);
    $f2->setB(2);
    $f2->setVersion("10.0.19045");
    $msg->setField2($f2);

    $msg->setGameToken($gameToken);

    if ($requested_game === "valo") {
        $msg->setExternalSid($sid);
    }

    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxeE1IYzUyaLOGSNGW5aWW0E8te3f\nJfBf8BYimapm/H69YNBl29ZCSf0ntyy6PMqXcEXGim5NfDjJ6CWa9y6+BG1/KpNWYBe3qLw3\nu+Zdg4LdkkVANWiSPAcaI/MIpVsnVjve7xzuHk1ZAlil3haA2r2C0mBIHX4EIJozNoWk9M4O\nzsRHWNmKh4icjHTJoE+5tX/D1RNgCmPnKVGS+40cX6cXWqX0I1v8eIV2k6uH9e6Ut8aSVQeV\n01upa2Kq1WYjsD6Gw9SM3C980tP1cXvqjmOKOqv12Dzo8nwBVr8MbuC86XIHtT9NtOFB4ogF\n2+55HtCL+PUGdf0S/dGM7c746QIDAQAB\n");
    $msg->setGameId($gameId);
    $msg->setBootState(3);

    $vg_ver = new vg_version();
    $vgData = get_client_version();
    $vg_ver->setA($vgData["a"]);
    $vg_ver->setB($vgData["b"]);
    $vg_ver->setC($vgData["c"]);
    $vg_ver->setD($vgData["d"]);
    $msg->setVersion1($vg_ver);
    $msg->setVersion2($vg_ver);

    $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";

    $authPayload = build_payload($msg->serializeToString(), $publicKey, "\x03");

    // Forward auth to Vanguard
    $region = $region ?: "eu";
    $serversToUse = [];
    if (isset($VANGUARD_SERVERS[$region])) {
        $serversToUse[] = $VANGUARD_SERVERS[$region];
    }
    $serversToUse = array_unique(array_merge($serversToUse, array_values($VANGUARD_SERVERS)));

    $authResponse = forward_to_vanguard($authPayload, $serversToUse);
    if ($authResponse === null) {
        session_store($session_id, ["status" => "failed", "error" => "auth forward failed"]);
        fail(502, "auth forward failed");
    }

    // Decrypt auth response
    try {
        $decrypted = decrypt_resp($authResponse);
    } catch (\Exception $e) {
        session_store($session_id, ["status" => "failed", "error" => "decrypt failed: " . $e->getMessage()]);
        fail(502, "decrypt failed");
    }

    $authRespMsg = new AuthenticationResponse();
    $authRespMsg->mergeFromString($decrypted);

    $serverPublicKey = $authRespMsg->getServerRsaPublicKey();
    if (!$serverPublicKey) {
        session_store($session_id, ["status" => "failed", "error" => "no server public key"]);
        fail(400, "broken auth response");
    }

    // Build access payload
    $access = new AccessRequest();
    $access->setToken($authRespMsg->getToken());

    $accessPayload = build_payload($access->serializeToString(), $serverPublicKey, "\x04");

    // Forward access to Vanguard
    $accessResponse = forward_to_vanguard($accessPayload, $serversToUse);
    if ($accessResponse === null) {
        session_store($session_id, ["status" => "failed", "error" => "access forward failed"]);
        fail(502, "access forward failed");
    }

    // Store the ticket
    session_store($session_id, [
        "status" => "ready",
        "ticket" => base64_encode($accessResponse),
        "created_at" => time(),
    ]);

    die(json_encode(["success" => true, "session_id" => $session_id]));

} elseif ($action === "poll") {
    if (!$session_id) {
        fail(400, "missing session_id");
    }

    $data = session_load($session_id);
    if ($data === null) {
        fail(404, "session not found");
    }

    $status = $data["status"] ?? "pending";
    $result = ["status" => $status];

    if ($status === "ready" && isset($data["ticket"])) {
        $result["ticket"] = $data["ticket"];
    } elseif ($status === "failed" && isset($data["error"])) {
        $result["error"] = $data["error"];
    }

    random_delay();
    die(json_encode($result));

} else {
    fail(400, "unknown action");
}

session_cleanup();
