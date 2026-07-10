<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo "OK";
    exit;
}
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
    "valo" => "com.riotgames.valorant",
    "league" => "com.riotgames.league",
];

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
    error_log("[GW] FAIL http={$code} msg={$message}");
    http_response_code($code);
    die(json_encode(["success" => false, "message" => $message]));
}

// Structured log helper — all GW logs go to Render's error stream
function gw_log(string $tag, string $msg, ?string $hexData = null): void
{
    $ts = date('H:i:s');
    $line = "[GW][{$ts}][{$tag}] {$msg}";
    if ($hexData !== null && strlen($hexData) > 0) {
        $bytes = str_split(substr($hexData, 0, 48));
        $hex   = implode(' ', array_map(fn($b) => strtoupper(bin2hex($b)), $bytes));
        $print = preg_replace('/[^\x20-\x7e]/', '.', substr($hexData, 0, 48));
        $line .= " | hex[0..".min(48,strlen($hexData))."]: {$hex} | ascii: {$print}";
    }
    error_log($line);
}

function decrypt_resp(string $payload): string
{
    $minLength = 9 + 256 + 12 + 16;
    gw_log("DECRYPT", "input=" . strlen($payload) . "B header=" . strtoupper(bin2hex(substr($payload,0,9))), $payload);
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
        gw_log("DECRYPT", "RSA FAIL: aesKey=" . ($aesKey === false ? "false" : strlen($aesKey)."B wrong size") . " encKey_head=" . strtoupper(bin2hex(substr($encryptedKey,0,16))));
        throw new \RuntimeException('not inso generated session');
    }
    gw_log("DECRYPT", "RSA OK aesKey=" . strtoupper(bin2hex($aesKey)) . " iv=" . strtoupper(bin2hex($iv)) . " ct=" . strlen($ciphertext) . "B tag=" . strtoupper(bin2hex($tag)));

    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

    if ($plaintext === false) {
        gw_log("DECRYPT", "AES-GCM FAIL: tag mismatch or corrupt ct. ct_head=" . strtoupper(bin2hex(substr($ciphertext,0,16))));
        throw new \RuntimeException('failed to decrypt');
    }
    gw_log("DECRYPT", "OK plaintext=" . strlen($plaintext) . "B", $plaintext);

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

    //useless to make the proto for the wrapper so just hardcode it -_-
    $rito_payload = hex2bin("52470100") . $rsaEncKey . $iv . $ciphertext . $tag;
    $outerWrapper = "\x08" . $type . "\x12" . encode_varint(strlen($rito_payload));

    return $outerWrapper . $rito_payload;
}

$input = json_decode(file_get_contents("php://input"), true);
if (!is_array($input)) {
    fail(400, "invalid input -- check docs for info");
}

$action = isset($input["action"]) && is_string($input["action"]) ? $input["action"] : "auth";
$requested_game = isset($input["game"]) && is_string($input["game"]) ? $input["game"] : null;
$sid = isset($input["sid"]) && is_string($input["sid"]) ? $input["sid"] : null;
$gameToken = isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : null;
$response_b64 = isset($input["response"]) && is_string($input["response"]) ? $input["response"] : null;
$region_input = isset($input["region"]) && is_string($input["region"]) ? strtolower(trim($input["region"])) : null;

$REGION_MAP = [
    'na'    => 'na.vg.ac.pvp.net',
    'eu'    => 'eu.vg.ac.pvp.net',
    'ap'    => 'ap.vg.ac.pvp.net',
    'kr'    => 'kr.vg.ac.pvp.net',
    'latam' => 'latam.vg.ac.pvp.net',
    'br'    => 'br.vg.ac.pvp.net',
];

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
    $msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");

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
    $vg_ver->setA(1);
    $vg_ver->setB(18);
    $vg_ver->setC(3);
    $vg_ver->setD(88);
    $msg->setVersion1($vg_ver);
    $msg->setVersion2($vg_ver);

    $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";

    $finalPayload = build_payload($msg->serializeToString(), $publicKey, "\x03");

    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "access" || $action === "heartbeat") {
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
        // fail(400, $e->getMessage());
        fail(400, "not inso generated session");
    } catch (\RuntimeException $e) {
        // fail(400, $e->getMessage());
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

    $type = $action === "access" ? "\x04" : "\x07";
    $finalPayload = build_payload($access->serializeToString(), $serverPublicKey, $type);

    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "forward") {
    if (!$response_b64) {
        fail(400, "invalid input -- check docs for info");
    }

    $payload = base64_decode($response_b64, true);
    if ($payload === false || strlen($payload) === 0) {
        fail(400, "invalid response encoding");
    }

    if ($region_input && isset($REGION_MAP[$region_input])) {
        $servers = [$REGION_MAP[$region_input]];
    } else {
        $servers = array_values($REGION_MAP);
    }

    $vgResponse = null;
    $respondedRegion = 'unknown';
    foreach ($servers as $server) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => "https://{$server}:8443/vanguard/v1/gateway",
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-protobuf'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT        => 10,
        ]);
        $resp    = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        gw_log("FORWARD", "server={$server} http={$httpCode} resp=" . strlen($resp ?: "") . "B" . ($curlErr ? " curl_err={$curlErr}" : ""), $resp ?: "");

        if ($resp !== false && strlen($resp) > 0) {
            $vgResponse = $resp;
            $respondedRegion = array_search($server, $REGION_MAP);
            if ($respondedRegion === false) $respondedRegion = 'unknown';
            gw_log("FORWARD", "SUCCESS region={$respondedRegion} resp_head=" . strtoupper(bin2hex(substr($resp,0,9))));
            break;
        }
        gw_log("FORWARD", "MISS server={$server} trying next");
    }

    if ($vgResponse === null) {
        gw_log("FORWARD", "FAIL all servers exhausted");
        fail(502, "all Vanguard servers failed");
    }

    die(json_encode(["success" => true, "data" => base64_encode($vgResponse), "region" => $respondedRegion]));

} elseif ($action === "refresh") {
    $gametoken = isset($input["token"]) && is_string($input["token"]) ? $input["token"] : 
                 (isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : null);
    $sid_refresh = isset($input["sid"]) && is_string($input["sid"]) ? $input["sid"] : null;
    $game = isset($input["game"]) && is_string($input["game"]) ? $input["game"] : null;
    $region = isset($input["region"]) && is_string($input["region"]) ? strtolower(trim($input["region"])) : "eu";

    if (!$gametoken || !$sid_refresh || !$game) {
        gw_log("REFRESH", "FAIL missing fields gametoken=" . ($gametoken ? "OK" : "null") . " sid=" . ($sid_refresh ? "OK" : "null") . " game=" . ($game ? "OK" : "null"));
        fail(400, "missing required fields");
    }
    if (!isset($GAME_IDS[$game])) fail(400, "unknown game type");

    $gameId = $GAME_IDS[$game];
    $session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : bin2hex(random_bytes(16));

    $msg = new AuthenticationRequest();
    $msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");
    $f2 = new Sub2(); $f2->setA(1); $f2->setB(2); $f2->setVersion("10.0.19045");
    $msg->setField2($f2);
    $msg->setGameToken($gametoken);
    if ($game === "valo") $msg->setExternalSid($sid_refresh);
    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxeE1IYzUyaLOGSNGW5aWW0E8te3f\nJfBf8BYimapm/H69YNBl29ZCSf0ntyy6PMqXcEXGim5NfDjJ6CWa9y6+BG1/KpNWYBe3qLw3\nu+Zdg4LdkkVANWiSPAcaI/MIpVsnVjve7xzuHk1ZAlil3haA2r2C0mBIHX4EIJozNoWk9M4O\nzsRHWNmKh4icjHTJoE+5tX/D1RNgCmPnKVGS+40cX6cXWqX0I1v8eIV2k6uH9e6Ut8aSVQeV\n01upa2Kq1WYjsD6Gw9SM3C980tP1cXvqjmOKOqv12Dzo8nwBVr8MbuC86XIHtT9NtOFB4ogF\n2+55HtCL+PUGdf0S/dGM7c746QIDAQAB\n");
    $msg->setGameId($gameId);
    $msg->setBootState(3);
    $vg_ver = new vg_version(); $vg_ver->setA(1); $vg_ver->setB(18); $vg_ver->setC(3); $vg_ver->setD(88);
    $msg->setVersion1($vg_ver); $msg->setVersion2($vg_ver);
    $publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";
    $authPayload = build_payload($msg->serializeToString(), $publicKey, "\x03");

    $server = $region_input && isset($REGION_MAP[$region_input]) ? $REGION_MAP[$region_input] : 'eu.vg.ac.pvp.net';

    $ch = curl_init();
    curl_setopt_array($ch, [CURLOPT_URL=>"https://{$server}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$authPayload,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);
    $resp = curl_exec($ch); curl_close($ch);
    if ($resp === false || strlen($resp) === 0) fail(502, "Vanguard server failed");

    try { $dec = decrypt_resp($resp); } catch (\Exception $e) { fail(502, "decrypt failed"); }
    $authResp = new AuthenticationResponse(); $authResp->mergeFromString($dec);
    $srvPub = $authResp->getServerRsaPublicKey();
    if (!$srvPub) fail(502, "broken response");

    $access = new AccessRequest(); $access->setToken($authResp->getToken());
    $accessPayload = build_payload($access->serializeToString(), $srvPub, "\x04");

    $ch2 = curl_init();
    curl_setopt_array($ch2, [CURLOPT_URL=>"https://{$server}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$accessPayload,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);
    $resp2 = curl_exec($ch2); curl_close($ch2);
    if ($resp2 === false || strlen($resp2) === 0) fail(502, "access request failed");

    // Store session with ticket in file
    $sessDir = __DIR__ . '/sessions';
    if (!is_dir($sessDir)) mkdir($sessDir, 0777, true);
    file_put_contents("$sessDir/$session_id.json", json_encode([
        "status" => "ready",
        "ticket" => base64_encode($resp2),
        "created" => time()
    ]));

    die(json_encode(["success" => true, "pending" => $session_id]));

} elseif ($action === "poll") {
    $session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] :
                  (isset($input["pending"]) && is_string($input["pending"]) ? $input["pending"] : null);
    if (!$session_id) fail(400, "missing session_id");

    $sessFile = __DIR__ . "/sessions/$session_id.json";
    if (!file_exists($sessFile)) fail(400, "unknown session_id");

    $sess = json_decode(file_get_contents($sessFile), true);
    $resp = ["status" => $sess["status"]];
    if ($sess["status"] === "ready" && isset($sess["ticket"])) $resp["ticket"] = $sess["ticket"];
    if ($sess["status"] === "failed" && isset($sess["error"])) $resp["error"] = $sess["error"];

    die(json_encode($resp));

} elseif ($action === "tasks") {
    $payload_b64 = isset($input["payload"]) && is_string($input["payload"]) ? $input["payload"] : null;
    if (!$payload_b64) fail(400, "missing payload");

    $taskBytes = base64_decode($payload_b64, true);
    if ($taskBytes === false || strlen($taskBytes) === 0) fail(400, "invalid payload");

    try {
        $decrypted = decrypt_resp($taskBytes);
    } catch (\Exception $e) {
        fail(400, "decrypt failed");
    }

    // Extract readable strings from decrypted blob
    $strings = [];
    $current = '';
    for ($i = 0; $i < strlen($decrypted); $i++) {
        $c = ord($decrypted[$i]);
        if ($c >= 32 && $c <= 126) {
            $current .= $decrypted[$i];
        } else {
            if (strlen($current) >= 4) $strings[] = $current;
            $current = '';
        }
    }
    if (strlen($current) >= 4) $strings[] = $current;

    // Find module URLs in extracted strings
    $moduleResults = [];
    foreach ($strings as $s) {
        // Match Vanguard CDN module URLs
        if (preg_match('#/v1/cdn/mod/(\d+)\?verify=([^\s]+)#i', $s, $m)) {
            $moduleId = $m[1];
            $verifyParam = $m[2];
            error_log("[GW] [MOD] found module id=$moduleId");

            // Try all regions for each module — modules may only exist on certain regions
            $rawData = null;
            $rawRgn = null;
            $decryptedMod = null;
            foreach ($REGION_MAP as $rgn => $host) {
                $cdnUrl = "https://$host:8443/vanguard/v1/cdn/mod/$moduleId?verify=$verifyParam";
                error_log("[GW] [MOD] trying $rgn: $cdnUrl");

                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $cdnUrl,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_SSL_VERIFYPEER => false,
                    CURLOPT_TIMEOUT => 15,
                    CURLOPT_FOLLOWLOCATION => true,
                ]);
                $modData = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                if ($httpCode === 200 && $modData !== false && strlen($modData) > 0) {
                    error_log("[GW] [MOD] downloaded module $moduleId " . strlen($modData) . "B from $rgn");
                    $rawData = $modData;
                    $rawRgn = $rgn;

                    // verify format: <uint32_timestamp>-<base64url_key>.<float_suffix>
                    // Key sits between the first '-' and the first '.'
                    $aesKey = null;
                    $dashPos = strpos($verifyParam, '-');
                    $dotPos  = strpos($verifyParam, '.');
                    if ($dashPos !== false && $dotPos !== false && $dotPos > $dashPos) {
                        $keyB64url = substr($verifyParam, $dashPos + 1, $dotPos - $dashPos - 1);
                        // base64url -> standard
                        $keyB64std = str_replace(['-', '_'], ['+', '/'], $keyB64url);
                        $kraw = base64_decode($keyB64std, true);
                        if ($kraw !== false) {
                            $ksz = strlen($kraw);
                            if ($ksz === 16 || $ksz === 24 || $ksz === 32) {
                                $aesKey = $kraw;
                            } elseif ($ksz > 32) {
                                $aesKey = substr($kraw, 0, 32); // AES-256
                            } elseif ($ksz > 24) {
                                $aesKey = substr($kraw, 0, 24); // AES-192
                            } elseif ($ksz > 16) {
                                $aesKey = substr($kraw, 0, 16); // AES-128
                            }
                        }
                    }

                    if ($aesKey) {
                        $ksz    = strlen($aesKey);
                        $cipher = $ksz === 16 ? 'aes-128' : ($ksz === 24 ? 'aes-192' : 'aes-256');

                        // AES-GCM (IV=first 12, tag=last 16)
                        $iv  = substr($modData, 0, 12);
                        $tag = substr($modData, -16);
                        $ct  = substr($modData, 12, -16);
                        if (strlen($iv) === 12)
                            $decryptedMod = @openssl_decrypt($ct, "{$cipher}-gcm", $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

                        // AES-CBC (IV=first 16)
                        if (!$decryptedMod) {
                            $iv = substr($modData, 0, 16);
                            $ct = substr($modData, 16);
                            $decryptedMod = @openssl_decrypt($ct, "{$cipher}-cbc", $aesKey, OPENSSL_RAW_DATA, $iv);
                        }

                        // AES-CTR (IV=first 16)
                        if (!$decryptedMod) {
                            $iv = substr($modData, 0, 16);
                            $ct = substr($modData, 16);
                            $decryptedMod = @openssl_decrypt($ct, "{$cipher}-ctr", $aesKey, OPENSSL_RAW_DATA, $iv);
                        }

                        // AES-ECB (no IV)
                        if (!$decryptedMod)
                            $decryptedMod = @openssl_decrypt($modData, "{$cipher}-ecb", $aesKey, OPENSSL_RAW_DATA);
                    }

                    // Zero key last resort
                    if (!$decryptedMod) {
                        $fixedKey = str_repeat("\x00", 32);
                        $decryptedMod = @openssl_decrypt($modData, 'aes-256-ecb', $fixedKey, OPENSSL_RAW_DATA);
                    }

                    if ($decryptedMod !== false && $decryptedMod !== null && strlen($decryptedMod) > 0) {
                        error_log("[GW] [MOD] decrypted module $moduleId (" . strlen($decryptedMod) . "B) from $rgn");
                        $moduleResults[] = [
                            "id" => $moduleId,
                            "data" => base64_encode($decryptedMod),
                            "raw" => base64_encode($rawData),
                            "encrypted" => false,
                        ];
                        break;
                    }
                }
            }
            // If no region had the module, try first raw download as fallback
            if ($rawData !== null && !in_array($moduleId, array_column($moduleResults, 'id'))) {
                error_log("[GW] [MOD] decrypt failed for $moduleId on all regions, returning raw");
                $moduleResults[] = [
                    "id" => $moduleId,
                    "data" => base64_encode($rawData),
                    "raw" => base64_encode($rawData),
                    "encrypted" => true,
                ];
            }
        }
    }

    // Build task response protobuf-like structure
    // Each module result gets wrapped in the expected task response format
    $taskResult = [
        "modules" => $moduleResults,
        "count" => count($moduleResults),
    ];

    // Encode task result as raw bytes to send back
    $resultPayload = json_encode($taskResult);

    die(json_encode(["success" => true, "data" => base64_encode($resultPayload)]));

} elseif ($action === "hb_full") {
    // Full heartbeat round-trip: build HB wire -> POST to Riot -> parse task CDN URLs
    // Input: auth_resp (b64 Riot AUTH response bytes), session_id, region
    $auth_resp_b64  = isset($input["auth_resp"])  && is_string($input["auth_resp"])  ? $input["auth_resp"]  : null;
    $emu_session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : "default";
    $hb_region      = isset($input["region"])     && is_string($input["region"])     ? strtolower(trim($input["region"])) : "eu";

    if (!$auth_resp_b64) fail(400, "missing auth_resp");

    $authRespBytes = base64_decode($auth_resp_b64, true);
    if ($authRespBytes === false || strlen($authRespBytes) === 0) fail(400, "invalid auth_resp encoding");

    try {
        $decryptedAuth = decrypt_resp($authRespBytes);
    } catch (\Exception $e) {
        fail(400, "auth_resp decrypt failed");
    }

    $authMsg = new AuthenticationResponse();
    $authMsg->mergeFromString($decryptedAuth);
    $serverPubKey = $authMsg->getServerRsaPublicKey();
    $sessionToken = $authMsg->getToken();
    if (!$serverPubKey || !$sessionToken) fail(400, "broken auth_resp");

    // Build HB wire (type 0x07)
    $hbAccess = new AccessRequest();
    $hbAccess->setToken($sessionToken);
    $hbPayload = build_payload($hbAccess->serializeToString(), $serverPubKey, "\x07");

    // POST to Riot Gateway
    $hbServer = isset($REGION_MAP[$hb_region]) ? $REGION_MAP[$hb_region] : "eu.vg.ac.pvp.net";
    $hbCh = curl_init();
    curl_setopt_array($hbCh, [
        CURLOPT_URL            => "https://{$hbServer}:8443/vanguard/v1/gateway",
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $hbPayload,
        CURLOPT_HTTPHEADER     => ["Content-Type: application/x-protobuf"],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT        => 15,
    ]);
    $hbResp = curl_exec($hbCh);
    $hbCode = curl_getinfo($hbCh, CURLINFO_HTTP_CODE);
    curl_close($hbCh);

    error_log("[GW] [HB] hb_full http={$hbCode} resp=" . strlen($hbResp ?: "") . "B");

    if (!$hbResp || strlen($hbResp) === 0) {
        die(json_encode(["success" => true, "tasks" => [], "hb_error" => "riot_unreachable"]));
    }

    // Try to decrypt HB response (same private key)
    $hbDecrypted = null;
    try {
        $hbDecrypted = decrypt_resp($hbResp);
    } catch (\Exception $e) {
        die(json_encode(["success" => true, "tasks" => [], "hb_error" => "decrypt_failed"]));
    }

    // Parse updated server pubkey/token from HB response
    $hbMsg = new AuthenticationResponse();
    $hbMsg->mergeFromString($hbDecrypted);
    $newSrvKey = $hbMsg->getServerRsaPublicKey();
    $newToken   = $hbMsg->getToken();

    // Store session state for task_result action
    $sessDir = __DIR__ . "/sessions";
    if (!is_dir($sessDir)) mkdir($sessDir, 0777, true);
    file_put_contents("{$sessDir}/{$emu_session_id}.json", json_encode([
        "server_pubkey" => $newSrvKey ?: $serverPubKey,
        "token"         => $newToken  ?: $sessionToken,
        "updated"       => time(),
        "region"        => $hb_region,
    ]));

    // Scan decrypted bytes for CDN module URLs
    $tasks = [];
    $cur = "";
    $raw = $hbDecrypted;
    for ($i = 0; $i < strlen($raw); $i++) {
        $c = ord($raw[$i]);
        if ($c >= 32 && $c <= 126) {
            $cur .= $raw[$i];
        } else {
            if (strlen($cur) >= 20) {
                if (preg_match('#/v1/cdn/mod/(\d+)\?verify=([^\s&"\']+)#i', $cur, $m)) {
                    $modId  = $m[1];
                    $verify = $m[2];
                    $tasks[] = [
                        "id"        => "task-" . substr(md5($modId . microtime()), 0, 8),
                        "module_id" => $modId,
                        "cdn_path"  => "/vanguard/v1/cdn/mod/{$modId}?verify={$verify}",
                        "verify"    => $verify,
                        "host"      => $hb_region,
                    ];
                    error_log("[GW] [HB] found task mod={$modId}");
                }
            }
            $cur = "";
        }
    }

    die(json_encode(["success" => true, "tasks" => $tasks, "task_count" => count($tasks)]));

} elseif ($action === "task_result") {
    // Encrypt mc result as type-9 wire and POST to Riot Gateway
    // Input: mc_json, session_id, task_id
    $mc_json_raw = isset($input["mc_json"])    && is_string($input["mc_json"])    ? $input["mc_json"]    : null;
    $tr_session  = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : null;
    $tr_task_id  = isset($input["task_id"])    && is_string($input["task_id"])    ? $input["task_id"]    : "";

    if (!$mc_json_raw || !$tr_session) fail(400, "missing mc_json or session_id");

    $sessFile = __DIR__ . "/sessions/{$tr_session}.json";
    if (!file_exists($sessFile)) fail(400, "unknown session_id — call hb_full first");

    $sessData = json_decode(file_get_contents($sessFile), true);
    if (!$sessData || empty($sessData["server_pubkey"])) fail(400, "no server_pubkey in session");

    $srvKey    = $sessData["server_pubkey"];
    $tr_region = $sessData["region"] ?? "eu";

    // Wrap mc JSON as proto field 2 (string): 0x12 <varint_len> <data>
    // This is the inner payload Vanguard expects inside the type-9 result wire
    $innerProto = "\x12" . encode_varint(strlen($mc_json_raw)) . $mc_json_raw;

    // Encrypt with RG+AES, type byte = 0x09
    $taskWire = build_payload($innerProto, $srvKey, "\x09");

    // POST to Riot Gateway
    $trServer = isset($REGION_MAP[$tr_region]) ? $REGION_MAP[$tr_region] : "eu.vg.ac.pvp.net";
    $trCh = curl_init();
    curl_setopt_array($trCh, [
        CURLOPT_URL            => "https://{$trServer}:8443/vanguard/v1/gateway",
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $taskWire,
        CURLOPT_HTTPHEADER     => ["Content-Type: application/x-protobuf"],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT        => 10,
    ]);
    $trResp = curl_exec($trCh);
    $trCode = curl_getinfo($trCh, CURLINFO_HTTP_CODE);
    curl_close($trCh);

    error_log("[GW] [TASK] result posted task={$tr_task_id} http={$trCode} resp=" . strlen($trResp ?: "") . "B");

    if ($trResp && strlen($trResp) > 50) {
        // Try to extract rotated server pubkey from Riot's ACK
        try {
            $ackDec = decrypt_resp($trResp);
            $ackMsg = new AuthenticationResponse();
            $ackMsg->mergeFromString($ackDec);
            $rotKey = $ackMsg->getServerRsaPublicKey();
            $rotTok = $ackMsg->getToken();
            if ($rotKey) {
                $sessData["server_pubkey"] = $rotKey;
                if ($rotTok) $sessData["token"] = $rotTok;
                file_put_contents($sessFile, json_encode($sessData));
                error_log("[GW] [TASK] pubkey rotated for {$tr_session}");
            }
        } catch (\Exception $e) {
            // Non-fatal
        }
    }

    die(json_encode([
        "success"    => ($trCode === 200 || $trCode === 0),
        "http_code"  => $trCode,
        "resp_bytes" => strlen($trResp ?: ""),
        "task_id"    => $tr_task_id,
    ]));

} else {
    fail(400, "unknown action");
}
