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

$SESSIONS_FILE = __DIR__ . '/sessions.json';
$SESSIONS = [];

if (file_exists($SESSIONS_FILE)) {
    $SESSIONS = json_decode(file_get_contents($SESSIONS_FILE), true) ?: [];
}

function save_sessions() {
    global $SESSIONS, $SESSIONS_FILE;
    file_put_contents($SESSIONS_FILE, json_encode($SESSIONS, JSON_PRETTY_PRINT));
}

function encode_varint(int $n): string {
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

function fail(int $code, string $message): never {
    http_response_code($code);
    die(json_encode(["success" => false, "message" => $message]));
}

function decrypt_resp(string $payload): string {
    $minLength = 9 + 256 + 12 + 16;
    if (strlen($payload) < $minLength) {
        throw new \InvalidArgumentException('payload too short');
    }

    $privateKeyPem = <<<'PEM'
-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDF4TUhjNTJos4ZI0ZblpZbQTy17d8l8F/wFiKZqmb8fr1g0GXb1kJJ/Se3LLo8ypdwRcaKbk18OMnoJZr3Lr4EbX8qk1ZgF7eovDe75l2Dgt2SRUA1aJI8Bxoj8wilWydWO97vHO4eTVkCWKXeFoDavYLSYEgdfgQimjM2haT0zg7OxEdY2YqHiJyMdMmgT7m1f8PVE2AKY+cpUZL7jRxfpxdapfQjW/x4hXaTq4f17pS3xpJVB5XTW6lrYqrVZiOwPobD1IzcL3zS0/Vxe+qOY4o6q/XYPOjyfAFWvwxu4Lzpcge1P0204UHiiAXb7nke0Iv49QZ1/RL90YztzvjpAgMBAAECggEASrHErwnspsJkXtvQarEwx3icNKZ6heUzKbsJS40lu+kRjnKMCIxb0HcVn1DsahclTBWiqM2TRTFgkddkJCtKQfydNJKSV8qMIs8NkMmYAhULk3O9lYuIK82YgfpzCIwckLIf6I24msqirz6MOgWvlSJVOBltD2jqoO3kKBARoPBfUlQz5d3CqN5PM0ArpIUAy+3BosrEdpMv5/p5XZ4LG7/8XifQhdT2AN34pCTzG1Wsv7fVh2wOLWjBLe9pAg1ydM721agOIqgmv8vEP8GSrp06mqxlFxXWxMWfNjL7g8V0AbE39Fj/mwlBxXU0mkgNyzAfGXkRAHbdPT6B7A4nkwKBgQDXMyRyog3u+YckHdo+qvPK4VgvdIMaTeyJ3upF72ly/W/uboXhxznMb1N2WmfYCy7KclUEfIRwfBqbM4SAKCnL6ratzd6TbR7Jg4dqdZHhki0pnHWvcak3YE+cET5gOW5HwKUeiXHbuSkAvvKGDpFGXYb2nd9Bq6s9Rwy+E/ThHwKBgQDrZWzXwCNe7Z5f/SbtnIc+Ak6mEntdxtwJmPakKcRrVSJicQ0/FV9Xn/mCfcjLRQY60I8vCFH+8FoWRw2OnC1WewjTlrt2XbFXo/E5cI0T1Vm63GJfDjrDKW9QCz7Eh5olPQdnGnWYJbGSTEykTPN61qBbCt/ERHTIreCIzum89wKBgQC/4fYp0J2j7BK3/XZQUpY23F+JUNZlaf3zoTQ7T5Iy2hAoBZyTCNVcmBdPfKUDWlVKZk+wRGbC9aWzpWgL7cP28z4YE2zW/4FoJUNlhZeiDnj+lWfKHArKObJCco2vtwXCLOAOLne7d4o8BAazyeF3YIWq+HHNWIjDhsqx4ZGD+QKBgElSuIqj4OCq55BCzKNrBH1+Pn1geGkHjna23OzZzcMZK7K6QEQMJjynKhNJlwgqIfykBlXCI7hjqcwSqdhoMX8kp+UwqIgAO0NvX65irq8k3+RizYmKZydveqrWNeEF1DARSIMHLOYNp7hIZ/8tsRHsVNrHEliSckYoUy6KNSiVAoGAV5ZzRU0OCI06XZlW7SQk63JAcO+OZCzfiUjjQYyIf93e70GB+LdCbLvwreP/t627bIXH5955emiDXHsHlalYZ7ChFPI2edmwYUKUvxmnO042IrTBewT9vKyAz7rLG/WPnpdS6aTwkUBnupzrLSi6Qx6o3OFmLA/lXEe87Kh+H+A=
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

function build_auth_request(string $gameToken, string $gameId, string $sid, string $game): string {
    $msg = new AuthenticationRequest();
    $msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");

    $f2 = new Sub2();
    $f2->setA(1);
    $f2->setB(2);
    $f2->setVersion("10.0.19045");
    $msg->setField2($f2);

    $msg->setGameToken($gameToken);

    if ($game === "valo") {
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

    return build_payload($msg->serializeToString(), $publicKey, "\x03");
}

function forward_to_vanguard(string $payload, ?string $region): ?string {
    $region_map = [
        'na'    => 'na.vg.ac.pvp.net',
        'eu'    => 'eu.vg.ac.pvp.net',
        'ap'    => 'ap.vg.ac.pvp.net',
        'kr'    => 'kr.vg.ac.pvp.net',
        'latam' => 'latam.vg.ac.pvp.net',
        'br'    => 'br.vg.ac.pvp.net',
    ];

    if ($region && isset($region_map[$region])) {
        $servers = [$region_map[$region]];
    } else {
        $servers = array_values($region_map);
    }

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
        $resp = curl_exec($ch);
        curl_close($ch);

        if ($resp !== false && strlen($resp) > 0) {
            return $resp;
        }
    }
    return null;
}

$input = json_decode(file_get_contents("php://input"), true);
if (!is_array($input)) {
    fail(400, "invalid input");
}

$action = isset($input["action"]) && is_string($input["action"]) ? $input["action"] : "auth";
$game = isset($input["game"]) && is_string($input["game"]) ? $input["game"] : null;
$sid = isset($input["sid"]) && is_string($input["sid"]) ? $input["sid"] : null;
$token = isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : null;
$response_b64 = isset($input["response"]) && is_string($input["response"]) ? $input["response"] : null;
$region_input = isset($input["region"]) && is_string($input["region"]) ? strtolower(trim($input["region"])) : null;
$session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : null;

if ($action === "auth") {
    if (!$token || !$game) {
        fail(400, "missing gametoken/game");
    }
    if ($game === "valo" && !$sid) {
        fail(400, "missing sid for valorant");
    }
    if (!isset($GAME_IDS[$game])) {
        fail(400, "unknown game");
    }

    $gameId = $GAME_IDS[$game];
    $payload = build_auth_request($token, $gameId, $sid ?: "", $game);

    die(json_encode(["success" => true, "data" => base64_encode($payload)]));

} elseif ($action === "access" || $action === "heartbeat") {
    if (!$response_b64) {
        fail(400, "missing response");
    }

    $responseBytes = base64_decode($response_b64, true);
    if ($responseBytes === false || strlen($responseBytes) === 0) {
        fail(400, "invalid response encoding");
    }

    try {
        $decrypted = decrypt_resp($responseBytes);
    } catch (\Exception $e) {
        fail(400, "not inso generated session");
    }

    $msg = new AuthenticationResponse();
    $msg->mergeFromString($decrypted);

    $serverPublicKey = $msg->getServerRsaPublicKey();
    if (!$serverPublicKey) {
        fail(400, "broken resp");
    }

    $access = new AccessRequest();
    $access->setToken($msg->getToken());

    $type = $action === "access" ? "\x04" : "\x07";
    $finalPayload = build_payload($access->serializeToString(), $serverPublicKey, $type);

    die(json_encode(["success" => true, "data" => base64_encode($finalPayload)]));

} elseif ($action === "forward") {
    if (!$response_b64) {
        fail(400, "missing response");
    }

    $payload = base64_decode($response_b64, true);
    if ($payload === false || strlen($payload) === 0) {
        fail(400, "invalid response encoding");
    }

    $vgResponse = forward_to_vanguard($payload, $region_input);
    if ($vgResponse === null) {
        fail(502, "all Vanguard servers failed");
    }

    die(json_encode(["success" => true, "data" => base64_encode($vgResponse)]));

} elseif ($action === "submit") {
    if (!$token || !$sid || !$game) {
        fail(400, "missing token/sid/game");
    }

    $session_id = bin2hex(random_bytes(16));
    $SESSIONS[$session_id] = [
        "token" => $token,
        "sid" => $sid,
        "game" => $game,
        "region" => $region_input ?: "eu",
        "status" => "pending",
        "ticket" => null,
        "created" => time(),
    ];
    save_sessions();

    die(json_encode(["success" => true, "session_id" => $session_id]));

} elseif ($action === "refresh") {
    if (!$session_id || !$token || !$sid) {
        fail(400, "missing session_id/token/sid");
    }

    if (!isset($SESSIONS[$session_id])) {
        $SESSIONS[$session_id] = [];
    }

    $SESSIONS[$session_id]["token"] = $token;
    $SESSIONS[$session_id]["sid"] = $sid;
    $SESSIONS[$session_id]["status"] = "pending";
    $SESSIONS[$session_id]["ticket"] = null;
    $SESSIONS[$session_id]["updated"] = time();
    save_sessions();

    die(json_encode(["success" => true, "session_id" => $session_id]));

} elseif ($action === "poll") {
    if (!$session_id) {
        fail(400, "missing session_id");
    }

    if (!isset($SESSIONS[$session_id])) {
        fail(400, "unknown session_id");
    }

    $sess = &$SESSIONS[$session_id];

    if ($sess["status"] === "pending") {
        $token = $sess["token"];
        $sid = $sess["sid"];
        $game = $sess["game"];
        $region = $sess["region"];

        $gameId = $GAME_IDS[$game] ?? "com.riotgames.valorant";
        $authPayload = build_auth_request($token, $gameId, $sid, $game);
        $authB64 = base64_encode($authPayload);

        $vgResp = forward_to_vanguard(base64_decode($authB64), $region);

        if ($vgResp !== null) {
            try {
                $dec = decrypt_resp($vgResp);
                $authResp = new AuthenticationResponse();
                $authResp->mergeFromString($dec);
                $srvPub = $authResp->getServerRsaPublicKey();

                $access = new AccessRequest();
                $access->setToken($authResp->getToken());
                $accessPayload = build_payload($access->serializeToString(), $srvPub, "\x04");

                $vgResp2 = forward_to_vanguard($accessPayload, $region);

                if ($vgResp2 !== null) {
                    $sess["ticket"] = base64_encode($vgResp2);
                    $sess["status"] = "ready";
                    save_sessions();
                } else {
                    $sess["status"] = "failed";
                    $sess["error"] = "access request failed";
                    save_sessions();
                }
            } catch (\Exception $e) {
                $sess["status"] = "failed";
                $sess["error"] = $e->getMessage();
                save_sessions();
            }
        } else {
            $sess["status"] = "failed";
            $sess["error"] = "Vanguard servers unreachable";
            save_sessions();
        }
    }

    $resp = ["status" => $sess["status"]];
    if ($sess["status"] === "ready" && $sess["ticket"]) {
        $resp["ticket"] = $sess["ticket"];
    }
    if ($sess["status"] === "failed" && isset($sess["error"])) {
        $resp["error"] = $sess["error"];
    }

    die(json_encode($resp));

} else {
    fail(400, "unknown action");
}
