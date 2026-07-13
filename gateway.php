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
    http_response_code($code);
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

    //useless to make the proto for the wrapper so just hardcode it -_-
    $rito_payload = hex2bin("52470100") . $rsaEncKey . $iv . $ciphertext . $tag;
    $outerWrapper = "\x08" . $type . "\x12" . encode_varint(strlen($rito_payload));

    return $outerWrapper . $rito_payload;
}

$SESSIONS_DIR = __DIR__ . '/sessions';
if (!is_dir($SESSIONS_DIR)) mkdir($SESSIONS_DIR, 0777, true);
foreach (glob($SESSIONS_DIR . '/*.json') as $f) { if (time() - filemtime($f) > 600) unlink($f); }

// ── Debug logging ──
$LOG_DIR = __DIR__ . '/logs';
if (!is_dir($LOG_DIR)) mkdir($LOG_DIR, 0777, true);
function log_debug(string $msg): void {
    global $LOG_DIR;
    $line = date('Y-m-d H:i:s') . ' ' . $msg . "\n";
    file_put_contents($LOG_DIR . '/gateway.log', $line, FILE_APPEND | LOCK_EX);
}

// ── PC task fabricator ──
function get_pc_task_result(): string {
    $cpus=['Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz','Intel(R) Core(TM) i5-12400F CPU @ 2.50GHz','Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz','Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz','Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz','Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz','AMD Ryzen 5 3600 6-Core','AMD Ryzen 5 5600X 6-Core','AMD Ryzen 7 3700X 8-Core','AMD Ryzen 7 5800X 8-Core'];
    $gpus=['NVIDIA GeForce GTX 1660 SUPER','NVIDIA GeForce RTX 2060','NVIDIA GeForce RTX 3060','NVIDIA GeForce RTX 3060 Ti','NVIDIA GeForce RTX 3070','NVIDIA GeForce RTX 3080','AMD Radeon RX 6600 XT','AMD Radeon RX 6700 XT'];
    $rams=[8192,16384,16384,16384,32768,32768];
    $os=['10.0.19041','10.0.19042','10.0.19043','10.0.19044','10.0.19045','10.0.22000','10.0.22621'];
    return json_encode(['cpu'=>$cpus[array_rand($cpus)],'ram'=>$rams[array_rand($rams)],'os'=>$os[array_rand($os)],'gpu'=>$gpus[array_rand($gpus)],'tpm'=>(rand(0,1)?true:false)]);
}

// ── Parse heartbeat for tasks + CDN URLs ──
function parse_heartbeat_tasks(string $hbDecrypted): array {
    log_debug("PARSE_HB: decrypted_len=" . strlen($hbDecrypted) . " hex=" . substr(bin2hex($hbDecrypted), 0, 200));
    $tasks=['ids'=>[],'cdn_urls'=>[],'task_types'=>[]];$pos=0;$len=strlen($hbDecrypted);
    while($pos<$len){$varint=0;$shift=0;do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$varint|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
        $fn=$varint>>3;$wt=$varint&0x07;
        log_debug("PARSE_HB: field=$fn wiretype=$wt pos=$pos");
        if($wt==0){$val=0;$shift=0;do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$val|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
            if($fn==2||$fn==4)$tasks['ids'][]=$val;
            if($fn==3)$tasks['task_types'][]=$val;
            log_debug("PARSE_HB: field=$fn varint=$val");
        }elseif($wt==2){$dLen=0;$shift=0;do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$dLen|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
            $data=substr($hbDecrypted,$pos,min($dLen,131072));
            if(preg_match('#/v\d+/cdn/mod/(\d+)(\?verify=[^\x00\x1F"\s]+)?#',$data,$m)){
                $tasks['cdn_urls'][]=['module_id'=>$m[1],'url'=>$m[0],'full_url'=>(strpos($m[0],'http')===0)?$m[0]:'https://ap.vg.ac.pvp.net:8443/'.ltrim($m[0],'/')];
                log_debug("PARSE_HB: CDN_URL module_id=".$m[1]." url=".($tasks['cdn_urls'][count($tasks['cdn_urls'])-1]['full_url']));
            }
            $pos+=$dLen;}
    }
    log_debug("PARSE_HB: task_ids=[".implode(',',$tasks['ids'])."] types=[".implode(',',$tasks['task_types'])."] cdn_count=".count($tasks['cdn_urls']));
    return $tasks;
}

// ── RICRYPTO module download + decrypt ──
$RICRYPTO_AES_KEY = hex2bin("b6a9822030164a75392cda99f1b999d2153c17dc8f4192ebb01c5565f5716279");

function download_module(string $url): ?string {
    log_debug("DOWNLOAD: url=" . $url);
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTPHEADER => ['User-Agent: RiotClient/97.0.0'],
    ]);
    $data = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $ok = ($code >= 200 && $code < 400 && $data && strlen($data) > 16);
    log_debug("DOWNLOAD: code=$code ok=" . ($ok?'yes':'no') . " dlen=" . strlen($data?:'') . " err=" . ($err?:'none'));
    return $ok ? $data : null;
}

function ricrypto_decrypt(string $data): ?string {
    global $RICRYPTO_AES_KEY;
    $dlen = strlen($data);
    log_debug("RICRYPTO: input_len=$dlen key=" . bin2hex($RICRYPTO_AES_KEY));
    if ($dlen < 20) { log_debug("RICRYPTO: FAIL too_short len=$dlen"); return null; }

    // Dump first 64 bytes hex for analysis
    log_debug("RICRYPTO: first64=" . bin2hex(substr($data, 0, 64)));
    log_debug("RICRYPTO: last32=" . bin2hex(substr($data, -32)));

    // Try: 4-byte header + IV(12) + ciphertext + tag(16)
    $offs = 0;
    $magic = substr($data, $offs, 4); $offs += 4;
    log_debug("RICRYPTO: magic=" . bin2hex($magic));
    if ($offs + 12 + 16 > $dlen) { log_debug("RICRYPTO: FAIL size_with_header"); return null; }
    $iv = substr($data, $offs, 12); $offs += 12;
    $tag = substr($data, -16);
    $ct = substr($data, $offs, $dlen - $offs - 16);
    log_debug("RICRYPTO: method=hdr_iv12 iv=".bin2hex($iv)." tag=".bin2hex($tag)." ctlen=".strlen($ct));

    $pt = openssl_decrypt($ct, 'aes-256-gcm', $RICRYPTO_AES_KEY, OPENSSL_RAW_DATA, $iv, $tag);
    if ($pt !== false && strlen($pt) > 0) { log_debug("RICRYPTO: OK method=hdr_iv12 ptlen=".strlen($pt)); return $pt; }
    log_debug("RICRYPTO: FAIL method=hdr_iv12 error=" . (openssl_error_string()?:'auth_fail'));

    // Try raw AES-256-GCM: IV at start, tag at end
    if ($dlen >= 28) {
        $iv2 = substr($data, 0, 12);
        $tag2 = substr($data, -16);
        $ct2 = substr($data, 12, $dlen - 28);
        log_debug("RICRYPTO: method=raw_iv12 iv2=".bin2hex($iv2)." tag2=".bin2hex($tag2)." ct2len=".strlen($ct2));
        $pt = openssl_decrypt($ct2, 'aes-256-gcm', $RICRYPTO_AES_KEY, OPENSSL_RAW_DATA, $iv2, $tag2);
        if ($pt !== false && strlen($pt) > 0) { log_debug("RICRYPTO: OK method=raw_iv12 ptlen=".strlen($pt)); return $pt; }
        log_debug("RICRYPTO: FAIL method=raw_iv12 error=" . (openssl_error_string()?:'auth_fail'));
    }

    log_debug("RICRYPTO: FAIL all_methods");
    return null;
}

function process_module_task(array $cdnUrl): string {
    $url = $cdnUrl['full_url'];
    $modId = $cdnUrl['module_id'];
    log_debug("MODULE: id=$modId url=$url");
    $encData = download_module($url);
    if (!$encData) { log_debug("MODULE: id=$modId DOWNLOAD_FAILED"); return json_encode(["0" => 1, "module" => $modId, "result" => "download_failed"]); }
    log_debug("MODULE: id=$modId downloaded_len=".strlen($encData));
    
    $decrypted = ricrypto_decrypt($encData);
    if (!$decrypted) { 
        log_debug("MODULE: id=$modId DECRYPT_FAILED first_hex=" . bin2hex(substr($encData, 0, 64)));
        return json_encode(["0" => 1, "module" => $modId, "result" => "decrypt_failed"]); 
    }
    log_debug("MODULE: id=$modId DECRYPT_OK ptlen=".strlen($decrypted)." preview=" . substr(bin2hex($decrypted), 0, 200));
    
    $result = ["0" => 1];
    if (strlen($decrypted) > 0) {
        if (preg_match('/\{[^}]+\}/', $decrypted, $m)) {
            $parsed = json_decode($m[0], true);
            if (is_array($parsed)) $result = array_merge($result, $parsed);
        }
        if (preg_match('/"0"\s*:\s*(\d+)/', $decrypted, $m)) $result["0"] = (int)$m[1];
    }
    $result["module"] = $modId;
    $result["decrypted"] = true;
    log_debug("MODULE: id=$modId result=" . json_encode($result));
    return json_encode($result);
}

// ── Send task result to Riot ──
function send_task_result(string $json, string $srvKey, string $region): bool {
    $inner="\x12".encode_varint(strlen($json)).$json;
    $taskWire=build_payload($inner,$srvKey,"\x09");
    log_debug("SEND_TASK: json=" . substr($json, 0, 200) . " region=$region wire_len=".strlen($taskWire));
    $region_map=['na'=>'na.vg.ac.pvp.net','eu'=>'eu.vg.ac.pvp.net','ap'=>'ap.vg.ac.pvp.net','kr'=>'kr.vg.ac.pvp.net','latam'=>'latam.vg.ac.pvp.net','br'=>'br.vg.ac.pvp.net'];
    $servers=isset($region_map[$region])?[$region_map[$region]]:array_values($region_map);
    foreach($servers as $srv){
        $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$taskWire,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);
        $resp=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);$err=curl_error($ch);curl_close($ch);
        log_debug("SEND_TASK: server=$srv code=$code resplen=".strlen($resp?:'')." err=".($err?:'none'));
        if($resp&&strlen($resp)>0)return true;
    }
    log_debug("SEND_TASK: ALL_FAILED");
    return false;
}

$input = json_decode(file_get_contents("php://input"), true);
if (!is_array($input)) {
    fail(400, "invalid input -- check docs for info");
}

$action = isset($input["action"]) && is_string($input["action"]) ? $input["action"] : "auth";
$requested_game = isset($input["game"]) && is_string($input["game"]) ? $input["game"] : null;
$sid = isset($input["sid"]) && is_string($input["sid"]) ? $input["sid"] : null;
$gameToken = isset($input["gametoken"]) && is_string($input["gametoken"]) ? $input["gametoken"] : (isset($input["response"]) && is_string($input["response"]) ? $input["response"] : null);
$response_b64 = isset($input["response"]) && is_string($input["response"]) ? $input["response"] : null;
$region_input = isset($input["region"]) && is_string($input["region"]) ? strtolower(trim($input["region"])) : null;


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
    // $msg->setMachineId(gen_vgc_hwid()); //removed
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
    $vg_ver->setD(77);
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

    die(json_encode(["success" => true, "data" => base64_encode($finalPayload), "server_key" => $serverPublicKey]));

} elseif ($action === "forward") {
    if (!$response_b64) {
        fail(400, "invalid input -- check docs for info");
    }
    $payload = base64_decode($response_b64, true);
    if ($payload === false || strlen($payload) === 0) {
        fail(400, "invalid response encoding");
    }
    $region_map = [
        'na'    => 'na.vg.ac.pvp.net', 'eu' => 'eu.vg.ac.pvp.net',
        'ap'    => 'ap.vg.ac.pvp.net', 'kr' => 'kr.vg.ac.pvp.net',
        'latam' => 'latam.vg.ac.pvp.net', 'br' => 'br.vg.ac.pvp.net',
    ];
    if ($region_input && isset($region_map[$region_input])) {
        $servers = [$region_map[$region_input]];
    } else {
        $servers = array_values($region_map);
    }
    $vgResponse = null;
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
            $vgResponse = $resp;
            break;
        }
    }
    if ($vgResponse === null) {
        fail(502, "all Vanguard servers failed");
    }
    die(json_encode(["success" => true, "data" => base64_encode($vgResponse)]));

} elseif ($action === "refresh") {
    if (!$gameToken || !$sid || !$requested_game) fail(400, "refresh requires token, sid, game");
    if (!isset($GAME_IDS[$requested_game])) fail(400, "unknown game");
    $sessId = isset($input["session_id"]) && $input["session_id"] ? $input["session_id"] : bin2hex(random_bytes(16));
    $sessFile = $SESSIONS_DIR . '/' . $sessId . '.json';
    $data = ['session_id'=>$sessId,'game'=>$requested_game,'token'=>$gameToken,'sid'=>$sid,'region'=>$region_input,'status'=>'processing','created_at'=>time()];
    file_put_contents($sessFile, json_encode($data), LOCK_EX);
    
    // Run full auth cycle server-side
    $gameId = $GAME_IDS[$requested_game];
    $msg = new AuthenticationRequest();
    $msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");
    $f2 = new Sub2(); $f2->setA(1); $f2->setB(2); $f2->setVersion("10.0.19045"); $msg->setField2($f2);
    $msg->setGameToken($gameToken); if ($requested_game === "valo") $msg->setExternalSid($sid);
    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxeE1IYzUyaLOGSNGW5aWW0E8te3f\nJfBf8BYimapm/H69YNBl29ZCSf0ntyy6PMqXcEXGim5NfDjJ6CWa9y6+BG1/KpNWYBe3qLw3\nu+Zdg4LdkkVANWiSPAcaI/MIpVsnVjve7xzuHk1ZAlil3haA2r2C0mBIHX4EIJozNoWk9M4O\nzsRHWNmKh4icjHTJoE+5tX/D1RNgCmPnKVGS+40cX6cXWqX0I1v8eIV2k6uH9e6Ut8aSVQeV\n01upa2Kq1WYjsD6Gw9SM3C980tP1cXvqjmOKOqv12Dzo8nwBVr8MbuC86XIHtT9NtOFB4ogF\n2+55HtCL+PUGdf0S/dGM7c746QIDAQAB\n");
    $msg->setGameId($gameId); $msg->setBootState(3);
    $vg = new vg_version(); $vg->setA(1); $vg->setB(18); $vg->setC(3); $vg->setD(88);
    $msg->setVersion1($vg); $msg->setVersion2($vg);
    $pubKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";
    $authPayload = build_payload($msg->serializeToString(), $pubKey, "\x03");
    $ticket = null;
    $region_map = ['na'=>'na.vg.ac.pvp.net','eu'=>'eu.vg.ac.pvp.net','ap'=>'ap.vg.ac.pvp.net','kr'=>'kr.vg.ac.pvp.net','latam'=>'latam.vg.ac.pvp.net','br'=>'br.vg.ac.pvp.net'];
    $servers = ($region_input && isset($region_map[$region_input])) ? [$region_map[$region_input]] : array_values($region_map);
    $authResp = null;
    foreach ($servers as $srv) { $ch = curl_init(); curl_setopt_array($ch, [CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$authPayload,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]); $resp = curl_exec($ch); curl_close($ch); if ($resp && strlen($resp) > 0) { $authResp = $resp; break; } }
    if ($authResp) {
        try { $dec = decrypt_resp($authResp); $ar = new AuthenticationResponse(); $ar->mergeFromString($dec); $spk = $ar->getServerRsaPublicKey();
            if ($spk) { $acc = new AccessRequest(); $acc->setToken($ar->getToken()); $accessPayload = build_payload($acc->serializeToString(), $spk, "\x04");
                foreach ($servers as $srv) { $ch = curl_init(); curl_setopt_array($ch, [CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$accessPayload,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]); $resp = curl_exec($ch); curl_close($ch); if ($resp && strlen($resp) > 0) { $ticket = $resp; break; } } }
        } catch (\Exception $e) {}
    }
    $data['status'] = $ticket ? 'ready' : 'failed';
    if ($ticket) $data['ticket'] = base64_encode($ticket); else $data['error'] = 'Auth cycle failed';
    $data['completed_at'] = time();
    file_put_contents($sessFile, json_encode($data), LOCK_EX);
    die(json_encode(["success" => $ticket ? true : false, "session_id" => $sessId]));

} elseif ($action === "poll") {
    $session_id = isset($input["session_id"]) && is_string($input["session_id"]) ? $input["session_id"] : null;
    if (!$session_id) fail(400, "session_id required");
    $sessFile = $SESSIONS_DIR . '/' . $session_id . '.json';
    if (!file_exists($sessFile)) fail(404, "session not found");
    $data = json_decode(file_get_contents($sessFile), true);
    if (!$data || time() - ($data['created_at'] ?? 0) > 600) { @unlink($sessFile); fail(404, "session expired"); }
    $status = $data['status'] ?? 'pending';
    $resp = ["status" => $status, "session_id" => $session_id];
    if ($status === 'ready') { $resp['ticket'] = $data['ticket'] ?? ''; $data['status'] = 'consumed'; file_put_contents($sessFile, json_encode($data), LOCK_EX); }
    elseif ($status === 'failed') { $resp['error'] = $data['error'] ?? 'unknown'; }
    die(json_encode($resp));

} elseif ($action === "process_heartbeat") {
    if (!$response_b64) fail(400, "missing response");
    $srvKey = isset($input["server_key"]) ? $input["server_key"] : "";
    if (!$srvKey) fail(400, "missing server_key");
    log_debug("PROCESS_HB: started srvKey_len=" . strlen($srvKey) . " b64_len=" . strlen($response_b64));
    $raw = base64_decode($response_b64, true);
    if ($raw === false || strlen($raw) === 0) { log_debug("PROCESS_HB: FAIL base64 decode"); fail(400, "invalid encoding"); }
    log_debug("PROCESS_HB: raw_len=" . strlen($raw) . " raw_hex=" . bin2hex(substr($raw, 0, 80)));
    try { $hbDecrypted = decrypt_resp($raw); } catch (\Exception $e) { log_debug("PROCESS_HB: FAIL decrypt_resp: " . $e->getMessage()); fail(400, "decrypt failed"); }
    log_debug("PROCESS_HB: decrypted_len=" . strlen($hbDecrypted));
    $tasks = parse_heartbeat_tasks($hbDecrypted);
    $results = [];
    $taskTypes = $tasks['task_types'];
    $cdnIdx = 0;
    log_debug("PROCESS_HB: processing " . count($tasks['ids']) . " tasks, " . count($tasks['cdn_urls']) . " CDN URLs");
    foreach ($tasks['ids'] as $i => $taskId) {
        $type = $taskTypes[$i] ?? 2;
        if ($type === 1) {
            log_debug("PROCESS_HB: task=$taskId type=PC");
            $pcJson = get_pc_task_result();
            log_debug("PROCESS_HB: task=$taskId pc_result=" . $pcJson);
            $ok = send_task_result($pcJson, $srvKey, $region_input);
            $results[] = ["task"=>$taskId,"type"=>"pc","sent"=>$ok];
        } else {
            $cdnUrl = isset($tasks['cdn_urls'][$cdnIdx]) ? $tasks['cdn_urls'][$cdnIdx] : null;
            if ($cdnUrl) { $cdnIdx++; }
            log_debug("PROCESS_HB: task=$taskId type=MODULE cdn_url=" . ($cdnUrl ? $cdnUrl['full_url'] : 'none'));
            $modResult = $cdnUrl ? process_module_task($cdnUrl) : '{"0":1}';
            $ok = send_task_result($modResult, $srvKey, $region_input);
            $results[] = ["task"=>$taskId,"type"=>"module","sent"=>$ok,"downloaded"=>($cdnUrl!==null)];
        }
    }
    if (empty($tasks['ids'])) { log_debug("PROCESS_HB: no tasks, sending keep-alive"); send_task_result('{"0":1}', $srvKey, $region_input); $results[] = ["task"=>0,"sent"=>true,"note"=>"keep-alive"]; }
    log_debug("PROCESS_HB: done, results=" . json_encode($results));
    die(json_encode(["success"=>true,"tasks_processed"=>count($tasks['ids']),"results"=>$results,"cdn_urls"=>$tasks['cdn_urls']]));

} elseif ($action === "task_result") {
    $srvKey = isset($input["server_key"]) ? $input["server_key"] : "";
    if (!$srvKey) fail(400, "missing server_key");
    $json = isset($input["result"]) ? $input["result"] : '{"0":1}';
    $ok = send_task_result($json, $srvKey, $region_input);
    die(json_encode(["success"=>$ok]));

} else {
    fail(400, "unknown action");
}