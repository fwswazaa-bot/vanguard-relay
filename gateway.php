<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { echo "OK"; exit; }
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
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\AES;

$GAME_IDS = ["valo"=>"com.riotgames.valorant","league"=>"com.riotgames.league"];
$REGION_MAP = ['na'=>'na.vg.ac.pvp.net','eu'=>'eu.vg.ac.pvp.net','ap'=>'ap.vg.ac.pvp.net','kr'=>'kr.vg.ac.pvp.net','latam'=>'latam.vg.ac.pvp.net','br'=>'br.vg.ac.pvp.net'];

$SESSIONS_DIR = __DIR__ . '/sessions';
if (!is_dir($SESSIONS_DIR)) mkdir($SESSIONS_DIR, 0777, true);
foreach (glob($SESSIONS_DIR . '/*.json') as $f) { if (time() - filemtime($f) > 600) unlink($f); }

// ── RICRYPTO: ECDH public key from Riot (for module payload decryption) ──
$RICRYPTO_ECDH_PUBKEY = "b6a9822030164a75392cda99f1b999d2153c17dc8f4192ebb01c5565f5716279";
// Fallback AES key (32 bytes hex). Module payloads are AES-256-GCM encrypted.
// The real key is derived from ECDH but we lack the private key.
// Set this to a known working key if found via vgc dumping.
$RICRYPTO_AES_KEY = ""; // hex string, e.g. "a1b2c3..."

function ricrypto_decrypt(string $payload): ?string {
    global $RICRYPTO_AES_KEY;
    if (empty($RICRYPTO_AES_KEY)) return null;
    if (strlen($payload) < 28) return null; // 12 IV + 16 tag minimum
    $key = hex2bin($RICRYPTO_AES_KEY);
    if (strlen($key) !== 32) return null;
    $iv = substr($payload, 0, 12);
    $tag = substr($payload, -16);
    $ct = substr($payload, 12, strlen($payload) - 28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return ($pt === false) ? null : $pt;
}

// ── PC task fabricator ──
function get_pc_task_result(): string {
    return json_encode([
        'cpu' => 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
        'ram' => 16384,
        'os'  => '10.0.19045',
        'gpu' => 'NVIDIA GeForce RTX 3070',
        'tpm' => true,
    ]);
}

function encode_varint(int $n): string {
    $out = '';
    while(true){$b=$n&0x7F;$n>>=7;$out.=$n?chr($b|0x80):chr($b);if(!$n)break;}
    return $out;
}
function fail(int $code, string $message): never {
    http_response_code($code); die(json_encode(["success"=>false,"message"=>$message]));
}
function decrypt_resp(string $payload): string {
    static $privKey=null;
    if(!$privKey){
        $pem="-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDF4TUhjNTJos4ZI0ZblpZbQTy17d8l8F/wFiKZqmb8fr1g0GXb1kJJ/Se3LLo8ypdwRcaKbk18OMnoJZr3Lr4EbX8qk1ZgF7eovDe75l2Dgt2SRUA1aJI8Bxoj8wilWydWO97vHO4eTVkCWKXeFoDavYLSYEgdfgQgmjM2haT0zg7OxEdY2YqHiJyMdMmgT7m1f8PVE2AKY+cpUZL7jRxfpxdapfQjW/x4hXaTq4f17pS3xpJVB5XTW6lrYqrVZiOwPobD1IzcL3zS0/Vxe+qOY4o6q/XYPOjyfAFWvwxu4Lzpcge1P0204UHiiAXb7nke0Iv49QZ1/RL90YztzvjpAgMBAAECggEASrHErwnspsJkXtvQarEwx3icNKZ6heUzKbsJS40lu+kRjnKMCIxb0HcVn1DsahclTBWiqM2TRTFgkddkJCtKQfydNJKSV8qMIs8NkMmYAhULk3O9lYuIK82YgfpzCIwckLIf6I24msqirz6MOgWvlSJVOBltD2jqoO3kKBARoPBfUlQz5d3CqN5PM0ArpIUAy+3BosrEdpMv5/p5XZ4LG7/8XifQhdT2AN34pCTzG1Wsv7fVh2wOLWjBLe9pAg1ydM721agOIqgmv8vEP8GSrp06mqxlFxXWxMWfNjL7g8V0AbE39Fj/mwlBxXU0mkgNyzAfGXkRAHbdPT6B7A4nkwKBgQDXMyRyog3u+YckHdo+qvPK4VgvdIMaTeyJ3upF72ly/W/uboXhxznMb1N2WmfYCy7KclUEfIRwfBqbM4SAKCnL6ratzd6TbR7Jg4dqdZHhki0pnHWvcak3YE+cET5gOW5HwKUeiXHbuSkAvvKGDpFGXYb2nd9Bq6s9Rwy+E/ThHwKBgQDrZWzXwCNe7Z5f/SbtnIc+Ak6mEntdxtwJmPakKcRrVSJicQ0/FV9Xn/mCfcjLRQY60I8vCFH+8FoWRw2OnC1WewjTlrt2XbFXo/E5cI0T1Vm63GJfDjrDKW9QCz7Eh5olPQdnGnWYJbGSTEykTPN61qBbCt/ERHTIreCIzum89wKBgQC/4fYp0J2j7BK3/XZQUpY23F+JUNZlaf3zoTQ7T5Iy2hAoBZyTCNVcmBdPfKUDWlVKZk+wRGbC9aWzpWgL7cP28z4YE2zW/4FoJUNlhZeiDnj+lWfKHArKObJCco2vtwXCLOAOLne7d4o8BAazyeF3YIWq+HHNWIjDhsqx4ZGD+QKBgElSuIqj4OCq55BCzKNrBH1+Pn1geGkHjna23OzZzcMZK7K6QEQMJjynKhNJlwgqIfykBlXCI7hjqcwSqdhoMX8kp+UwqIgAO0NvX65irq8k3+RizYmKZydveqrWNeEF1DARSIMHLOYNp7hIZ/8tsRHsVNrHEliSckYoUy6KNSiVAoGAV5ZzRU0OCI06XZlW7SQk63JAcO+OZCzfiUjjQYyIf93e70GB+LdCbLvwreP/t627bIXH5955emiDXHsHlalYZ7ChFPI2edmwYUKUvxmnO042IrTBewT9vKyAz7rLG/WPnpdS6aTwkUBnupzrLSi6Qx6o3OFmLA/lXEe87Kh+H+A=\n-----END RSA PRIVATE KEY-----";
        $privKey=RSA::loadPrivateKey($pem)->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha512')->withMGFHash('sha512');
    }
    $sig=hex2bin("52470100");$sigPos=strpos($payload,$sig);
    if($sigPos===false)$sigPos=9;
    $minLen=$sigPos+256+12+16;if(strlen($payload)<$minLen)throw new \InvalidArgumentException('payload too short');
    $off=$sigPos+strlen($sig);
    $encKey=substr($payload,$off,256);$off+=256;$iv=substr($payload,$off,12);$off+=12;
    $tag=substr($payload,-16);$ct=substr($payload,$off,strlen($payload)-$off-16);
    $aesKey=$privKey->decrypt($encKey);
    if($aesKey===false||strlen($aesKey)!==32)throw new \RuntimeException('not inso');
    $pt=openssl_decrypt($ct,'aes-256-gcm',$aesKey,OPENSSL_RAW_DATA,$iv,$tag);
    if($pt===false)throw new \RuntimeException('decrypt failed');
    return $pt;
}
function build_payload(string $data, string $pubkey, string $type): string {
    $key=random_bytes(32);$iv=random_bytes(12);$tag='';
    $ct=openssl_encrypt($data,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,'',16);
    $rsa=RSA::loadPublicKey($pubkey)->withPadding(RSA::ENCRYPTION_OAEP)->withHash('sha512')->withMGFHash('sha512');
    $encKey=$rsa->encrypt($key);
    $rp=hex2bin("52470100").$encKey.$iv.$ct.$tag;
    return "\x08".$type."\x12".encode_varint(strlen($rp)).$rp;
}
function forward_to_riot(string $payload, string $region): ?string {
    global $REGION_MAP;
    $servers=isset($REGION_MAP[$region])?[$REGION_MAP[$region]]:array_values($REGION_MAP);
    foreach($servers as $srv){$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$payload,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);$resp=curl_exec($ch);curl_close($ch);if($resp&&strlen($resp)>0)return $resp;}
    return null;
}
function build_auth_payload(string $gameToken, string $sid, string $gameId): string {
    $msg=new AuthenticationRequest();$msg->setMachineId("my doc whitelisted hwid 0o0o0o0o0");
    $f2=new Sub2();$f2->setA(1);$f2->setB(2);$f2->setVersion("10.0.19045");$msg->setField2($f2);
    $msg->setGameToken($gameToken);if($sid)$msg->setExternalSid($sid);
    $msg->setClientRsaPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxeE1IYzUyaLOGSNGW5aWW0E8te3f\nJfBf8BYimapm/H69YNBl29ZCSf0ntyy6PMqXcEXGim5NfDjJ6CWa9y6+BG1/KpNWYBe3qLw3\nu+Zdg4LdkkVANWiSPAcaI/MIpVsnVjve7xzuHk1ZAlil3haA2r2C0mBIHX4EIJozNoWk9M4O\nzsRHWNmKh4icjHTJoE+5tX/D1RNgCmPnKVGS+40cX6cXWqX0I1v8eIV2k6uH9e6Ut8aSVQeV\n01upa2Kq1WYjsD6Gw9SM3C980tP1cXvqjmOKOqv12Dzo8nwBVr8MbuC86XIHtT9NtOFB4ogF\n2+55HtCL+PUGdf0S/dGM7c746QIDAQAB\n");
    $msg->setGameId($gameId);$msg->setBootState(3);
    $vg=new vg_version();$vg->setA(1);$vg->setB(18);$vg->setC(3);$vg->setD(88);
    $msg->setVersion1($vg);$msg->setVersion2($vg);
    $pubKey="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6O\nIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jfTv\n2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2az5\nAJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBLYdhR\n+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9FdrrhhRzNR\n3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWOJwIDAQAB\n-----END PUBLIC KEY-----\n";
    return build_payload($msg->serializeToString(),$pubKey,"\x03");
}
function parse_heartbeat_tasks(string $hbDecrypted): array {
    $tasks=['ids'=>[],'cdn_urls'=>[],'task_types'=>[]];
    $pos=0;$len=strlen($hbDecrypted);
    while($pos<$len){
        $varint=0;$shift=0;
        do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$varint|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
        $fieldNum=$varint>>3;$wireType=$varint&0x07;
        if($wireType==0){$val=0;$shift=0;do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$val|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
            if($fieldNum==2||$fieldNum==4)$tasks['ids'][]=$val;
            if($fieldNum==3)$tasks['task_types'][]=$val; // type: 1=PC, 2=Module
        }elseif($wireType==2){$dLen=0;$shift=0;do{if($pos>=$len)break 2;$b=ord($hbDecrypted[$pos++]);$dLen|=($b&0x7F)<<$shift;$shift+=7;}while($b&0x80);
            $data=substr($hbDecrypted,$pos,min($dLen,131072));
            if(preg_match('#/v\d+/cdn/mod/(\d+)(\?verify=[^\x00\x1F"\s]+)?#',$data,$m)){
                $tasks['cdn_urls'][]=['module_id'=>$m[1],'url'=>$m[0],'full_url'=>(strpos($m[0],'http')===0)?$m[0]:'https://ap.vg.ac.pvp.net:8443/'.ltrim($m[0],'/')];
            }
            $pos+=$dLen;
        }
    }
    return $tasks;
}
function send_task_result(string $json, string $srvKey, string $region): bool {
    $innerProto="\x12".encode_varint(strlen($json)).$json;
    $taskWire=build_payload($innerProto,$srvKey,"\x09");
    $resp=forward_to_riot($taskWire,$region);
    return $resp!==null;
}

// ── Main ──
$input=json_decode(file_get_contents("php://input"),true);
if(!is_array($input))fail(400,"invalid input");
$action=$input["action"]??"auth";$game=$input["game"]??null;$sid=$input["sid"]??null;
$gameToken=$input["gametoken"]??null;$response_b64=$input["response"]??null;
$region=strtolower(trim($input["region"]??"eu"));$token=$input["token"]??null;
$session_id=$input["session_id"]??null;$srvKey=$input["server_key"]??null;
$mcJson=$input["result"]??null;

if($action==="auth"){
    if(!$gameToken||!$game)fail(400,"invalid input");
    if($game==="valo"&&!$sid)fail(400,"invalid input");
    if(!isset($GAME_IDS[$game]))fail(400,"unknown game");
    $payload=build_auth_payload($gameToken,(string)$sid,$GAME_IDS[$game]);
    die(json_encode(["success"=>true,"data"=>base64_encode($payload)]));
}elseif($action==="access"||$action==="heartbeat"){
    if(!$response_b64)fail(400,"invalid input");
    $raw=base64_decode($response_b64,true);
    if($raw===false||strlen($raw)===0)fail(400,"invalid encoding");
    try{$dec=decrypt_resp($raw);}catch(\Exception $e){fail(400,"not inso");}
    $msg=new AuthenticationResponse();$msg->mergeFromString($dec);
    $spk=$msg->getServerRsaPublicKey();if(!$spk)fail(400,"broken resp");
    $acc=new AccessRequest();$acc->setToken($msg->getToken());
    $type=$action==="access"?"\x04":"\x07";
    $payload=build_payload($acc->serializeToString(),$spk,$type);
    die(json_encode(["success"=>true,"data"=>base64_encode($payload),"server_key"=>$spk]));
}elseif($action==="forward"){
    if(!$response_b64)fail(400,"invalid input");
    $raw=base64_decode($response_b64,true);
    if($raw===false||strlen($raw)===0)fail(400,"invalid encoding");
    $resp=forward_to_riot($raw,$region);
    if($resp===null)fail(502,"all Vanguard servers failed");
    die(json_encode(["success"=>true,"data"=>base64_encode($resp)]));
}elseif($action==="refresh"){
    if(!$gameToken||!$sid||!$game)fail(400,"refresh requires token,sid,game");
    if(!isset($GAME_IDS[$game]))fail(400,"unknown game");
    $sessId=$session_id?:bin2hex(random_bytes(16));
    $sessFile=$SESSIONS_DIR.'/'.$sessId.'.json';
    $data=['session_id'=>$sessId,'game'=>$game,'token'=>$gameToken,'sid'=>$sid,'region'=>$region,'status'=>'processing','created_at'=>time()];
    file_put_contents($sessFile,json_encode($data),LOCK_EX);
    $ap=build_auth_payload($gameToken,$sid,$GAME_IDS[$game]);$ticket=null;
    $servers=isset($REGION_MAP[$region])?[$REGION_MAP[$region]]:array_values($REGION_MAP);$ar=null;
    foreach($servers as $srv){$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$ap,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);$resp=curl_exec($ch);curl_close($ch);if($resp&&strlen($resp)>0){$ar=$resp;break;}}
    if($ar){try{$dec=decrypt_resp($ar);$mr=new AuthenticationResponse();$mr->mergeFromString($dec);$spk=$mr->getServerRsaPublicKey();
        if($spk){$acc=new AccessRequest();$acc->setToken($mr->getToken());$acp=build_payload($acc->serializeToString(),$spk,"\x04");
            foreach($servers as $srv){$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://{$srv}:8443/vanguard/v1/gateway",CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$acp,CURLOPT_HTTPHEADER=>['Content-Type: application/x-protobuf'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_TIMEOUT=>10]);$resp=curl_exec($ch);curl_close($ch);if($resp&&strlen($resp)>0){$ticket=$resp;break;}}}}catch(\Exception $e){}}
    if($ticket){$data['status']='ready';$data['ticket']=base64_encode($ticket);}else{$data['status']='failed';$data['error']='Auth cycle failed';}
    $data['completed_at']=time();file_put_contents($sessFile,json_encode($data),LOCK_EX);
    die(json_encode(["success"=>$ticket?true:false,"session_id"=>$sessId]));
}elseif($action==="poll"){
    if(!$session_id)fail(400,"session_id required");
    $sessFile=$SESSIONS_DIR.'/'.$session_id.'.json';
    if(!file_exists($sessFile))fail(404,"session not found");
    $data=json_decode(file_get_contents($sessFile),true);
    if(!$data||time()-($data['created_at']??0)>600){@unlink($sessFile);fail(404,"session expired");}
    $status=$data['status']??'pending';$resp=["status"=>$status,"session_id"=>$session_id];
    if($status==='ready'){$resp['ticket']=$data['ticket']??'';$data['status']='consumed';file_put_contents($sessFile,json_encode($data),LOCK_EX);}
    elseif($status==='failed'){$resp['error']=$data['error']??'unknown';}
    die(json_encode($resp));
}elseif($action==="process_heartbeat"){
    if(!$response_b64)fail(400,"missing response");if(!$srvKey)fail(400,"missing server_key");
    $raw=base64_decode($response_b64,true);
    if($raw===false||strlen($raw)===0)fail(400,"invalid encoding");
    try{$hbDecrypted=decrypt_resp($raw);}catch(\Exception $e){fail(400,"decrypt failed: ".$e->getMessage());}
    $tasks=parse_heartbeat_tasks($hbDecrypted);
    $results=[];$taskTypes=$tasks['task_types'];
    // Send appropriate results for each task type
    foreach($tasks['ids'] as $i=>$taskId){
        $type=$taskTypes[$i]??2; // default to module type
        if($type===1){ // PC task: system info
            $ok=send_task_result(get_pc_task_result(),$srvKey,$region);
            $results[]=["task"=>$taskId,"type"=>"pc","sent"=>$ok];
        }else{ // Module task: use CDN result or dummy
            $ok=send_task_result($mcJson?:'{"0":1}',$srvKey,$region);
            $results[]=["task"=>$taskId,"type"=>"module","sent"=>$ok];
        }
    }
    if(empty($tasks['ids'])){send_task_result('{"0":1}',$srvKey,$region);$results[]=["task"=>0,"sent"=>true,"note"=>"keep-alive"];}
    die(json_encode(["success"=>true,"tasks_processed"=>count($tasks['ids']),"results"=>$results,"cdn_urls"=>$tasks['cdn_urls'],"ricrypto"=>["pubkey"=>$RICRYPTO_ECDH_PUBKEY,"aes_key_set"=>!empty($RICRYPTO_AES_KEY)]]));
}elseif($action==="task_result"){
    if(!$srvKey)fail(400,"missing server_key");
    $json=$mcJson?:(($input["type"]??2)==1?get_pc_task_result():'{"0":1}');
    $ok=send_task_result($json,$srvKey,$region);
    die(json_encode(["success"=>$ok]));
}elseif($action==="ricrypto_decrypt"){
    // Decrypt module payload using RICRYPTO AES key
    if(!$response_b64)fail(400,"missing response");
    $raw=base64_decode($response_b64,true);
    if($raw===false)fail(400,"invalid encoding");
    $dec=ricrypto_decrypt($raw);
    if($dec===null)fail(400,"decrypt failed — AES key not set or invalid payload");
    die(json_encode(["success"=>true,"data"=>base64_encode($dec)]));
}else{fail(400,"unknown action");}
