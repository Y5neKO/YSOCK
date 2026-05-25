using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Threading;


public static class YSock
{
    static string KEY = "CHANGE_ME";
    static long ECTR = 0;
    static ConcurrentDictionary<long, Socket> Sessions = new ConcurrentDictionary<long, Socket>();
    static ConcurrentDictionary<string, ConcurrentQueue<byte[]>> Queues = new ConcurrentDictionary<string, ConcurrentQueue<byte[]>>();
    static ConcurrentDictionary<string, bool> CloseFlags = new ConcurrentDictionary<string, bool>();


    public static string Handle(string body)
    {
        if (string.IsNullOrEmpty(body)) return "{\"d\":\"\"}";
        string action = JStr(body, "a");
        if (action == null) return "{\"d\":\"\"}";
        try
        {
            switch (action)
            {
                case "h":  return OnHandshake(body);
                case "cc": return OnClassicCreate(body);
                case "cp": return OnClassicPoll(body);
                case "c":  return OnHalfCreate(body);
                case "d":  return OnHalfData(body);
                case "x":  return OnHalfClose(body);
                default:   return "{\"d\":\"\"}";
            }
        }
        catch { return "{\"d\":\"\"}"; }
    }


    public static void HandleStream(Stream input, Stream output)
    {
        try
        {
            string body = ReadJson(input);
            string action = JStr(body, "a");
            if (action != "f") { byte[] b = Encoding.UTF8.GetBytes("{\"d\":\"\"}"); output.Write(b, 0, b.Length); return; }

            string rd = JStr(body, "d");
            if (rd == null) return;
            byte[] raw = Dec(B64D(rd), KEY);
            if (raw == null || raw.Length < 2) return;
            byte[] synData = ParseSynData(raw);
            int[] synInfo = ParseSyn(raw);
            if (synData == null || synInfo == null) return;
            int sid = synInfo[0], seq = synInfo[1];

            Socket sock = Connect(synData);
            if (sock == null)
            {
                MemoryStream fb = new MemoryStream();
                fb.WriteByte(0); fb.WriteByte(1);
                byte[] pkt = MkPkt(0x00, sid, 0, seq, new byte[0]);
                fb.Write(pkt, 0, pkt.Length);
                WriteFrame(output, 0x00, fb.ToArray());
                return;
            }
            Sessions.TryAdd(sid, sock);
            lock (output) { WriteFrame(output, 0x00, new byte[0]); }

            new Thread(() =>
            {
                try
                {
                    byte[] buf = new byte[65536];
                    while (sock.Connected)
                    {
                        int n = sock.Receive(buf);
                        if (n == 0) break;
                        byte[] chunk = new byte[n]; Cp(buf, 0, chunk, 0, n);
                        lock (output) { WriteFrame(output, 0x01, chunk); }
                    }
                }
                catch { }
                finally
                {
                    try { lock (output) { WriteFrame(output, 0x02, new byte[0]); } } catch { }
                    try { sock.Close(); } catch { }
                    Socket _; Sessions.TryRemove(sid, out _);
                }
            }) { IsBackground = true }.Start();

            try
            {
                while (sock.Connected)
                {
                    byte[] frame = ReadFrame(input);
                    if (frame == null) break;
                    byte typeByte = frame[0];
                    byte[] data = new byte[frame.Length - 1];
                    if (data.Length > 0) Cp(frame, 1, data, 0, data.Length);
                    if (typeByte == 0x01 && data.Length > 0) sock.Send(data);
                    else if (typeByte == 0x02) break;
                }
            }
            catch { }
            finally { try { sock.Close(); } catch { } Socket _; Sessions.TryRemove(sid, out _); }
        }
        catch { }
    }


    static string OnHandshake(string body)
    {
        string rd = JStr(body, "d");
        if (rd == null) return "{\"d\":\"\",\"m\":3}";
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null) return "{\"d\":\"\",\"m\":3}";
        return "{\"d\":\"" + B64E(Enc(raw, KEY)) + "\",\"m\":2}";
    }

    static string OnClassicCreate(string body)
    {
        string rd = JStr(body, "d");
        if (rd == null) return "{\"d\":\"\"}";
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null || raw.Length < 2) return "{\"d\":\"\"}";
        byte[] synData = ParseSynData(raw);
        int[] synInfo = ParseSyn(raw);
        if (synData == null || synInfo == null) return "{\"d\":\"\"}";
        int sid = synInfo[0], seq = synInfo[1];

        Socket sock = Connect(synData);
        if (sock == null)
        {
            MemoryStream fb = new MemoryStream();
            fb.WriteByte(0); fb.WriteByte(1);
            fb.Write(MkPkt(0x00, sid, 0, seq, new byte[0]), 0, 17);
            return "{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\"}";
        }
        Sessions.TryAdd(sid, sock);
        Queues.TryAdd("r_" + sid, new ConcurrentQueue<byte[]>());
        Queues.TryAdd("w_" + sid, new ConcurrentQueue<byte[]>());
        MemoryStream fb2 = new MemoryStream();
        fb2.WriteByte(0); fb2.WriteByte(1);
        fb2.Write(MkPkt(0x04, sid, 0, seq, new byte[0]), 0, 17);
        new Thread(() => BgRead(sid, sock)) { IsBackground = true }.Start();
        return "{\"d\":\"" + B64E(Enc(fb2.ToArray(), KEY)) + "\",\"id\":\"" + sid + "\"}";
    }

    static string OnClassicPoll(string body)
    {
        string idStr = JStr(body, "id"), rd = JStr(body, "d");
        long sid = 0;
        if (!string.IsNullOrEmpty(idStr)) sid = long.Parse(idStr);
        if (!string.IsNullOrEmpty(rd) && sid > 0)
        {
            byte[] raw = Dec(B64D(rd), KEY);
            if (raw != null)
            {
                Socket sock;
                if (Sessions.TryGetValue(sid, out sock) && sock.Connected)
                {
                    try { sock.Send(raw); } catch { Socket _; Sessions.TryRemove(sid, out _); }
                }
            }
        }
        if (sid > 0)
        {
            ConcurrentQueue<byte[]> rq;
            MemoryStream db = new MemoryStream(); bool fin = false;
            if (Queues.TryGetValue("r_" + sid, out rq))
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
            if (!Sessions.TryGetValue(sid, out sock2) || !sock2.Connected) fin = true;
            if (rd2.Length > 0)
            {
                MemoryStream fb = new MemoryStream();
                fb.WriteByte(0); fb.WriteByte(1);
                byte[] pkt = MkPkt(0x02, (int)sid, 0, 0, rd2);
                fb.Write(pkt, 0, pkt.Length);
                return "{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\",\"fin\":" + fin.ToString().ToLower() + "}";
            }
            else if (fin)
            {
                MemoryStream fb = new MemoryStream();
                fb.WriteByte(0); fb.WriteByte(1);
                fb.Write(MkPkt(0x08, (int)sid, 0, 0, new byte[0]), 0, 17);
                return "{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\",\"fin\":true}";
            }
            return "{\"d\":\"\",\"fin\":false}";
        }
        return "{\"d\":\"\",\"fin\":false}";
    }

    static string OnHalfCreate(string body)
    {
        string rd = JStr(body, "d");
        if (rd == null) return "{\"d\":\"\"}";
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null || raw.Length < 2) return "{\"d\":\"\"}";
        byte[] synData = ParseSynData(raw);
        int[] synInfo = ParseSyn(raw);
        if (synData == null || synInfo == null) return "{\"d\":\"\"}";
        int sid = synInfo[0], seq = synInfo[1];
        Socket sock = Connect(synData);
        if (sock == null)
        {
            MemoryStream fb = new MemoryStream();
            fb.WriteByte(0); fb.WriteByte(1);
            fb.Write(MkPkt(0x00, sid, 0, seq, new byte[0]), 0, 17);
            return "{\"d\":\"" + B64E(Enc(fb.ToArray(), KEY)) + "\"}";
        }
        Sessions.TryAdd(sid, sock);
        var wq = new ConcurrentQueue<byte[]>();
        Queues.TryAdd("w_" + sid, wq);
        new Thread(() => BgRead(sid, sock)) { IsBackground = true }.Start();
        new Thread(() =>
        {
            try
            {
                while (sock.Connected && !CloseFlags.ContainsKey("c_" + sid))
                {
                    byte[] wd = null;
                    if (wq.TryDequeue(out wd) && wd != null && wd.Length > 0)
                    {
                        try { sock.Send(wd); } catch { break; }
                    }
                    else Thread.Sleep(50);
                    if (!sock.Connected) break;
                }
            }
            catch { }
            finally
            {
                bool _b; CloseFlags.TryRemove("c_" + sid, out _b);
                ConcurrentQueue<byte[]> _q; Queues.TryRemove("w_" + sid, out _q);
                Socket _s; Sessions.TryRemove(sid, out _s);
            }
        }) { IsBackground = true }.Start();
        MemoryStream fb2 = new MemoryStream();
        fb2.WriteByte(0); fb2.WriteByte(1);
        fb2.Write(MkPkt(0x04, sid, 0, seq, new byte[0]), 0, 17);
        return "{\"d\":\"" + B64E(Enc(fb2.ToArray(), KEY)) + "\",\"id\":\"" + sid + "\"}";
    }

    static string OnHalfData(string body)
    {
        string idStr = JStr(body, "id"), rd = JStr(body, "d");
        if (idStr == null || rd == null) return "{\"ok\":false}";
        long sid = long.Parse(idStr);
        byte[] raw = Dec(B64D(rd), KEY);
        if (raw == null) return "{\"ok\":false}";
        ConcurrentQueue<byte[]> wq;
        if (!Queues.TryGetValue("w_" + sid, out wq) || wq == null) return "{\"ok\":false}";
        wq.Enqueue(raw);
        return "{\"ok\":true}";
    }

    static string OnHalfClose(string body)
    {
        string idStr = JStr(body, "id");
        if (idStr == null) return "{\"ok\":false}";
        CloseFlags["c_" + long.Parse(idStr)] = true;
        return "{\"ok\":true}";
    }


    static void BgRead(long sid, Socket sock)
    {
        byte[] buf = new byte[65536];
        try
        {
            while (sock.Connected && !CloseFlags.ContainsKey("c_" + sid))
            {
                int n = sock.Receive(buf);
                if (n == 0) break;
                byte[] chunk = new byte[n]; Cp(buf, 0, chunk, 0, n);
                ConcurrentQueue<byte[]> rq;
                if (Queues.TryGetValue("r_" + sid, out rq)) rq.Enqueue(chunk);
            }
        }
        catch { }
        finally
        {
            ConcurrentQueue<byte[]> rq;
            if (Queues.TryGetValue("r_" + sid, out rq)) rq.Enqueue(new byte[0]);
            try { sock.Close(); } catch { }
            Socket _; Sessions.TryRemove(sid, out _);
        }
    }


    static byte[] Cp(byte[] s, int so, byte[] d, int dp, int l) { for (int i = 0; i < l; i++) d[dp + i] = s[so + i]; return d; }
    static byte[] Cat(byte[] a, byte[] b) { byte[] r = new byte[a.Length + b.Length]; Cp(a, 0, r, 0, a.Length); Cp(b, 0, r, a.Length, b.Length); return r; }
    static byte[] S2B(string s) { byte[] r = new byte[s.Length]; for (int i = 0; i < s.Length; i++) r[i] = (byte)(s[i] & 0xFF); return r; }

    static byte[][] Dk(string key)
    {
        byte[] master; using (var sha = SHA256.Create()) master = sha.ComputeHash(Encoding.UTF8.GetBytes(key));
        byte[] ek, ak;
        using (var sha = SHA256.Create()) ek = sha.ComputeHash(Cat(master, S2B("enc")));
        using (var sha = SHA256.Create()) ak = sha.ComputeHash(Cat(master, S2B("auth")));
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
                Cp(ek, 0, input, 0, ek.Length); Cp(n, 0, input, ek.Length, n.Length);
                input[ek.Length + n.Length] = (byte)(c >> 24); input[ek.Length + n.Length + 1] = (byte)(c >> 16);
                input[ek.Length + n.Length + 2] = (byte)(c >> 8); input[ek.Length + n.Length + 3] = (byte)c;
                byte[] h = sha.ComputeHash(input); int r = (int)(len - ms.Length);
                if (r > h.Length) r = h.Length; ms.Write(h, 0, r);
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
            ms.Write(n, 0, n.Length); ms.Write(ct, 0, ct.Length);
            byte[] h = hmac.ComputeHash(ms.ToArray());
            byte[] tag = new byte[16]; Cp(h, 0, tag, 0, 16); return tag;
        }
    }

    static byte[] Enc(byte[] data, string key)
    {
        try
        {
            byte[][] ks = Dk(key); byte[] ek = ks[0], ak = ks[1];
            long ctr = Interlocked.Increment(ref ECTR);
            byte[] iv;
            using (var sha = SHA256.Create())
            {
                byte[] input = new byte[ek.Length + 8]; Cp(ek, 0, input, 0, ek.Length);
                input[ek.Length] = (byte)(ctr >> 56); input[ek.Length + 1] = (byte)(ctr >> 48);
                input[ek.Length + 2] = (byte)(ctr >> 40); input[ek.Length + 3] = (byte)(ctr >> 32);
                input[ek.Length + 4] = (byte)(ctr >> 24); input[ek.Length + 5] = (byte)(ctr >> 16);
                input[ek.Length + 6] = (byte)(ctr >> 8); input[ek.Length + 7] = (byte)ctr;
                iv = sha.ComputeHash(input);
            }
            byte[] n = new byte[12]; Cp(iv, 0, n, 0, 12);
            byte[] k2 = GKS(ek, n, data.Length); byte[] ct = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) ct[i] = (byte)(data[i] ^ k2[i]);
            byte[] tag = CTag(ak, n, ct);
            byte[] result = new byte[12 + ct.Length + 16];
            Cp(n, 0, result, 0, 12); Cp(ct, 0, result, 12, ct.Length); Cp(tag, 0, result, 12 + ct.Length, 16);
            return result;
        }
        catch { return new byte[0]; }
    }

    static byte[] Dec(byte[] data, string key)
    {
        try
        {
            if (data.Length < 28) return null;
            byte[][] ks = Dk(key); byte[] ek = ks[0], ak = ks[1];
            byte[] n = new byte[12]; Cp(data, 0, n, 0, 12);
            byte[] tag = new byte[16]; Cp(data, data.Length - 16, tag, 0, 16);
            byte[] ct = new byte[data.Length - 28]; Cp(data, 12, ct, 0, ct.Length);
            byte[] exp = CTag(ak, n, ct);
            for (int i = 0; i < 16; i++) if (exp[i] != tag[i]) return null;
            byte[] k2 = GKS(ek, n, ct.Length); byte[] pt = new byte[ct.Length];
            for (int i = 0; i < ct.Length; i++) pt[i] = (byte)(ct[i] ^ k2[i]);
            return pt;
        }
        catch { return null; }
    }


    static byte[] MkPkt(int flag, int sid, int seq, int ack, byte[] data)
    {
        byte[] r = new byte[17 + data.Length];
        r[0] = (byte)flag;
        r[1] = (byte)(sid >> 24); r[2] = (byte)(sid >> 16); r[3] = (byte)(sid >> 8); r[4] = (byte)sid;
        r[5] = (byte)(seq >> 24); r[6] = (byte)(seq >> 16); r[7] = (byte)(seq >> 8); r[8] = (byte)seq;
        r[9] = (byte)(ack >> 24); r[10] = (byte)(ack >> 16); r[11] = (byte)(ack >> 8); r[12] = (byte)ack;
        r[13] = (byte)(data.Length >> 24); r[14] = (byte)(data.Length >> 16); r[15] = (byte)(data.Length >> 8); r[16] = (byte)data.Length;
        if (data.Length > 0) Cp(data, 0, r, 17, data.Length);
        return r;
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
                if ((flag & 0x0F) == 0x01) { byte[] d = new byte[dlen]; Cp(raw, off, d, 0, dlen); return d; }
                off += dlen;
            }
        }
        catch { }
        return null;
    }

    static Socket Connect(byte[] dd)
    {
        try
        {
            int hlen = dd[0]; string host = Encoding.UTF8.GetString(dd, 1, hlen);
            int port = (dd[1 + hlen] << 8) | dd[2 + hlen];
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            s.Connect(host, port); s.NoDelay = true; return s;
        }
        catch { return null; }
    }


    static void WriteFrame(Stream os, int typeByte, byte[] data)
    {
        byte[] payload = new byte[1 + data.Length]; payload[0] = (byte)typeByte;
        Cp(data, 0, payload, 1, data.Length);
        byte[] encrypted = Enc(payload, KEY);
        byte[] lenBuf = new byte[] { (byte)(encrypted.Length >> 24), (byte)(encrypted.Length >> 16), (byte)(encrypted.Length >> 8), (byte)encrypted.Length };
        os.Write(lenBuf, 0, 4); os.Write(encrypted, 0, encrypted.Length); os.Flush();
    }

    static byte[] ReadFrame(Stream is_)
    {
        byte[] lb = new byte[4]; int t = 0;
        while (t < 4) { int n = is_.Read(lb, t, 4 - t); if (n <= 0) return null; t += n; }
        int fl = (lb[0] << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3];
        if (fl <= 0 || fl > 262144) return null;
        byte[] fb = new byte[fl]; t = 0;
        while (t < fl) { int n = is_.Read(fb, t, fl - t); if (n <= 0) return null; t += n; }
        byte[] d = Dec(fb, KEY);
        return (d != null && d.Length >= 1) ? d : null;
    }

    static string ReadJson(Stream is_)
    {
        MemoryStream bos = new MemoryStream();
        int depth = 0; bool inStr = false, esc = false; int b;
        while ((b = is_.ReadByte()) != -1)
        {
            bos.WriteByte((byte)b); char ch = (char)b;
            if (inStr) { if (esc) esc = false; else if (ch == '\\') esc = true; else if (ch == '"') inStr = false; }
            else { if (ch == '"') inStr = true; else if (ch == '{') depth++; else if (ch == '}') { depth--; if (depth == 0) break; } }
        }
        return Encoding.UTF8.GetString(bos.ToArray());
    }


    static string B64E(byte[] b) { return Convert.ToBase64String(b); }
    static byte[] B64D(string s) { return Convert.FromBase64String(s); }

    static string JStr(string json, string key)
    {
        string q = "\"" + key + "\""; int i = json.IndexOf(q); if (i < 0) return null; i += q.Length;
        while (i < json.Length && json[i] != ':') i++; if (i >= json.Length) return null; i++;
        while (i < json.Length && json[i] == ' ') i++; if (i >= json.Length) return null;
        if (json[i] == '"')
        {
            StringBuilder sb = new StringBuilder(); i++;
            while (i < json.Length && json[i] != '"') { if (json[i] == '\\' && i + 1 < json.Length) { i++; sb.Append(json[i]); } else sb.Append(json[i]); i++; }
            return sb.ToString();
        }
        int s = i;
        while (i < json.Length && ",} \t\r\n".IndexOf(json[i]) < 0) i++;
        return json.Substring(s, i - s);
    }
}
