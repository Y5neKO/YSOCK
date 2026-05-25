package ysock;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class YSock {
    private static String KEY = "CHANGE_ME";
    private static final AtomicLong ECTR = new AtomicLong(0);
    private static final ConcurrentHashMap<Long, Socket> sessions = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, LinkedBlockingQueue<byte[]>> queues = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Boolean> closeFlags = new ConcurrentHashMap<>();


    public static String handle(String body) {
        if (body == null || body.isEmpty()) return "{\"d\":\"\"}";
        String action = jStr(body, "a");
        if (action == null) return "{\"d\":\"\"}";
        try {
            switch (action) {
                case "h":  return onHandshake(body);
                case "c":  return onHalfCreate(body);
                case "d":  return onHalfData(body);
                case "x":  return onHalfClose(body);
                case "cc": return onClassicCreate(body);
                case "cp": return onClassicPoll(body);
                default:   return "{\"d\":\"\"}";
            }
        } catch (Exception e) { return "{\"d\":\"\"}"; }
    }


    public static void handleStream(InputStream in, OutputStream out) {
        try {
            String body = readJson(in);
            String action = jStr(body, "a");
            if (!"f".equals(action)) { out.write(jsonBytes("{\"d\":\"\"}")); return; }

            String rd = jStr(body, "d");
            if (rd == null) return;
            byte[] raw = dec(b64d(rd), KEY);
            if (raw == null || raw.length < 2) return;
            byte[] synData = parseSynData(raw);
            int[] synInfo = parseSyn(raw);
            if (synData == null || synInfo == null) return;
            int sid = synInfo[0], seq = synInfo[1];

            Socket sock = connect(synData);
            if (sock == null) {
                ByteArrayOutputStream fb = new ByteArrayOutputStream();
                fb.write(0); fb.write(1); fb.write(mkPkt(0x00, sid, 0, seq, new byte[0]));
                writeFrame(out, 0x00, fb.toByteArray()); return;
            }
            sessions.put((long) sid, sock);
            synchronized (out) { writeFrame(out, 0x00, new byte[0]); }

            new Thread(() -> {
                try {
                    byte[] buf = new byte[65536];
                    InputStream is = sock.getInputStream();
                    while (!sock.isClosed()) {
                        int n = is.read(buf); if (n == -1) break;
                        byte[] chunk = Arrays.copyOf(buf, n);
                        synchronized (out) { writeFrame(out, 0x01, chunk); out.flush(); }
                    }
                } catch (Exception e) {}
                finally {
                    try { synchronized (out) { writeFrame(out, 0x02, new byte[0]); out.flush(); } } catch (Exception e) {}
                    try { sock.close(); } catch (Exception e) {}
                    sessions.remove((long) sid);
                }
            }).start();

            OutputStream sockOut = sock.getOutputStream();
            while (!sock.isClosed()) {
                byte[] frame = readFrame(in);
                if (frame == null) break;
                byte typeByte = frame[0];
                byte[] data = Arrays.copyOfRange(frame, 1, frame.length);
                if (typeByte == 0x01 && data.length > 0) sockOut.write(data);
                else if (typeByte == 0x02) break;
            }
            sock.close(); sessions.remove((long) sid);
        } catch (Exception e) {}
    }
    private static String onHandshake(String body) throws Exception {
        String rd = jStr(body, "d");
        if (rd == null) return "{\"d\":\"\",\"m\":3}";
        byte[] raw = dec(b64d(rd), KEY);
        if (raw == null) return "{\"d\":\"\",\"m\":3}";
        return "{\"d\":\"" + b64e(enc(raw, KEY)) + "\",\"m\":2}";
    }

    private static String onClassicCreate(String body) throws Exception {
        String rd = jStr(body, "d");
        if (rd == null) return "{\"d\":\"\"}";
        byte[] raw = dec(b64d(rd), KEY);
        if (raw == null || raw.length < 2) return "{\"d\":\"\"}";
        byte[] synData = parseSynData(raw);
        int[] synInfo = parseSyn(raw);
        if (synData == null || synInfo == null) return "{\"d\":\"\"}";
        int sid = synInfo[0], seq = synInfo[1];

        Socket sock = connect(synData);
        if (sock == null) {
            ByteArrayOutputStream fb = new ByteArrayOutputStream();
            fb.write(0); fb.write(1); fb.write(mkPkt(0x00, sid, 0, seq, new byte[0]));
            return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\"}";
        }
        sessions.put((long) sid, sock);
        queues.put("r_" + sid, new LinkedBlockingQueue<byte[]>());
        queues.put("w_" + sid, new LinkedBlockingQueue<byte[]>());
        ByteArrayOutputStream fb = new ByteArrayOutputStream();
        fb.write(0); fb.write(1); fb.write(mkPkt(0x04, sid, 0, seq, new byte[0]));
        new Thread(() -> bgRead(sid, sock)).start();
        return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\",\"id\":\"" + sid + "\"}";
    }

    private static String onClassicPoll(String body) throws Exception {
        String idStr = jStr(body, "id"), rd = jStr(body, "d");
        long sid = 0;
        if (idStr != null && !idStr.isEmpty()) sid = Long.parseLong(idStr);
        if (rd != null && !rd.isEmpty() && sid > 0) {
            byte[] raw = dec(b64d(rd), KEY);
            if (raw != null) {
                Socket sock = sessions.get(sid);
                if (sock != null && !sock.isClosed()) {
                    try { sock.getOutputStream().write(raw); } catch (Exception e) { sessions.remove(sid); }
                }
            }
        }
        if (sid > 0) {
            LinkedBlockingQueue<byte[]> rq = queues.get("r_" + sid);
            ByteArrayOutputStream db = new ByteArrayOutputStream(); boolean fin = false;
            if (rq != null) { byte[] chunk; while ((chunk = rq.poll()) != null) { if (chunk.length == 0) { fin = true; break; } db.write(chunk); } }
            byte[] rd2 = db.toByteArray();
            Socket sock = sessions.get(sid);
            if (sock == null || sock.isClosed()) fin = true;
            if (rd2.length > 0) {
                ByteArrayOutputStream fb = new ByteArrayOutputStream();
                fb.write(0); fb.write(1); fb.write(mkPkt(0x02, (int) sid, 0, 0, rd2));
                return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\",\"fin\":" + fin + "}";
            } else if (fin) {
                ByteArrayOutputStream fb = new ByteArrayOutputStream();
                fb.write(0); fb.write(1); fb.write(mkPkt(0x08, (int) sid, 0, 0, new byte[0]));
                return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\",\"fin\":true}";
            }
            return "{\"d\":\"\",\"fin\":false}";
        }
        return "{\"d\":\"\",\"fin\":false}";
    }

    private static String onHalfCreate(String body) throws Exception {
        String rd = jStr(body, "d");
        if (rd == null) return "{\"d\":\"\"}";
        byte[] raw = dec(b64d(rd), KEY);
        if (raw == null || raw.length < 2) return "{\"d\":\"\"}";
        byte[] synData = parseSynData(raw);
        int[] synInfo = parseSyn(raw);
        if (synData == null || synInfo == null) return "{\"d\":\"\"}";
        int sid = synInfo[0], seq = synInfo[1];
        Socket sock = connect(synData);
        if (sock == null) {
            ByteArrayOutputStream fb = new ByteArrayOutputStream();
            fb.write(0); fb.write(1); fb.write(mkPkt(0x00, sid, 0, seq, new byte[0]));
            return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\"}";
        }
        sessions.put((long) sid, sock);
        LinkedBlockingQueue<byte[]> wq = new LinkedBlockingQueue<>();
        queues.put("w_" + sid, wq);

        ByteArrayOutputStream fb = new ByteArrayOutputStream();
        fb.write(0); fb.write(1); fb.write(mkPkt(0x04, sid, 0, seq, new byte[0]));

        new Thread(() -> bgRead(sid, sock)).start();

        new Thread(() -> {
            try {
                while (!sock.isClosed() && !closeFlags.containsKey("c_" + sid)) {
                    byte[] wd = wq.poll(200, TimeUnit.MILLISECONDS);
                    if (wd != null && wd.length > 0) { try { sock.getOutputStream().write(wd); } catch (Exception e) { break; } }
                    if (sock.isClosed()) break;
                }
            } catch (Exception e) {}
            finally { closeFlags.remove("c_" + sid); queues.remove("w_" + sid); sessions.remove((long) sid); }
        }).start();
        return "{\"d\":\"" + b64e(enc(fb.toByteArray(), KEY)) + "\",\"id\":\"" + sid + "\"}";
    }

    private static String onHalfData(String body) throws Exception {
        String idStr = jStr(body, "id"), rd = jStr(body, "d");
        if (idStr == null || rd == null) return "{\"ok\":false}";
        long sid = Long.parseLong(idStr);
        byte[] raw = dec(b64d(rd), KEY);
        if (raw == null) return "{\"ok\":false}";
        LinkedBlockingQueue<byte[]> wq = queues.get("w_" + sid);
        if (wq == null) return "{\"ok\":false}";
        wq.offer(raw);
        return "{\"ok\":true}";
    }

    private static String onHalfClose(String body) throws Exception {
        String idStr = jStr(body, "id");
        if (idStr == null) return "{\"ok\":false}";
        closeFlags.put("c_" + Long.parseLong(idStr), true);
        return "{\"ok\":true}";
    }
    private static void bgRead(long sid, Socket sock) {
        byte[] buf = new byte[65536];
        try {
            InputStream is = sock.getInputStream();
            while (!sock.isClosed() && !closeFlags.containsKey("c_" + sid)) {
                int n = is.read(buf); if (n == -1) break;
                byte[] chunk = Arrays.copyOf(buf, n);
                LinkedBlockingQueue<byte[]> rq = queues.get("r_" + sid);
                if (rq != null) rq.offer(chunk);
            }
        } catch (Exception e) {}
        finally {
            LinkedBlockingQueue<byte[]> rq = queues.get("r_" + sid);
            if (rq != null) rq.offer(new byte[0]);
            try { sock.close(); } catch (Exception e) {}
            sessions.remove(sid);
        }
    }
    private static byte[][] dk(String key) throws Exception {
        byte[] master = sha256(key.getBytes("UTF-8"));
        return new byte[][]{ sha256(cat(master, "enc".getBytes("UTF-8"))), sha256(cat(master, "auth".getBytes("UTF-8"))) };
    }
    private static byte[] gks(byte[] ek, byte[] n, int len) throws Exception {
        ByteArrayOutputStream s = new ByteArrayOutputStream(); int c = 0;
        while (s.size() < len) {
            MessageDigest md = MessageDigest.getInstance("SHA-256"); md.update(ek); md.update(n);
            md.update(new byte[]{(byte)(c>>24),(byte)(c>>16),(byte)(c>>8),(byte)c});
            byte[] h = md.digest(); int r = len - s.size();
            s.write(h, 0, r > h.length ? h.length : r); c++;
        }
        return s.toByteArray();
    }
    private static byte[] ctag(byte[] ak, byte[] n, byte[] ct) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(ak, "HmacSHA256"));
        mac.update(n); mac.update(ct); return Arrays.copyOf(mac.doFinal(), 16);
    }
    private static byte[] enc(byte[] data, String key) {
        try {
            byte[][] ks = dk(key); byte[] ek = ks[0], ak = ks[1];
            long ctr = ECTR.incrementAndGet();
            MessageDigest md = MessageDigest.getInstance("SHA-256"); md.update(ek);
            md.update(new byte[]{(byte)(ctr>>56),(byte)(ctr>>48),(byte)(ctr>>40),(byte)(ctr>>32),(byte)(ctr>>24),(byte)(ctr>>16),(byte)(ctr>>8),(byte)ctr});
            byte[] iv = md.digest(); byte[] n = Arrays.copyOf(iv, 12);
            byte[] k2 = gks(ek, n, data.length); byte[] ct = new byte[data.length];
            for (int i = 0; i < data.length; i++) ct[i] = (byte)(data[i] ^ k2[i]);
            byte[] tag = ctag(ak, n, ct);
            byte[] out = new byte[12 + ct.length + 16];
            System.arraycopy(n, 0, out, 0, 12); System.arraycopy(ct, 0, out, 12, ct.length); System.arraycopy(tag, 0, out, 12 + ct.length, 16);
            return out;
        } catch (Exception e) { return new byte[0]; }
    }
    private static byte[] dec(byte[] data, String key) {
        try {
            if (data.length < 28) return null;
            byte[][] ks = dk(key); byte[] ek = ks[0], ak = ks[1];
            byte[] n = Arrays.copyOfRange(data, 0, 12);
            byte[] tag = Arrays.copyOfRange(data, data.length - 16, data.length);
            byte[] ct = Arrays.copyOfRange(data, 12, data.length - 16);
            if (!Arrays.equals(tag, ctag(ak, n, ct))) return null;
            byte[] k2 = gks(ek, n, ct.length); byte[] pt = new byte[ct.length];
            for (int i = 0; i < ct.length; i++) pt[i] = (byte)(ct[i] ^ k2[i]);
            return pt;
        } catch (Exception e) { return null; }
    }
    private static byte[] sha256(byte[] data) { try { return MessageDigest.getInstance("SHA-256").digest(data); } catch (Exception e) { return new byte[0]; } }
    private static byte[] cat(byte[] a, byte[] b) { byte[] r = new byte[a.length + b.length]; System.arraycopy(a, 0, r, 0, a.length); System.arraycopy(b, 0, r, a.length, b.length); return r; }
    private static byte[] mkPkt(int flag, int sid, int seq, int ack, byte[] data) {
        byte[] r = new byte[17 + data.length];
        r[0] = (byte) flag;
        r[1] = (byte)(sid>>24); r[2] = (byte)(sid>>16); r[3] = (byte)(sid>>8); r[4] = (byte)sid;
        r[5] = (byte)(seq>>24); r[6] = (byte)(seq>>16); r[7] = (byte)(seq>>8); r[8] = (byte)seq;
        r[9] = (byte)(ack>>24); r[10] = (byte)(ack>>16); r[11] = (byte)(ack>>8); r[12] = (byte)ack;
        r[13] = (byte)(data.length>>24); r[14] = (byte)(data.length>>16); r[15] = (byte)(data.length>>8); r[16] = (byte)data.length;
        if (data.length > 0) System.arraycopy(data, 0, r, 17, data.length);
        return r;
    }
    private static int[] parseSyn(byte[] raw) {
        try { if (raw.length < 2) return null; int cnt = ((raw[0]&0xFF)<<8)|(raw[1]&0xFF), off = 2;
            for (int i = 0; i < cnt; i++) { if (off+17>raw.length) break; int flag = raw[off]&0xFF;
                int sid = ((raw[off+1]&0xFF)<<24)|((raw[off+2]&0xFF)<<16)|((raw[off+3]&0xFF)<<8)|(raw[off+4]&0xFF);
                int seq = ((raw[off+5]&0xFF)<<24)|((raw[off+6]&0xFF)<<16)|((raw[off+7]&0xFF)<<8)|(raw[off+8]&0xFF);
                int dlen = ((raw[off+13]&0xFF)<<24)|((raw[off+14]&0xFF)<<16)|((raw[off+15]&0xFF)<<8)|(raw[off+16]&0xFF);
                off += 17; if ((flag&0x0F) == 0x01) return new int[]{sid,seq}; off += dlen;
            }
        } catch (Exception e) {} return null;
    }
    private static byte[] parseSynData(byte[] raw) {
        try { if (raw.length < 2) return null; int cnt = ((raw[0]&0xFF)<<8)|(raw[1]&0xFF), off = 2;
            for (int i = 0; i < cnt; i++) { if (off+17>raw.length) break; int flag = raw[off]&0xFF;
                int dlen = ((raw[off+13]&0xFF)<<24)|((raw[off+14]&0xFF)<<16)|((raw[off+15]&0xFF)<<8)|(raw[off+16]&0xFF);
                off += 17; if (off+dlen>raw.length) break;
                if ((flag&0x0F) == 0x01) return Arrays.copyOfRange(raw, off, off+dlen); off += dlen;
            }
        } catch (Exception e) {} return null;
    }
    private static Socket connect(byte[] dd) {
        try { int hlen = dd[0]&0xFF; String host = new String(dd, 1, hlen);
            int port = ((dd[1+hlen]&0xFF)<<8)|(dd[2+hlen]&0xFF);
            Socket s = new Socket(); s.connect(new InetSocketAddress(host, port), 5000); s.setTcpNoDelay(true); return s;
        } catch (Exception e) { return null; }
    }
    private static void writeFrame(OutputStream os, int typeByte, byte[] data) throws Exception {
        byte[] payload = new byte[1 + data.length]; payload[0] = (byte) typeByte;
        System.arraycopy(data, 0, payload, 1, data.length);
        byte[] encrypted = enc(payload, KEY);
        os.write(new byte[]{(byte)(encrypted.length>>24),(byte)(encrypted.length>>16),(byte)(encrypted.length>>8),(byte)encrypted.length});
        os.write(encrypted); os.flush();
    }
    private static byte[] readFrame(InputStream is) throws Exception {
        byte[] lb = new byte[4]; int t = 0;
        while (t < 4) { int n = is.read(lb, t, 4-t); if (n==-1) return null; t+=n; }
        int fl = ((lb[0]&0xFF)<<24)|((lb[1]&0xFF)<<16)|((lb[2]&0xFF)<<8)|(lb[3]&0xFF);
        if (fl <= 0 || fl > 262144) return null;
        byte[] fb = new byte[fl]; t = 0;
        while (t < fl) { int n = is.read(fb, t, fl-t); if (n==-1) return null; t+=n; }
        byte[] d = dec(fb, KEY); return (d != null && d.length >= 1) ? d : null;
    }
    private static String readJson(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int depth = 0; boolean inStr = false, esc = false; int b;
        while ((b = is.read()) != -1) { bos.write(b); char ch = (char)b;
            if (inStr) { if (esc) esc=false; else if (ch=='\\') esc=true; else if (ch=='"') inStr=false; }
            else { if (ch=='"') inStr=true; else if (ch=='{') depth++; else if (ch=='}') { depth--; if (depth==0) break; } }
        }
        return bos.toString("ISO-8859-1");
    }
    private static String b64e(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] b64d(String s) { return Base64.getDecoder().decode(s); }
    private static byte[] jsonBytes(String s) { try { return s.getBytes("UTF-8"); } catch (Exception e) { return new byte[0]; } }
    private static String jStr(String json, String key) {
        String q = "\""+key+"\""; int i = json.indexOf(q); if (i<0) return null; i+=q.length();
        while (i<json.length() && json.charAt(i)!=':') i++; if (i>=json.length()) return null; i++;
        while (i<json.length() && json.charAt(i)==' ') i++; if (i>=json.length()) return null;
        if (json.charAt(i)=='"') { StringBuilder sb=new StringBuilder(); i++;
            while (i<json.length() && json.charAt(i)!='"') { if (json.charAt(i)=='\\'&&i+1<json.length()){i++;sb.append(json.charAt(i));}else sb.append(json.charAt(i)); i++; }
            return sb.toString(); }
        int s=i; while (i<json.length() && ",} \t\r\n".indexOf(json.charAt(i))<0) i++;
        return json.substring(s,i);
    }
}
