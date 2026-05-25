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
	t := fs.String("t", "", "Payload type: jsp, jspx, php, aspx, asp, java, cs")
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
	case "jspx":
		data = generateJSPX(*k)
	case "php":
		data = generatePHP(*k)
	case "aspx":
		data = generateASPX(*k)
	case "asp":
		data = generateASP(*k)
	case "java":
		data = generateJava(*k)
	case "cs":
		data = generateCS(*k)
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

func generateJSPX(key string) string {
	return strings.Replace(payload.JSPXTemplate, `String KEY = "CHANGE_ME"`, `String KEY = "`+key+`"`, 1)
}

func generateASPX(key string) string {
	return strings.Replace(payload.ASPXTemplate, `static string KEY = "CHANGE_ME"`, `static string KEY = "`+key+`"`, 1)
}

func generateASP(key string) string {
	return strings.Replace(payload.ASPTemplate, `var KEY = "CHANGE_ME"`, `var KEY = "`+key+`"`, 1)
}

func generateJava(key string) string {
	return strings.Replace(payload.JavaTemplate, `private static String KEY = "CHANGE_ME"`, `private static String KEY = "`+key+`"`, 1)
}

func generateCS(key string) string {
	return strings.Replace(payload.CSTemplate, `static string KEY = "CHANGE_ME"`, `static string KEY = "`+key+`"`, 1)
}
