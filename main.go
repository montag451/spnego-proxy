package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/crypto/ssh/terminal"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

func getPassword(passwordFile string) (string, error) {
	var password []byte
	if passwordFile == "" {
		stdin := int(os.Stdin.Fd())
		if !terminal.IsTerminal(stdin) {
			return "", errors.New("no password file specified and stdin is not a terminal")
		}
		stdout := int(os.Stdout.Fd())
		if !terminal.IsTerminal(stdout) {
			return "", errors.New("no password file specified and stdout is not a terminal")
		}
		fmt.Print("Password: ")
		var err error
		password, err = terminal.ReadPassword(stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
	} else {
		f, err := os.Open(passwordFile)
		if err != nil {
			return "", fmt.Errorf("failed to open password file %q: %w", passwordFile, err)
		}
		password, err = ioutil.ReadAll(f)
		if err != nil {
			return "", fmt.Errorf("failed to read password file %q: %w", passwordFile, err)
		}
	}
	return string(password), nil
}

type SPNEGOClient struct {
	Client *spnego.SPNEGO
	mu     sync.Mutex
}

func (c *SPNEGOClient) GetToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Client.AcquireCred(); err != nil {
		return "", fmt.Errorf("could not acquire client credential: %v", err)
	}
	token, err := c.Client.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("could not initialize context: %v", err)
	}
	b, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("could not marshal SPNEGO token: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func handleClient(conn net.Conn, proxy string, spnegoCli *SPNEGOClient, debug bool) {
	defer conn.Close()
	if debug {
		defer logger.Printf("stop processing request for client: %v", conn.RemoteAddr())
		logger.Printf("new client: %v", conn.RemoteAddr())
	}
	proxyConn, err := net.Dial("tcp", proxy)
	if err != nil {
		logger.Printf("failed to connect to proxy: %v", err)
		return
	}
	defer proxyConn.Close()
	reqReader := bufio.NewReader(conn)
	respReader := bufio.NewReader(proxyConn)
	if debug {
		reqReader = bufio.NewReader(io.TeeReader(conn, os.Stdout))
		respReader = bufio.NewReader(io.TeeReader(proxyConn, os.Stdout))
	}
	for {
		token, err := spnegoCli.GetToken()
		if err != nil {
			logger.Printf("failed to get SPNEGO token: %v", err)
			return
		}
		authHeader := "Negotiate " + token
		req, err := http.ReadRequest(reqReader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Printf("failed to read request: %v", err)
			}
			return
		}
		req.Header.Set("Proxy-Authorization", authHeader)
		if debug {
			req.WriteProxy(io.MultiWriter(proxyConn, os.Stdout))
		} else {
			req.WriteProxy(proxyConn)
		}
		if req.Method == "CONNECT" {
			var wg sync.WaitGroup
			forward := func(from, to net.Conn) {
				defer wg.Done()
				defer to.(*net.TCPConn).CloseWrite()
				if debug {
					fromAddr, toAddr := from.RemoteAddr(), to.RemoteAddr()
					logger.Printf("forward start %v -> %v", fromAddr, toAddr)
					defer logger.Printf("forward done %v -> %v", fromAddr, toAddr)
				}
				io.Copy(to, from)
			}
			wg.Add(2)
			go forward(conn, proxyConn)
			go forward(proxyConn, conn)
			wg.Wait()
			return
		}
		resp, err := http.ReadResponse(respReader, req)
		if err != nil {
			logger.Printf("failed to read response: %v", err)
			return
		}
		var respWriter io.Writer = conn
		if debug {
			respWriter = io.MultiWriter(conn, os.Stdout)
		}
		if err := resp.Write(respWriter); err != nil {
			logger.Printf("failed to write response: %v", err)
			return
		}
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	cfgFile := flag.String("config", "", "config file")
	user := flag.String("user", "", "user name")
	realm := flag.String("realm", "", "realm")
	proxy := flag.String("proxy", "", "proxy address")
	spn := flag.String("spn", "", "service principal name")
	passwordFile := flag.String("password-file", "", "password file path")
	debug := flag.Bool("debug", false, "turn on debugging")
	flag.Parse()
	if *addr == "" || *cfgFile == "" || *user == "" || *realm == "" || *proxy == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *spn == "" {
		host, _, err := net.SplitHostPort(*proxy)
		if err != nil {
			logger.Panic(err)
		}
		*spn = "HTTP/" + host
		logger.Println("inferred service principal name:", *spn)
		logger.Println("if it's not correct use the -spn flag")
	}
	cfg, err := config.Load(*cfgFile)
	if err != nil {
		logger.Panic(err)
	}
	passwd, err := getPassword(*passwordFile)
	if err != nil {
		logger.Panic(err)
	}
	opts := []func(*client.Settings){
		client.DisablePAFXFAST(true),
	}
	if *debug {
		opts = append(opts, client.Logger(logger))
	}
	cli := client.NewWithPassword(*user, *realm, passwd, cfg, opts...)
	spnegoCli := &SPNEGOClient{
		Client: spnego.SPNEGOClient(cli, *spn),
	}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Panic(err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Panic(err)
		}
		go handleClient(conn, *proxy, spnegoCli, *debug)
	}
}
