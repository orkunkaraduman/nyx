package main

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-httpproxy/httpproxy"
)

var logErr = log.New(os.Stderr, "ERR: ", log.LstdFlags)
var tlsCert, tlsKey []byte
var mitmCaCert, mitmCaKey []byte

func main() {
	log.SetOutput(os.Stdout)
	log.Print("started")

	sigTermChan := make(chan os.Signal)
	signal.Notify(sigTermChan, syscall.SIGTERM, os.Interrupt, os.Kill)
	sigHupChan := make(chan os.Signal)
	signal.Notify(sigHupChan, syscall.SIGHUP)

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionSSL30,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if conf.TLS != nil {
		var err error
		tlsCert, err = ioutil.ReadFile(conf.TLS.Cert)
		if err != nil {
			logErr.Fatal(err)
		}
		tlsKey, err = ioutil.ReadFile(conf.TLS.Key)
		if err != nil {
			logErr.Fatal(err)
		}
		cert, err := tls.X509KeyPair(tlsCert, tlsKey)
		if err != nil {
			logErr.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if conf.Mitm != nil {
		var err error
		mitmCaCert, err = ioutil.ReadFile(conf.Mitm.CaCert)
		if err != nil {
			logErr.Fatal(err)
		}
		mitmCaKey, err = ioutil.ReadFile(conf.Mitm.CaKey)
		if err != nil {
			logErr.Fatal(err)
		}
	}
	prx, err := httpproxy.NewProxyCert(mitmCaCert, mitmCaKey)
	if err != nil {
		logErr.Fatal(err)
	}
	prx.OnError = prxOnError
	prx.OnAccept = prxOnAccept
	if conf.Auth != nil {
		prx.OnAuth = prxOnAuth
	}
	prx.OnConnect = prxOnConnect
	prx.OnRequest = prxOnRequest
	prx.OnResponse = prxOnResponse

	server := &http.Server{
		Handler:      prx,
		ErrorLog:     log.New(ioutil.Discard, "", log.LstdFlags),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if opts.Verbose {
		server.ErrorLog = log.New(os.Stderr, "ERR: HTTP: ", log.LstdFlags)
	}
	serveErrChan := make(chan error)
	go func() {
		ln, err := net.Listen("tcp", conf.Listen)
		if err != nil {
			serveErrChan <- err
			return
		}
		defer ln.Close()
		if conf.TLS != nil {
			ln = tls.NewListener(ln, tlsConfig)
		}
		serveErrChan <- server.Serve(ln)
	}()
	log.Printf("listening %s", conf.Listen)

mainloop:
	for {
		select {
		case <-sigTermChan:
			break mainloop
		case <-sigHupChan:
			readConf(opts.ConfFile)
		case listenErr := <-serveErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			logErr.Fatal(listenErr)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server.SetKeepAlivesEnabled(false)
	if err := server.Shutdown(ctx); err == context.DeadlineExceeded {
		log.Print("force shutdown")
	} else {
		log.Print("graceful shutdown")
	}
}
