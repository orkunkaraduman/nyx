package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/go-httpproxy/httpproxy"
)

type prxCtxUserData struct {
	ID         string
	Tm         time.Time
	AuthUser   string
	RemoteAddr string
	RealAddr   string
	RrAddr     string
	SubID      string
	SubTm      time.Time
}

func prxOnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	if !opts.Verbose && err != httpproxy.ErrPanic {
		return
	}
	e := errors.New("")
	if opErr != nil {
		e = opErr
	}
	logErr.Printf("%s: %s: %s", where, err, e)
}

func prxOnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	userData := &prxCtxUserData{}
	ctx.UserData = userData
	rn, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	h := md5.New()
	h.Write(rn.Bytes())
	userData.ID = hex.EncodeToString(h.Sum(nil))
	userData.Tm = time.Now()
	userData.RemoteAddr = r.RemoteAddr
	userData.RealAddr = r.Header.Get("X-Forwarded-For")
	userData.RrAddr = userData.RemoteAddr
	if userData.RealAddr != "" {
		userData.RrAddr += fmt.Sprintf("[%s]", userData.RealAddr)
	}
	log.Printf("Accept %s %s", userData.ID, userData.RrAddr)
	if r.Method == "GET" && !r.URL.IsAbs() {
		switch r.URL.Path {
		case "/info":
			w.Write([]byte("This is nyx http proxy."))
		case "/healthcheck":
			w.Write([]byte("UP"))
		case "/mitm.crt":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			pemBlock := pem.Block{Type: "CERTIFICATE", Bytes: mitmCaCert}
			pem.Encode(w, &pemBlock)
		default:
			http.Error(w, "This is a proxy server. Does not respond to non-proxy requests except /info or /healthcheck or /mitm.crt", 500)
		}
		return true
	}
	return false
}

func prxOnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	userData := ctx.UserData.(*prxCtxUserData)
	userData.AuthUser = user
	confMu.RLock()
	defer confMu.RUnlock()
	if conf.Auth == nil || len(conf.Auth.Users) <= 0 {
		return false
	}
	if p, ok := conf.Auth.Users[user]; ok && p == pass {
		log.Printf("AuthOK %s %s", userData.ID, userData.AuthUser)
		return true
	}
	log.Printf("AuthError %s %s", userData.ID, userData.AuthUser)
	return false
}

func prxOnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	userData := ctx.UserData.(*prxCtxUserData)
	log.Printf("Connect %s %s %s", userData.ID, ctx.ConnectReq.Method, ctx.ConnectReq.RequestURI)
	ConnectAction = httpproxy.ConnectProxy
	newHost = host
	confMu.RLock()
	defer confMu.RUnlock()
	if conf.Mitm == nil {
		return
	}
	for _, h := range conf.Mitm.Hosts {
		if h == host {
			return httpproxy.ConnectMitm, host
		}
	}
	return
}

func prxOnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	userData := ctx.UserData.(*prxCtxUserData)
	/*rn, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	h := md5.New()
	h.Write(rn.Bytes())
	userData.SubID = hex.EncodeToString(h.Sum(nil))*/
	userData.SubTm = time.Now()
	log.Printf("Request %s %s %s", userData.ID, req.Method, req.RequestURI)
	if priv, _ := isPrivateHostname(req.URL.Hostname()); priv {
		resp = httpproxy.InMemoryResponse(502, nil, []byte("Can not proxy to private host"))
		return
	}
	return
}

func prxOnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	resp.Header.Add("Via", "nyx")
}
