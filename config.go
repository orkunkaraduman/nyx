package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/BurntSushi/toml"
)

type options struct {
	ConfFile string
	Verbose  bool
}

var opts options

type config struct {
	Listen string
	TLS    *struct {
		Cert string
		Key  string
	}
	Mitm *struct {
		CaCert string
		CaKey  string
		Hosts  []string
	}
	Auth *struct {
		Users map[string]string
	}
}

var conf config
var confMu sync.RWMutex

func readConf(confFile string) error {
	newConf := config{Listen: ":8080"}
	_, err := toml.DecodeFile(confFile, &newConf)
	if err != nil {
		return err
	}
	confMu.Lock()
	defer confMu.Unlock()
	conf = newConf
	return nil
}

func init() {
	flag.StringVar(&opts.ConfFile, "c", "nyx.conf", "Config file")
	flag.BoolVar(&opts.Verbose, "v", false, "Show verbose debug information")
	flag.Parse()
	if err := readConf(opts.ConfFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
