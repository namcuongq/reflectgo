package main

import (
	"flag"
	"fmt"
	"os"
	"reflectgo/pe"

	"github.com/BurntSushi/toml"
)

var (
	conf       pe.Config
	configPath string
	isDebug    bool
)

func main() {
	m := pe.New(conf)
	if isDebug {
		m.Debug()
	}

	err := m.Exec()
	if err != nil {
		fmt.Println(err)
	}
}

func init() {
	flag.StringVar(&configPath, "c", "config.toml", "path of file config")
	flag.BoolVar(&isDebug, "debug", false, "enable debug")
	flag.Parse()
	_, err := toml.DecodeFile(configPath, &conf)
	if err != nil {
		fmt.Println("parse file config error", err)
		os.Exit(1)
	}
}
