package main

import (
	"flag"
	"fmt"
	"os"
	"reflectgo/inject"
	"reflectgo/pe"

	"github.com/BurntSushi/toml"
)

var (
	conf       Config
	configPath string
	mode       int
	isDebug    bool
)

type Config struct {
	File   string
	Params string
}

func main() {
	flag.Parse()

	_, err := toml.DecodeFile(configPath, &conf)
	if err != nil {
		fmt.Println("parse file config error", err)
		os.Exit(1)
	}

	switch mode {
	case 0:
		m := pe.New(conf.File, conf.Params)
		if isDebug {
			m.Debug()
		}

		err := m.Exec()
		if err != nil {
			fmt.Println(err)
		}
	case 1:
		p := inject.New(conf.File, conf.Params)
		p.Run()
	default:
		fmt.Println("Not Support!")
	}
}

func init() {
	flag.StringVar(&configPath, "c", "config.toml", "path of file config")
	flag.BoolVar(&isDebug, "debug", false, "enable debug")
	flag.IntVar(&mode, "mode", 0, "mode for execute: 0 - reflect || 1 - process")
}
