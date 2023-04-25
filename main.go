package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"reflectgo/inject"
	"reflectgo/pe"
	"strings"
)

var (
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
	file, params, err := getConfig(configPath)
	if err != nil {
		fmt.Println("parse file config error", err)
		os.Exit(1)
	}

	switch mode {
	case 1:
		p := inject.New(file, params)
		err = p.Run()
		if err != nil {
			fmt.Println(err)
		}
	default:
		m := pe.New(file, params)
		if isDebug {
			m.Debug()
		}

		err := m.Exec()
		if err != nil {
			fmt.Println(err)
		}
	}
}

func getConfig(path string) (string, string, error) {
	readFile, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var commands []string

	for fileScanner.Scan() {
		text := fileScanner.Text()
		if strings.HasPrefix(text, "#") {
			continue
		}
		commands = append(commands, text)
		if len(commands) >= 2 {
			break
		}
	}
	readFile.Close()
	lenCommand := len(commands)
	if lenCommand < 1 {
		return "", "", fmt.Errorf("no pe file")
	} else if lenCommand == 1 {
		commands = append(commands, "")
	}

	return strings.TrimSpace(commands[0]), strings.TrimSpace(commands[1]), nil
}

func init() {
	flag.StringVar(&configPath, "c", "config.toml", "path of file config")
	flag.BoolVar(&isDebug, "v", false, "enable debug")
	flag.IntVar(&mode, "m", 0, "mode for execute: 0 - reflect || 1 - process")
}
