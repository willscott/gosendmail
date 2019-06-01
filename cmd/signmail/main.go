package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/willscott/gosendmail/lib"
	"github.com/spf13/viper"
)

func main() {
	// get config
	viper.AddConfigPath("$HOME/.gosendmail")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	// get mail as input
	msg := lib.ReadMessage(os.Stdin)

	// Parse msg
	parsed := lib.ParseMessage(&msg)

	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		log.Fatalf("No configuration for sender %s", parsed.SourceDomain)
	}

	lib.SignMessage(&msg, parsed, cfg)

	// send to remote server.
	keycmd := strings.Split(cfg.SendCommand, " ")
	cmd := exec.Command(keycmd[0], keycmd[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer stdin.Close()
		io.Copy(stdin, bytes.NewReader(msg))
	}()

	_, err = cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
}
