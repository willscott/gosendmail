package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
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

	for _, dest := range parsed.DestDomain {
		SendTo(dest, &parsed, cfg, msg)
	}
}

func SendTo(dest string, parsed *lib.ParsedMessage, cfg *lib.Config, msg []byte) {
	// enumerate possible mx IPs
	hosts := lib.FindServers(dest, cfg)

	// open connection
	conn, hostname := lib.DialFromList(hosts, cfg)
	if err := conn.Hello(parsed.SourceDomain); err != nil {
		log.Fatal(err)
	}

	// try ssl upgrade
	lib.StartTLS(conn, hostname, cfg)

	// send email
	if err := conn.Mail(parsed.Sender); err != nil {
		log.Fatal(err)
	}

	for _, rcpt := range parsed.Rcpt[dest] {
		if err := conn.Rcpt(rcpt); err != nil {
			log.Fatal(err)
		}
	}

	// Send the email body.
	wc, err := conn.Data()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := io.Copy(wc, bytes.NewReader(msg)); err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Send the QUIT command and close the connection.
	err = conn.Quit()
	if err != nil {
		log.Fatal(err)
	}
}
