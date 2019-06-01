
package main

import (
	"bytes"
	"io"
	"log"
	"os"

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

	// enumerate possible mx IPs
	hosts := lib.FindServers(parsed.DestDomain, cfg)

	// open connection
	conn := lib.DialFromList(hosts, cfg)
	if err := conn.Hello(parsed.SourceDomain); err != nil {
		log.Fatal(err)
	}

	// try ssl upgrade
	lib.StartTLS(conn, cfg)

	// send email
	if err := conn.Mail(parsed.Sender); err != nil {
		log.Fatal(err)
	}
	if err := conn.Rcpt(parsed.Rcpt); err != nil {
		log.Fatal(err)
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

