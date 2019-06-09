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
	viper.SetDefault("tls", true)
	viper.SetDefault("selfsigned", false)
	viper.SetEnvPrefix("gosendmail")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	// get mail as input
	msg := lib.ReadMessage(os.Stdin)

	// Parse msg
	parsed := lib.ParseMessage(&msg)

	// remove bcc
	//lib.RemoveHeader(&msg, "BCC")

	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		log.Fatalf("No configuration for sender %s", parsed.SourceDomain)
	}

	for _, dest := range parsed.DestDomain {
		log.Printf("Mail for %s:", dest)
		SendTo(dest, &parsed, cfg, msg, viper.GetBool("tls"), viper.GetBool("selfsigned"))
		log.Printf(" Sent.\n")
	}
}

func SendTo(dest string, parsed *lib.ParsedMessage, cfg *lib.Config, msg []byte, tls bool, selfsigned bool) {
	// enumerate possible mx IPs
	hosts := lib.FindServers(dest, cfg)

	// open connection
	conn, hostname := lib.DialFromList(hosts, cfg)
	if err := conn.Hello(parsed.SourceDomain); err != nil {
		log.Fatalf("Errored @hello: %v", err)
	}

	// try ssl upgrade
	if tls {
		if err := lib.StartTLS(conn, hostname, cfg, selfsigned); err != nil {
			log.Fatalf("Errored @starttls: %v", err)
		}
	}

	// send email
	if err := conn.Mail(parsed.Sender); err != nil {
		log.Fatalf("Errored @mailfrom: %v", err)
	}

	for _, rcpt := range parsed.Rcpt[dest] {
		if err := conn.Rcpt(rcpt); err != nil {
			log.Fatalf("Errored @rcptto: %v", err)
		}
	}

	// Send the email body.
	wc, err := conn.Data()
	if err != nil {
		log.Fatalf("Errored @data: %v", err)
	}

	if _, err := io.Copy(wc, bytes.NewReader(msg)); err != nil {
		log.Fatalf("Errored sending: %v", err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatalf("Errored closing send: %v", err)
	}

	// Send the QUIT command and close the connection.
	err = conn.Quit()
	if err != nil {
		log.Fatalf("Errored @quit: %v", err)
	}
}
