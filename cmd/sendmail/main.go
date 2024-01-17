package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
)

// Sendmail negotiates a series of SMTP connections with remote servers
// to deliver a message sent on stdin. It is stateless.
//
// The output (log.Fatalf / log.Printf) from this process are parsed
// by lib/log.go in the signmail commanding process.
// The expected convention is that lines follow one of three formats:
// * "Info: " - ignored
// * "Delivered: <recipients>" - indication of successful delivery
// * "Fatal: " - indication that an error occured
func main() {
	// get config
	viper.AddConfigPath("$HOME/.gosendmail")
	viper.AddConfigPath(".")
	viper.SetDefault("tls", true)
	viper.SetDefault("selfsigned", false)
	viper.SetDefault("recipients", "")
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

	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		log.Fatalf("Fatal: No configuration for sender %s\n", parsed.SourceDomain)
	}

	rcptOverride := viper.GetString("recipients")
	if rcptOverride != "" {
		parsed.SetRecipients(rcptOverride)
	}

	for _, dest := range parsed.DestDomain {
		log.Printf("Info: connecting to %s\n", dest)
		SendTo(dest, &parsed, cfg, msg, viper.GetBool("tls"), viper.GetBool("selfsigned"))
	}
	log.Printf("Info: finished\n")
}

func SendTo(dest string, parsed *lib.ParsedMessage, cfg *lib.Config, msg []byte, tls bool, selfSigned bool) {
	// enumerate possible mx IPs
	hosts := lib.FindServers(dest)

	// open connection
	conn, hostname := lib.DialFromList(hosts, cfg)
	helloSrc := parsed.SourceDomain
	if len(cfg.SourceHost) > 0 {
		helloSrc = cfg.SourceHost
	}
	if err := conn.Hello(helloSrc); err != nil {
		log.Fatalf("Fatal: negotiating hello with %s: %v", hostname, err)
	}

	// try ssl upgrade
	if tls {
		if err := lib.StartTLS(conn, hostname, cfg, selfSigned); err != nil {
			log.Fatalf("Fatal: negotiating starttls with %s: %v", hostname, err)
		}
	}

	// send email
	if err := conn.Mail(parsed.Sender); err != nil {
		log.Fatalf("Fatal: setting mailfrom: %v\n", err)
	}

	rcpts := ""
	for _, rcpt := range parsed.Rcpt[dest] {
		if err := conn.Rcpt(rcpt); err != nil {
			log.Fatalf("Fatal: setting rcpt %s: %v\n", rcpt, err)
		}
		if rcpts != "" {
			rcpts = rcpts + ", "
		}
		rcpts = rcpts + rcpt
	}

	// Send the email body.
	wc, err := conn.Data()
	if err != nil {
		log.Fatalf("Fatal: sending data: %v\n", err)
	}

	if _, err := io.Copy(wc, bytes.NewReader(msg)); err != nil {
		log.Fatalf("Fatal: copying bytes of body: %v\n", err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatalf("Fatal: concluding data: %v\n", err)
	}

	log.Printf("Delivered: %s\n", rcpts)

	// Send the QUIT command and close the connection.
	conn.Quit()
}
