package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/flashmob/go-guerrilla"
	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/log"
	"github.com/flashmob/go-guerrilla/mail"

	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/lib"
)

const (
	defaultPidFile = "/var/run/gosendmailrelay.pid"
)

var (
	signalChannel = make(chan os.Signal, 1)
	d             guerrilla.Daemon

	mainlog log.Logger
)

func sigHandler() {
	// handle SIGHUP for reloading the configuration while running
	signal.Notify(signalChannel,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT,
		syscall.SIGKILL,
		syscall.SIGUSR1,
	)
	// Keep the daemon busy by waiting for signals to come
	for sig := range signalChannel {
		if sig == syscall.SIGHUP {
			viper.ReadInConfig()
			cf := viper.GetViper().ConfigFileUsed()
			d.ReloadConfigFile(cf)
		} else if sig == syscall.SIGUSR1 {
			d.ReopenLogs()
		} else if sig == syscall.SIGTERM || sig == syscall.SIGQUIT || sig == syscall.SIGINT {
			d.Shutdown()
			return
		} else {
			return
		}
	}
}

func init() {
	// log to stderr on startup
	var err error
	mainlog, err = log.GetLogger(log.OutputStderr.String(), log.InfoLevel.String())
	if err != nil {
		mainlog.WithError(err).Errorf("Failed creating a logger to %s", log.OutputStderr)
	}
}

// Relay is a go-guerrilla processor that forwards on inbound SMTP messages.
// Designed for a satellite host, where messages from internal VMs / machines
// should be forwarded out to an external collector / MTA
func main() {
	// get config
	viper.AddConfigPath("$HOME/.gosendmailrelay")
	viper.AddConfigPath(".")
	viper.SetDefault("tls", true)
	viper.SetDefault("selfsigned", false)
	viper.SetDefault("recipients", "")
	viper.SetEnvPrefix("gosendmail")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		mainlog.Fatal(err)
	}

	// start up the server.
	d = guerrilla.Daemon{Logger: mainlog}
	d.AddProcessor("Relay", Processor)

	cf := viper.GetViper().ConfigFileUsed()
	if _, err := d.LoadConfig(cf); err != nil {
		mainlog.Fatal(err)
	}
	if err != nil {
		mainlog.WithError(err).Fatal("Error while reading config")
	}
	// Check that max clients is not greater than system open file limit.
	fileLimit := getFileLimit()
	if fileLimit > 0 {
		maxClients := 0
		for _, s := range d.Config.Servers {
			maxClients += s.MaxClients
		}
		if maxClients > fileLimit {
			mainlog.Fatalf("Combined max clients for all servers (%d) is greater than open file limit (%d). "+
				"Please increase your open file limit or decrease max clients.", maxClients, fileLimit)
		}
	}

	err = d.Start()
	if err != nil {
		mainlog.WithError(err).Error("Error(s) when starting server(s)")
		os.Exit(1)
	}

	sigHandler()
}

// Processor allows the 'relay' option for guerrilla
var Processor = func() backends.Decorator {
	return func(c backends.Processor) backends.Processor {
		// The function will be called on each email transaction.
		// On success, it forwards to the next step in the processor call-stack,
		// or returns with an error if failed
		return backends.ProcessWith(func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
			if task == backends.TaskSaveMail {
				handler(e.NewReader())
				return c.Process(e, task)
			}
			return c.Process(e, task)
		})
	}
}

func handler(rawMsg io.Reader) {
	// get mail as input
	msg := lib.ReadMessage(rawMsg)

	// Parse msg
	parsed := lib.ParseMessage(&msg)

	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		mainlog.Fatalf("Fatal: No configuration for sender %s\n", parsed.SourceDomain)
	}
	if cfg.DkimKeyCmd != "" {
		if err := lib.SignMessage(parsed, cfg); err != nil {
			mainlog.Fatalf("Fatal: failed to sign %s\n", err)
		}
	}

	rcptOverride := viper.GetString("recipients")
	if rcptOverride != "" {
		mainlog.Printf("Over-riding recipients to %s", rcptOverride)
		parsed.SetRecipients(rcptOverride)
	}

	for _, dest := range parsed.DestDomain {
		mainlog.Printf("sending: connecting to %s\n", dest)
		SendTo(dest, &parsed, cfg, msg, viper.GetBool("tls"), viper.GetBool("selfsigned"))
	}
	mainlog.Printf("sending: finished\n")
}

// SendTo sends a parsed message
func SendTo(dest string, parsed *lib.ParsedMessage, cfg *lib.Config, msg []byte, tls bool, selfSigned bool) {
	// enumerate possible mx IPs
	hosts := lib.FindServers(dest)

	// open connection
	conn, hostname := lib.DialFromList(hosts, cfg)
	if err := conn.Hello(parsed.SourceDomain); err != nil {
		mainlog.Fatalf("Fatal: negotiating hello with %s: %v", hostname, err)
	}

	// try ssl upgrade
	if tls {
		if err := lib.StartTLS(conn, hostname, cfg, selfSigned); err != nil {
			mainlog.Fatalf("Fatal: negotiating starttls with %s: %v", hostname, err)
		}
	}

	// send email
	if err := conn.Mail(parsed.Sender); err != nil {
		mainlog.Fatalf("Fatal: setting mailfrom: %v\n", err)
	}

	rcpts := ""
	for _, rcpt := range parsed.Rcpt[dest] {
		if err := conn.Rcpt(rcpt); err != nil {
			mainlog.Fatalf("Fatal: setting rcpt %s: %v\n", rcpt, err)
		}
		if rcpts != "" {
			rcpts = rcpts + ", "
		}
		rcpts = rcpts + rcpt
	}

	// Send the email body.
	wc, err := conn.Data()
	if err != nil {
		mainlog.Fatalf("Fatal: sending data: %v\n", err)
	}

	if _, err := io.Copy(wc, bytes.NewReader(msg)); err != nil {
		mainlog.Fatalf("Fatal: copying bytes of body: %v\n", err)
	}
	err = wc.Close()
	if err != nil {
		mainlog.Fatalf("Fatal: concluding data: %v\n", err)
	}

	mainlog.Printf("Delivered: %s\n", rcpts)

	// Send the QUIT command and close the connection.
	conn.Quit()
}

func getFileLimit() int {
	cmd := exec.Command("ulimit", "-n")
	out, err := cmd.Output()
	if err != nil {
		return -1
	}
	limit, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return -1
	}
	return limit
}
