package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/flashmob/go-guerrilla"
	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/log"
	"github.com/flashmob/go-guerrilla/mail"
	"github.com/kballard/go-shellquote"

	"github.com/3th1nk/cidr"
	"github.com/spf13/viper"
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
	viper.SetEnvPrefix("gosendmail")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		mainlog.Fatal(err)
	}

	// start up the server.
	d = guerrilla.Daemon{Logger: mainlog}
	d.AddProcessor("Relay", Processor)
	d.AddProcessor("Gate", Auth)

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

var Auth = func() backends.Decorator {
	return func(c backends.Processor) backends.Processor {
		allowedNetStr := viper.GetString("AllowedNetwork")
		allowNet := &cidr.CIDR{}
		if len(allowedNetStr) > 0 {
			var err error
			allowNet, err = cidr.Parse(allowedNetStr)
			if err != nil {
				mainlog.Fatalf("Fatal: failed to parse allowed networks %s\n", err)
				return nil
			}
		}

		return backends.ProcessWith(func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
			if task == backends.TaskValidateRcpt {
				remote := e.RemoteIP
				if !allowNet.Contains(remote) {
					mainlog.Infof("Rejecting message from %s\n", remote)
					return backends.NewResult(fmt.Sprintf("550 5.7.1 %s is not allowed to send mail", remote), 550), nil
				}
			}
			return c.Process(e, task)
		})
	}
}

// Processor allows the 'relay' option for guerrilla
var Processor = func() backends.Decorator {
	return func(c backends.Processor) backends.Processor {
		sc := viper.GetString("SendCommand")
		shq, err := shellquote.Split(sc)
		if err != nil {
			mainlog.Fatalf("Fatal: failed to parse send command %s\n", err)
			return nil
		}

		// The function will be called on each email transaction.
		// On success, it forwards to the next step in the processor call-stack,
		// or returns with an error if failed
		return backends.ProcessWith(func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
			if task == backends.TaskSaveMail {
				ctx, cncl := context.WithTimeout(context.Background(), 10*time.Second)
				defer cncl()
				child := exec.CommandContext(ctx, shq[0], shq[1:]...)

				child.Stdin = &e.Data
				dlp := e.RcptTo
				destList := ""
				for _, dest := range dlp {
					if destList != "" {
						destList = destList + ", " + dest.String()
					} else {
						destList = "" + dest.String()
					}
				}
				child.Env = []string{"GOSENDMAIL_FROM=" + e.MailFrom.String(), "GOSENDMAIL_RECIPIENTS=" + destList}
				out, err := child.Output()
				if err != nil {
					mainlog.WithError(fmt.Errorf("sendmail err %w: %s", err, out)).Errorf("Failed to send mail")
					return backends.NewResult("550 5.7.1 Failed to send mail", 550), nil
				}
				return backends.NewResult("250 2.0.0 OK: queued", 250), nil
			}
			return c.Process(e, task)
		})
	}
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
