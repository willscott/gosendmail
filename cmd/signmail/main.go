package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/willscott/gosendmail/cache"
	"github.com/willscott/gosendmail/lib"
)

func init() {
	flag.CommandLine.BoolP("queue", "s", false, "Store message to queue if not sent successfully")
	flag.CommandLine.BoolP("resume", "r", false, "Attempt delivery of queued messages")
	flag.CommandLine.StringP("from", "f", "", "Use explicit sender separate from the address parsed in the msg")
}

func main() {
	// get config
	viper.AddConfigPath("$HOME/.gosendmail")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}
	viper.SetEnvPrefix("gosendmail")
	viper.AutomaticEnv()
	if flag.CommandLine.Parse(os.Args[1:]) != nil {
		flag.CommandLine.Usage()
		return
	}
	if err := viper.BindPFlags(flag.CommandLine); err != nil {
		log.Fatal(err)
	}
	explicitFrom := viper.GetString("from")
	fmt.Printf("resume is: %t\n", viper.GetBool("resume"))

	if viper.GetBool("resume") {
		mc, err := cache.LoadMessageCache()
		if err != nil {
			log.Fatalf("Failed to load queue: %v", err)
		}
		newMC := new(cache.MessageCache)
		for _, parsed := range mc {
			err = trySend(parsed)
			if err != nil {
				*newMC = append(*newMC, parsed)
				log.Printf("Delivery failure: %v", err)
			} else {
				if err = parsed.Unlink(); err != nil {
					log.Printf("Failed to remove cached message: %v", err)
				}
			}
		}
		err = newMC.Save()
		if err != nil {
			log.Fatalf("Failed to save queue: %v", err)
		}
	} else {
		// get mail as input
		msg := lib.ReadMessage(os.Stdin)

		// Parse msg
		parsed := lib.ParseMessage(&msg)
		if len(explicitFrom) > 0 {
			if err = parsed.SetSender(explicitFrom); err != nil {
				log.Fatalf("Failed to prepare message: %v", err)
			}
		}
		if err = prepareMessage(parsed); err != nil {
			log.Fatalf("Failed to prepare message: %v", err)
		}

		err := trySend(parsed)
		if err != nil {
			if viper.GetBool("queue") {
				log.Printf("Failed to send message: %v", err)
				mc, err := cache.LoadMessageCache()
				if err != nil {
					log.Fatalf("Failed to load cache: %v", err)
				}
				mc = append(mc, parsed)
				if err = mc.Save(); err != nil {
					log.Fatalf("Failed to save cache: %v", err)
				}
			} else {
				log.Fatalf("Failed to send message: %v", err)
			}
		}
	}
}

func prepareMessage(parsed lib.ParsedMessage) error {
	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		return fmt.Errorf("No configuration for sender %s", parsed.SourceDomain)
	}

	if err := lib.SanitizeMessage(parsed, cfg); err != nil {
		return err
	}

	if cfg.DkimKeyCmd != "" {
		if err := lib.SignMessage(parsed, cfg); err != nil {
			return err
		}
	}
	return nil
}

func trySend(parsed lib.ParsedMessage) error {
	cfg := lib.GetConfig(parsed.SourceDomain)
	if cfg == nil {
		return fmt.Errorf("No configuration for sender %s", parsed.SourceDomain)
	}

	// send to remote server.
	keycmd := strings.Split(cfg.SendCommand, " ")
	cmd := exec.Command(keycmd[0], keycmd[1:]...)
	cmd.Env = append(os.Environ(),
		"GOSENDMAIL_RECIPIENTS="+parsed.Recipients())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		io.Copy(stdin, bytes.NewReader(*parsed.Bytes))
	}()

	l, err := cmd.CombinedOutput()
	lib.InterpretLog(string(l), &parsed)
	if err != nil {
		return fmt.Errorf("%s: %v", l, err)
	}
	return nil
}
