package lib

import (
	"strings"
)

// InterpretLog matches the output of a `sendmail` command
// for a given ParsedMessage. Output lines indicating the
// message was delivered are used to remove remaining recipients
// where redelivery is needed.
func InterpretLog(l string, parsed *ParsedMessage) {
	lines := strings.Split(l, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Fatal") {
			return
		} else if strings.HasPrefix(line, "Info") {
			continue
		} else if strings.HasPrefix(line, "Delivered:") {
			// remove rcpts. from parsed.
			rcpts := line[10:]
			parsed.RemoveRecipients(rcpts)
		}
	}
}
