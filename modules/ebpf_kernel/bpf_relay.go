package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type EventDetail struct {
	PID   int    `json:"pid"`
	UID   int    `json:"uid"`
	FName string `json:"fname"`
}

type Event struct {
	Device     string      `json:"device"`
	App        string      `json:"app"`
	Kind       string      `json:"kind"`
	Detail     EventDetail `json:"detail"`
	AppVersion string      `json:"app_version"`
}

func main() {
	u := url.URL{Scheme: "ws", Host: "127.0.0.1:8787", Path: "/ws/ingest"}
	
	var c *websocket.Conn
	var err error
	for {
		c, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
		if err == nil {
			break
		}
		log.Printf("wait for driftnetd...")
		time.Sleep(1 * time.Second)
	}
	defer c.Close()

	log.Printf("Connected to driftnetd")

	// PID: 123 | UID: 0 | COMM: test | FNAME: /etc/passwd
	re := regexp.MustCompile(`PID:\s*(\d+)\s*\|\s*UID:\s*(\d+)\s*\|\s*COMM:\s*(.*?)\s*\|\s*FNAME:\s*(.*)`)
	
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 5 {
			pid, _ := strconv.Atoi(matches[1])
			uid, _ := strconv.Atoi(matches[2])
			comm := strings.TrimSpace(matches[3])
			fname := strings.TrimSpace(matches[4])
			
			ev := Event{
				Device:     "Android-Ring0",
				App:        comm,
				Kind:       "sys_openat",
				Detail:     EventDetail{PID: pid, UID: uid, FName: fname},
				AppVersion: "1.0",
			}
			
			payload, _ := json.Marshal(ev)
			c.WriteMessage(websocket.TextMessage, payload)
		}
	}
}
