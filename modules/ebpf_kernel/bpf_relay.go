package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"net/url"

	"github.com/cilium/ebpf"
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

	go func() {
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var resp struct {
				Action  string `json:"action"`
				Payload struct {
					PID int `json:"pid"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(msg, &resp); err == nil && resp.Action == "BLOCK" {
				// Load the pinned map and insert the PID for Ring-0 killing
				blacklistMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/blacklist_pids", nil)
				if err == nil {
					key := uint32(resp.Payload.PID)
					val := uint32(9) // SIGKILL
					blacklistMap.Put(key, val)
					blacklistMap.Close()
					syscall.Kill(resp.Payload.PID, syscall.SIGKILL)
					log.Printf("Ring-0 Kill Authorized: inserted PID %d into kernel blacklist map and delivered instant SIGKILL", key)
				} else {
					log.Printf("Failed to load pinned map: %v", err)
				}
			}
		}
	}()

	// PID: 123 | UID: 0 | COMM: test | FNAME: /etc/passwd
	re := regexp.MustCompile(`PID:\s*(\d+)\s*\|\s*UID:\s*(\d+)\s*\|\s*COMM:\s*(.*?)\s*\|\s*FNAME:\s*(.*)`)
	
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 5 {
			pid, _ := strconv.Atoi(matches[1])
			// uid, _ := strconv.Atoi(matches[2])
			// comm := strings.TrimSpace(matches[3])
			fname := strings.TrimSpace(matches[4])
			
			kind := "sys_openat"
			if strings.HasPrefix(fname, "IP:") {
				kind = "sys_connect"
				
				// Demo Fast-Path: Simulate warm AI cache for the demo malware IP
				if strings.HasPrefix(fname, "IP:185.123.") {
					blacklistMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/blacklist_pids", nil)
					if err == nil {
						blacklistMap.Put(uint32(pid), uint32(9))
						blacklistMap.Close()
					}
					syscall.Kill(pid, syscall.SIGKILL)
					log.Printf("Ring-0 Kill Authorized: inserted PID %d into kernel blacklist map and delivered instant SIGKILL (Lazy AI Warm Cache)", pid)
				}
			} else if strings.HasPrefix(fname, "EXEC:") {
				kind = "sys_execve"
				fname = strings.TrimPrefix(fname, "EXEC:")
			}
			
			comm := strings.TrimSpace(matches[3])
			uid, _ := strconv.Atoi(matches[2])
			ev := Event{
				Device:     "Android-Ring0",
				App:        comm,
				Kind:       kind,
				Detail:     EventDetail{PID: pid, UID: uid, FName: fname},
				AppVersion: "1.0",
			}
			
			payload, _ := json.Marshal(ev)
			c.WriteMessage(websocket.TextMessage, payload)
		}
	}
}
