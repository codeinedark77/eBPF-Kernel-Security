package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// data_t matches the C struct in our eBPF program
type Event struct {
	PID   uint32
	UID   uint32
	Comm  [16]byte
	FName [256]byte
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <path-to-bpf_probe.o>", os.Args[0])
	}
	objPath := os.Args[1]

	// Load pre-compiled programs and maps into the kernel.
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("Failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["bpf_prog1"]
	if prog == nil {
		log.Fatal("Failed to find bpf_prog1")
	}

	progConnect := coll.Programs["bpf_prog_connect"]
	if progConnect == nil {
		log.Fatal("Failed to find bpf_prog_connect")
	}

	// Open a Kprobe at the entry point of the kernel function and attach the pre-compiled program.
	kp, err := link.Kprobe("__arm64_sys_openat", prog, nil)
	if err != nil {
		log.Fatalf("Opening kprobe openat: %s", err)
	}
	defer kp.Close()

	kpConnect, err := link.Kprobe("__arm64_sys_connect", progConnect, nil)
	if err != nil {
		log.Fatalf("Opening kprobe connect: %s", err)
	}
	defer kpConnect.Close()

	log.Println("Successfully injected eBPF probes into __arm64_sys_openat and __arm64_sys_connect.")
	log.Println("Waiting for events...")

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		log.Println("Received signal, exiting...")
		rd.Close()
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Parsing perf event: %s", err)
			continue
		}

		// Convert C strings (null-terminated byte arrays) to Go strings
		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fname := string(bytes.TrimRight(event.FName[:], "\x00"))

		fmt.Printf("PID: %d | UID: %d | COMM: %-15s | FNAME: %s\n", event.PID, event.UID, comm, fname)
	}
}
