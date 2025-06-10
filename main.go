package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "os/signal"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"


type event struct {
    Pid uint32
    Comm [16]byte
}

func main() {
    spec, err := ebpf.LoadCollectionSpec("gen/socktrace.bpf.o")
    if err != nil {
        log.Fatalf("Failed to load BPF object: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("failed to create collection: %v, err)
    }
    defer coll.Close()

    prog := coll.Programs["handle_connect"]
    if prog == nil {
        log.Fatal("program not found")
    }

    link, err := prog.AttachTracepoint("syscalls", "sys_enter_connect")
    if err != nil {
        log.Fatalf("failed to attach tracepoint: %v", err)
    }
    defer link.Close()

    rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
    if err != nil {
        log.Fatalf("failed to open perf reader: %v", err)
    }
    defer rd.Close()

    log.Println("Waiting for events... (press Ctrl+C to stop)")
    sig := make(chan os.Signal, 1)

    for {
        select {
            case <- sig:
                log.Println("Exiting")
                return
            default:
                record, err := rd.read()
                if err != nil {
                    log.Printf("reading from perf even reader: %v", err)
                    continue
                }
                if record.LostSamples != 0 {
                    log.Printf("lost %d samples", record.LostSamples)
                    continue
                }
                var e event
                if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
                    log.Printf("Failed to decode received data: %v", err)
                    continue
                }
                fmt.Printf("PID %d - COMM %s\n", e,Pid, bytes.Trim(e.Comm[:], "\x00"))
        }
    }
}
