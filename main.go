package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	// "go/types"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"net/http"

	// "golang.org/x/tools/go/packages"

	// "bytes"
	// "flag"
	// "time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	SO_ATTACH_BPF = 0x32
)

type ipv4FlowKey struct {
	saddr uint32
	daddr uint32
	sport uint16
	dport uint16
}

type flowCount struct {
	count64 uint64
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf main.c

func processDNSRecords(records []layers.DNSResourceRecord, m *map[string]string) {
	for _, answer := range records {
		// fmt.Printf("%T\n", answer)
		if (answer.Type) != layers.DNSTypeA {
			continue
		}

		// fmt.Println(string(answer.Name))
		// fmt.Println("  Class:", answer.Class)

		bytes := answer.Data
		resolvedIP := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(bytes)), "."), "[]")

		var mutex = sync.RWMutex{}
		mutex.Lock()
		(*m)[resolvedIP] = string(answer.Name)
		mutex.Unlock()
	}
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	interfaceIndex, err := strconv.Atoi(os.Getenv("SOCK_INTERFACE_INDEX"))
	if err != nil {
		panic("required env var - SOCK_INTERFACE_INDEX")
	}

	sock, err := openRawSock(interfaceIndex)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	programFD := objs.bpfPrograms.SocketHandler.FD()

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, programFD); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on eth index: %d\n", interfaceIndex)

	buffer := make([]byte, 1024)

	ipToResolvedAddress := make(map[string]string)

	go func() {
		for {
			n, err := syscall.Read(sock, buffer)
			if err == nil {
				// Process the received packet data
				packetData := buffer[:n]
				// fmt.Print(packetData)

				packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
				// // Iterate over all layers, printing out each layer type
				// for _, layer := range packet.Layers() {
				// 	fmt.Println("PACKET LAYER:", layer.LayerType())
				// }

				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					processDNSRecords(dns.Answers, &ipToResolvedAddress)
				}
			} else {
				time.Sleep(420 * time.Millisecond)
			}

			c := make(chan os.Signal)
			signal.Notify(c, os.Interrupt, syscall.SIGINT)
			go func() {
				<-c
				os.Exit(1)
			}()
		}
	}()

	listenPort := os.Getenv("LISTEN_PORT")
	listen := "0.0.0.0:" + listenPort

	http.HandleFunc("/stat", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, ipToResolvedAddress)
	})

	fmt.Printf("Server listening on port %s...\n", listen)
	err2 := http.ListenAndServe(listen, nil) // Start the server
	if err2 != nil {
		panic(err2)
	}
}

func handler(w http.ResponseWriter, r *http.Request, ipToResolvedAddress map[string]string) {
	ipv4_count, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ipv4_count", nil)

	// ipv4_count, err := ebpf.LoadPinnedMap("/sys/fs/bpf/ipv4_count", &ebpf.LoadPinOptions{
	// 	ReadOnly: true,
	// })

	if err != nil {
		panic("cant load map")
	}

	// fmt.Fprintln("Map Info: ")
	// fmt.Fprintln(ipv4_count.Info())

	iter := ipv4_count.Iterate()
	key := 0
	value := 0
	for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
		flowKey := *(*ipv4FlowKey)(unsafe.Pointer(&key))
		flowCountVal := *(*flowCount)(unsafe.Pointer(&value))

		daddrstring := fmt.Sprintf("%s:%d", (intToIP(ntohs(flowKey.daddr))).String(), flowKey.dport)
		val, ok := ipToResolvedAddress[daddrstring]
		if ok {
			// fmt.Fprintln(w, val, "-->", daddrstring, ":", flowKey.dport)
			ret := fmt.Sprintf("%-50s %-20s %d", val, daddrstring, flowCountVal.count64)
			fmt.Fprintln(w, ret)
		} else {
			ret := fmt.Sprintf("%-50s %-20s %d", daddrstring, daddrstring, flowCountVal.count64)
			fmt.Fprintln(w, ret)
		}
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func ntohs(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
