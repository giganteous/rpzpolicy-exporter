package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	pb "github.com/giganteous/rpzpolicy-exporter/dnsmessage"
	"github.com/golang/protobuf/proto"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	pbAddress     = flag.String("pb.listen-address", ":4242", "Address on which to listen for PBDNSMessages")
	listenAddress = flag.String("web.listen-address", ":9142", "Address on which to expose metrics and web interface.")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	MaxPrefixLength uint16 = 0xffff

	appliedPolicy = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pdns_protobuf",
			Subsystem: "rpz",
			Name:      "applied_policy_total",
			Help:      "Number of packets applied in each received policyName",
		},
		[]string{"policy", "resolver"},
	)
)

func qtype(t uint32) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	default:
		return strconv.FormatUint(uint64(t), 10)
	}
}

func main() {
	prometheus.MustRegister(appliedPolicy)
	flag.Parse()

	c := make(chan *pb.PBDNSMessage)

	// sink
	go func() {
		for {
			m := <-c
			if t := m.GetType(); t == pb.PBDNSMessage_DNSResponseType {
				from := m.GetFrom()
				if from == nil {
					continue
				}
				serverid := net.IP(from).String() // identity of recursor
				r := m.GetResponse()

				policy := r.GetAppliedPolicy()
				if policy == "" {
					policy = "clean" // no rpz policy applied
				} else {
					printQuery(m)
				}

				appliedPolicy.WithLabelValues(policy, serverid).Inc()
			}
		}
	}()

	// listen for protobuf
	go func() {
		ln, err := net.Listen("tcp", *pbAddress)
		if err != nil {
			log.Fatal("Cannot listen: %s", err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("Error accepting: %s", err)
				continue
			}
			go handleConnection(conn, c)
		}
	}()

	// listen for prometheus scrapes
	handler := prometheus.Handler()
	http.Handle(*metricsPath, handler)
	log.Println("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

// Reads the prefix from the connection
func readLengthPrefix(conn io.Reader) (val uint16, err error) {
	err = binary.Read(conn, binary.BigEndian, &val)
	if err != nil {
		return 0, err
	}
	return
}

func handleConnection(conn net.Conn, c chan *pb.PBDNSMessage) {
	log.Print("Protobuf Connection established from ", conn.RemoteAddr())
	defer conn.Close()
	data := make([]byte, MaxPrefixLength)

	for {
		pblen, err := readLengthPrefix(conn)
		if err != nil {
			log.Printf("Cannot read pb length: %s", err)
			continue
		} else if pblen > MaxPrefixLength {
			log.Printf("Cannot accept protobuf packets > %d: %d", pblen, MaxPrefixLength)
			continue
		}

		if _, err := io.ReadFull(conn, data[0:pblen]); err == io.EOF {
			log.Print("Unexpected EOF on protobuf stream")
			continue
		} else if err != nil {
			log.Printf("Cannot read from protobuf stream: %s", err)
			continue
		}

		message := &pb.PBDNSMessage{}
		err = proto.Unmarshal(data[0:pblen], message)
		if err != nil {
			log.Printf("Cannot unmarshal packet: %s", err)
			continue
		}
		c <- message
	}
}

// prints verbose output on stdout
func printQuery(m *pb.PBDNSMessage) {
	var ipfromstr = "N/A"
	if from := m.GetFrom(); from != nil {
		ipfromstr = net.IP(from).String()
	}
	if sub := m.GetOriginalRequestorSubnet(); sub != nil {
		ipfromstr = net.IP(sub).String() + " [" + ipfromstr + "]"
	}

	r := m.GetResponse()
	policystr := r.GetAppliedPolicy()

	q := m.GetQuestion()
	if q == nil {
		return
	}
	qclass := q.GetQClass()
	if qclass == 0 {
		qclass = 1
	}

	fmt.Printf("client %s: query: %s %s [p=%s]\n",
		ipfromstr,
		q.GetQName(),
		qtype(q.GetQType()),
		policystr,
	)
}
