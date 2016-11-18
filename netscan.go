package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type scan struct {
	lport   int
	rport   int
	laddr   net.IP
	raddr   net.IP
	target  string
	ifName  string
	network string
	forceV4 bool
	forceV6 bool
	ip      gopacket.NetworkLayer
}

func NewPortScan(target string) *scan {
	var s scan
	s.forceV6 = false
	s.setIP(target)
	return &s
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	if r := strings.Index(ip.String(), ":"); r != -1 {
		return true
	}
	return false
}

func (s *scan) setIP(target string) error {
	ips, err := net.LookupIP(target)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if isIPv4(ip) && !s.forceV6 {
			s.raddr = ip
			s.network = "ip4"
			break
		} else if isIPv6(ip) && !s.forceV4 {
			s.raddr = ip
			s.network = "ip6"
			break
		}
	}
	return nil
}

func (s *scan) setProto(proto string) error {
	var netProto = fmt.Sprintf("%s:%s", s.network, proto)

	switch netProto {
	case "ip4:tcp":
		s.ip = &layers.IPv4{
			SrcIP:    s.laddr,
			DstIP:    s.raddr,
			Protocol: layers.IPProtocolTCP,
		}
	case "ip4:udp":
		s.ip = &layers.IPv4{
			SrcIP:    s.laddr,
			DstIP:    s.raddr,
			Protocol: layers.IPProtocolUDP,
		}
	case "ip6:tcp":
		s.ip = &layers.IPv6{
			SrcIP:      s.laddr,
			DstIP:      s.raddr,
			NextHeader: layers.IPProtocolTCP,
		}
	case "ip6:udp":
		s.ip = &layers.IPv6{
			SrcIP:      s.laddr,
			DstIP:      s.raddr,
			NextHeader: layers.IPProtocolUDP,
		}

	}

	return nil
}

func (s *scan) packetDataTCP(rport int) (error, []byte) {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(s.lport),
		DstPort: layers.TCPPort(rport),
		Seq:     1,
		SYN:     true,
		Window:  15000,
	}

	tcp.SetNetworkLayerForChecksum(s.ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return err, []byte{}
	}

	return nil, buf.Bytes()
}

func (s *scan) packetDataUDP(rport int) (error, []byte) {
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(s.lport),
		DstPort: layers.UDPPort(rport),
	}

	udp.SetNetworkLayerForChecksum(s.ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, udp); err != nil {
		return err, []byte{}
	}

	return nil, buf.Bytes()
}

func (s *scan) sendTCPSYN() error {

	return nil
}

func (s *scan) setLocalNet() error {
	conn, err := net.Dial("udp", net.JoinHostPort(s.raddr.String(), "80"))
	if err != nil {
		return err
	}
	defer conn.Close()

	if lAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		s.laddr = lAddr.IP
		s.lport = lAddr.Port
	} else {
		return fmt.Errorf("can not find local address/port")
	}

	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.String() == s.laddr.String() {
				s.ifName = i.Name
				break
			}
		}
	}

	return nil
}

func (s *scan) pCapture(ctx context.Context) {
	var (
		tcp     *layers.TCP
		udp     *layers.UDP
		timeout = 100 * time.Nanosecond
		ok      bool
	)
	handle, err := pcap.OpenLive(s.ifName, 6*1024, false, timeout)
	if err != nil {
		println(err.Error())
		return
	}
	defer handle.Close()

	filter := "(tcp or udp) and src host " + s.raddr.String()
	if err := handle.SetBPFFilter(filter); err != nil {
		println(err.Error())
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case packet := <-packetSource.Packets():
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				if tcp, ok = tcpLayer.(*layers.TCP); !ok {
					continue
				}
				if tcp.SYN && tcp.ACK {
					fmt.Printf("TCP %+v\n", tcp.SrcPort)
				}
				continue
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				if udp, ok = udpLayer.(*layers.UDP); !ok {
					continue
				}
				fmt.Printf("UDP %+v\n", udp.SrcPort)
				continue
			}

		}
	}
}

func main() {
	var (
		buf    []byte
		err    error
		target = os.Args[1]
	)

	ctx, cancel := context.WithCancel(context.Background())

	s := NewPortScan(os.Args[1])
	if err = s.setLocalNet(); err != nil {
		println(err.Error())
	}
	if err = s.setProto("tcp"); err != nil {
		println(err.Error())
	}
	fmt.Printf("scanning %s (%s) port 1-500\n", target, s.raddr.String())
	go func() {
		conn, err := net.ListenPacket(s.network+":tcp", "0.0.0.0")
		if err != nil {
			println(err.Error())
		}
		for i := 1; i <= 500; i++ {
			if err, buf = s.packetDataTCP(i); err != nil {
				println(err.Error())
			}
			if _, err := conn.WriteTo(buf, &net.IPAddr{IP: s.raddr}); err != nil {
				println(err.Error())
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(2 * time.Second)
		cancel()
	}()

	s.pCapture(ctx)
}
