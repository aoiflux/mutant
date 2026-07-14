package builtin

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"mutant/object"
)

func TestNetSynScanFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start TCP listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := int64(ln.Addr().(*net.TCPAddr).Port)
	result := NetSynScan(stringObj("127.0.0.1"), intObj(port), intObj(port), intObj(200))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash := nfMustHash(t, payload)
	openPortsObj := nfMustHashValue(t, hash, "open_ports")
	openPorts, ok := openPortsObj.(*object.Array)
	if !ok {
		t.Fatalf("open_ports is not ARRAY: %T", openPortsObj)
	}
	if len(openPorts.Elements) != 1 {
		t.Fatalf("expected one open port, got=%d", len(openPorts.Elements))
	}
	found, ok := openPorts.Elements[0].(*object.Integer)
	if !ok || found.Value != port {
		t.Fatalf("unexpected open port result")
	}
}

func TestNetUDPScanFindsResponsivePort(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP listener: %v", err)
	}
	defer packetConn.Close()

	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, readErr := packetConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = packetConn.WriteTo(buf[:n], addr)
		}
	}()

	port := int64(packetConn.LocalAddr().(*net.UDPAddr).Port)
	result := NetUDPScan(stringObj("127.0.0.1"), intObj(port), intObj(port), intObj(250))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash := nfMustHash(t, payload)
	respObj := nfMustHashValue(t, hash, "responsive_ports")
	respPorts, ok := respObj.(*object.Array)
	if !ok {
		t.Fatalf("responsive_ports is not ARRAY: %T", respObj)
	}
	if len(respPorts.Elements) != 1 {
		t.Fatalf("expected one responsive port, got=%d", len(respPorts.Elements))
	}
}

func TestNetBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start banner listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Write([]byte("SSH-2.0-Mutant\r\n"))
		_ = conn.Close()
	}()

	result := NetBanner(stringObj(ln.Addr().String()), intObj(300))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash := nfMustHash(t, payload)
	bannerObj := nfMustHashValue(t, hash, "banner")
	banner, ok := bannerObj.(*object.String)
	if !ok {
		t.Fatalf("banner is not STRING: %T", bannerObj)
	}
	if !strings.Contains(banner.Value, "SSH-2.0-Mutant") {
		t.Fatalf("unexpected banner: %q", banner.Value)
	}
}

func TestNetTLSFingerprint(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	result := NetTLSFingerprint(stringObj(u.Host), intObj(1000))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected tls fingerprint error: %s", errObj.Inspect())
	}
	hash := nfMustHash(t, payload)
	okObj := nfMustHashValue(t, hash, "ok")
	okBool, ok := okObj.(*object.Boolean)
	if !ok || !okBool.Value {
		t.Fatalf("expected tls fingerprint ok=true")
	}
	fpObj := nfMustHashValue(t, hash, "peer_cert_sha256")
	fp, ok := fpObj.(*object.String)
	if !ok || len(fp.Value) != 64 {
		t.Fatalf("unexpected fingerprint value")
	}
}

func TestNetDNSQueryLocalhost(t *testing.T) {
	result := NetDNSQuery(stringObj("localhost"), stringObj("A"))
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected dns error: %s", errObj.Inspect())
	}
	arr, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("dns payload type mismatch: %T", payload)
	}
	if len(arr.Elements) == 0 {
		t.Fatalf("expected at least one localhost A record")
	}
}

func TestNetFlowReconstruct(t *testing.T) {
	packets := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{
			"src":   stringObj("10.0.0.2"),
			"dst":   stringObj("10.0.0.5"),
			"sport": intObj(51500),
			"dport": intObj(443),
			"proto": stringObj("tcp"),
			"bytes": intObj(120),
		}),
		makeHashObject(map[string]object.Object{
			"src":   stringObj("10.0.0.5"),
			"dst":   stringObj("10.0.0.2"),
			"sport": intObj(443),
			"dport": intObj(51500),
			"proto": stringObj("tcp"),
			"bytes": intObj(80),
		}),
	}}

	result := NetFlowReconstruct(packets)
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected flow reconstruction error: %s", errObj.Inspect())
	}

	flows, ok := payload.(*object.Array)
	if !ok {
		t.Fatalf("flow payload type mismatch: %T", payload)
	}
	if len(flows.Elements) != 1 {
		t.Fatalf("expected one reconstructed flow, got=%d", len(flows.Elements))
	}
	flowHash, ok := flows.Elements[0].(*object.Hash)
	if !ok {
		t.Fatalf("flow entry type mismatch: %T", flows.Elements[0])
	}
	packetsCountObj := nfMustHashValue(t, flowHash, "packets")
	packetsCount, ok := packetsCountObj.(*object.Integer)
	if !ok || packetsCount.Value != 2 {
		t.Fatalf("unexpected packets count")
	}
	bytesObj := nfMustHashValue(t, flowHash, "bytes")
	bytesValue, ok := bytesObj.(*object.Integer)
	if !ok || bytesValue.Value != 200 {
		t.Fatalf("unexpected bytes count")
	}
}

func TestNetPCAPAnalyze(t *testing.T) {
	pcapPath := writePCAPFixture(t)

	payload, errObj := unwrapPair(t, NetPCAPAnalyze(stringObj(pcapPath)))
	if errObj != nil {
		t.Fatalf("unexpected pcap analyze error: %s", errObj.Inspect())
	}

	hash := nfMustHash(t, payload)
	packetCountObj := nfMustHashValue(t, hash, "packet_count")
	packetCount, ok := packetCountObj.(*object.Integer)
	if !ok || packetCount.Value != 2 {
		t.Fatalf("unexpected packet_count: %v", packetCountObj.Inspect())
	}

	tcpCountObj := nfMustHashValue(t, hash, "tcp_packets")
	tcpCount, ok := tcpCountObj.(*object.Integer)
	if !ok || tcpCount.Value != 1 {
		t.Fatalf("unexpected tcp_packets: %v", tcpCountObj.Inspect())
	}

	udpCountObj := nfMustHashValue(t, hash, "udp_packets")
	udpCount, ok := udpCountObj.(*object.Integer)
	if !ok || udpCount.Value != 1 {
		t.Fatalf("unexpected udp_packets: %v", udpCountObj.Inspect())
	}

	flowsObj := nfMustHashValue(t, hash, "flows")
	flows, ok := flowsObj.(*object.Array)
	if !ok {
		t.Fatalf("flows is not ARRAY: %T", flowsObj)
	}
	if len(flows.Elements) != 2 {
		t.Fatalf("expected two flows, got=%d", len(flows.Elements))
	}
}

func TestNetCaptureAndOSFingerprintUnsupported(t *testing.T) {
	_, errObj := unwrapPair(t, NetCaptureRaw())
	if errObj == nil || !strings.Contains(errObj.Message, "unsupported") {
		t.Fatalf("expected unsupported error from net_capture_raw")
	}

	_, errObj = unwrapPair(t, NetOSFingerprint(stringObj("127.0.0.1"), intObj(100)))
	if errObj == nil || !strings.Contains(errObj.Message, "unsupported") {
		t.Fatalf("expected unsupported error from net_os_fingerprint")
	}
}

func TestNetForensicsArgumentValidation(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "syn scan port range invalid",
			call: func() object.Object { return NetSynScan(stringObj("127.0.0.1"), intObj(100), intObj(10), intObj(100)) },
		},
		{
			name: "udp scan bad host type",
			call: func() object.Object { return NetUDPScan(intObj(1), intObj(1), intObj(2), intObj(100)) },
		},
		{
			name: "banner bad timeout type",
			call: func() object.Object { return NetBanner(stringObj("127.0.0.1:1"), stringObj("bad")) },
		},
		{
			name: "dns bad qtype",
			call: func() object.Object { return NetDNSQuery(stringObj("localhost"), stringObj("FOO")) },
		},
		{
			name: "flow bad packet shape",
			call: func() object.Object {
				return NetFlowReconstruct(&object.Array{Elements: []object.Object{stringObj("bad")}})
			},
		},
		{
			name: "pcap analyze bad arg type",
			call: func() object.Object { return NetPCAPAnalyze(intObj(1)) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, tt.call())
			if errObj == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func writePCAPFixture(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "sample.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap fixture: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	tcpBytes := serializePacketBytes(t,
		&layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("10.1.1.1").To4(), DstIP: net.ParseIP("10.1.1.2").To4()},
		&layers.TCP{SrcPort: 51500, DstPort: 443, SYN: true, Window: 64240},
		gopacket.Payload([]byte("hello-tcp")),
	)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0), Length: len(tcpBytes), CaptureLength: len(tcpBytes)}, tcpBytes); err != nil {
		t.Fatalf("write tcp packet: %v", err)
	}

	udpBytes := serializePacketBytes(t,
		&layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("10.2.2.1").To4(), DstIP: net.ParseIP("10.2.2.2").To4()},
		&layers.UDP{SrcPort: 53000, DstPort: 53},
		gopacket.Payload([]byte("hello-udp")),
	)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000001, 0), Length: len(udpBytes), CaptureLength: len(udpBytes)}, udpBytes); err != nil {
		t.Fatalf("write udp packet: %v", err)
	}

	return path
}

func serializePacketBytes(t *testing.T, layersToSerialize ...gopacket.SerializableLayer) []byte {
	t.Helper()

	for _, l := range layersToSerialize {
		switch p := l.(type) {
		case *layers.TCP:
			for _, inner := range layersToSerialize {
				if ip4, ok := inner.(*layers.IPv4); ok {
					_ = p.SetNetworkLayerForChecksum(ip4)
				}
			}
		case *layers.UDP:
			for _, inner := range layersToSerialize {
				if ip4, ok := inner.(*layers.IPv4); ok {
					_ = p.SetNetworkLayerForChecksum(ip4)
				}
			}
		}
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return bytes.Clone(buf.Bytes())
}

func nfMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	hash, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return hash
}

func nfMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}
