package builtin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"mutant/object"
)

type netFlowSummary struct {
	src     string
	dst     string
	sport   int64
	dport   int64
	proto   string
	packets int64
	bytes   int64
}

func NetResolve(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `net_resolve` must be STRING, got %s", args[0].Type()))
	}
	addrs, err := net.LookupHost(host.Value)
	if err != nil {
		return resultAndError(nil, newError("net_resolve: %s", err.Error()))
	}
	elements := make([]object.Object, 0, len(addrs))
	for _, addr := range addrs {
		elements = append(elements, stringObj(addr))
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func NetDial(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_dial` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_dial` must be INTEGER, got %s", args[1].Type()))
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr.Value, time.Duration(timeoutMs.Value)*time.Millisecond)
	elapsed := time.Since(start).Milliseconds()

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else {
		conn.Close()
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":         boolObj(err == nil),
		"latency_ms": intObj(elapsed),
		"error":      stringObj(errMsg),
	}), nil)
}

func NetSynScan(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_syn_scan` must be STRING, got %s", args[0].Type()))
	}
	startPort, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_syn_scan` must be INTEGER, got %s", args[1].Type()))
	}
	endPort, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_syn_scan` must be INTEGER, got %s", args[2].Type()))
	}
	timeoutMs, ok := args[3].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `net_syn_scan` must be INTEGER, got %s", args[3].Type()))
	}
	if errObj := validatePortRange("net_syn_scan", startPort.Value, endPort.Value); errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	start := time.Now()
	openPorts := make([]object.Object, 0)
	for port := startPort.Value; port <= endPort.Value; port++ {
		addr := net.JoinHostPort(host.Value, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			openPorts = append(openPorts, intObj(port))
			_ = conn.Close()
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"host":        stringObj(host.Value),
		"start_port":  intObj(startPort.Value),
		"end_port":    intObj(endPort.Value),
		"scanned":     intObj(endPort.Value - startPort.Value + 1),
		"open_ports":  &object.Array{Elements: openPorts},
		"duration_ms": intObj(time.Since(start).Milliseconds()),
	}), nil)
}

func NetUDPScan(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}

	host, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_udp_scan` must be STRING, got %s", args[0].Type()))
	}
	startPort, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_udp_scan` must be INTEGER, got %s", args[1].Type()))
	}
	endPort, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `net_udp_scan` must be INTEGER, got %s", args[2].Type()))
	}
	timeoutMs, ok := args[3].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 4 to `net_udp_scan` must be INTEGER, got %s", args[3].Type()))
	}
	if errObj := validatePortRange("net_udp_scan", startPort.Value, endPort.Value); errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	start := time.Now()
	responsive := make([]object.Object, 0)
	for port := startPort.Value; port <= endPort.Value; port++ {
		addr := net.JoinHostPort(host.Value, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write([]byte("mutant-probe"))
		buf := make([]byte, 64)
		n, readErr := conn.Read(buf)
		_ = conn.Close()
		if readErr == nil && n > 0 {
			responsive = append(responsive, intObj(port))
		}
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"host":             stringObj(host.Value),
		"start_port":       intObj(startPort.Value),
		"end_port":         intObj(endPort.Value),
		"scanned":          intObj(endPort.Value - startPort.Value + 1),
		"responsive_ports": &object.Array{Elements: responsive},
		"duration_ms":      intObj(time.Since(start).Milliseconds()),
	}), nil)
}

func NetBanner(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_banner` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_banner` must be INTEGER, got %s", args[1].Type()))
	}

	timeout := time.Duration(timeoutMs.Value) * time.Millisecond
	conn, err := net.DialTimeout("tcp", addr.Value, timeout)
	if err != nil {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":     boolObj(false),
			"banner": stringObj(""),
			"error":  stringObj(err.Error()),
		}), nil)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	banner, readErr := io.ReadAll(io.LimitReader(conn, 4096))
	if readErr != nil {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":     boolObj(false),
			"banner": stringObj(""),
			"error":  stringObj(readErr.Error()),
		}), nil)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":     boolObj(true),
		"banner": stringObj(string(banner)),
		"error":  stringObj(""),
	}), nil)
}

func NetTLSFingerprint(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	addr, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_tls_fingerprint` must be STRING, got %s", args[0].Type()))
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_tls_fingerprint` must be INTEGER, got %s", args[1].Type()))
	}

	host, _, err := net.SplitHostPort(addr.Value)
	if err != nil {
		host = addr.Value
	}
	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs.Value) * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr.Value, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return resultAndError(makeHashObject(map[string]object.Object{
			"ok":    boolObj(false),
			"error": stringObj(err.Error()),
		}), nil)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	sha := ""
	subject := ""
	issuer := ""
	notBefore := ""
	notAfter := ""
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		digest := sha256.Sum256(cert.Raw)
		sha = hex.EncodeToString(digest[:])
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		notBefore = cert.NotBefore.UTC().Format(time.RFC3339)
		notAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	alpn := ""
	if state.NegotiatedProtocol != "" {
		alpn = state.NegotiatedProtocol
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"ok":               boolObj(true),
		"version":          stringObj(tlsVersionToString(state.Version)),
		"cipher":           stringObj(tls.CipherSuiteName(state.CipherSuite)),
		"alpn":             stringObj(alpn),
		"peer_cert_sha256": stringObj(sha),
		"subject":          stringObj(subject),
		"issuer":           stringObj(issuer),
		"not_before":       stringObj(notBefore),
		"not_after":        stringObj(notAfter),
		"error":            stringObj(""),
	}), nil)
}

func NetDNSQuery(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	name, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_dns_query` must be STRING, got %s", args[0].Type()))
	}
	typeObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_dns_query` must be STRING, got %s", args[1].Type()))
	}

	qType := strings.ToUpper(strings.TrimSpace(typeObj.Value))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch qType {
	case "A", "AAAA", "IP":
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(ips))
		for _, ip := range ips {
			if qType == "A" && ip.To4() == nil {
				continue
			}
			if qType == "AAAA" && ip.To4() != nil {
				continue
			}
			items = append(items, stringObj(ip.String()))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "CNAME":
		cname, err := net.DefaultResolver.LookupCNAME(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		return resultAndError(stringObj(cname), nil)
	case "MX":
		records, err := net.DefaultResolver.LookupMX(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(records))
		for _, rec := range records {
			items = append(items, makeHashObject(map[string]object.Object{
				"host": stringObj(rec.Host),
				"pref": intObj(int64(rec.Pref)),
			}))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "TXT":
		txts, err := net.DefaultResolver.LookupTXT(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(txts))
		for _, txt := range txts {
			items = append(items, stringObj(txt))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "NS":
		nsRecords, err := net.DefaultResolver.LookupNS(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(nsRecords))
		for _, rec := range nsRecords {
			items = append(items, stringObj(rec.Host))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	case "PTR":
		ptrRecords, err := net.DefaultResolver.LookupAddr(ctx, name.Value)
		if err != nil {
			return resultAndError(nil, newError("net_dns_query: %s", err.Error()))
		}
		items := make([]object.Object, 0, len(ptrRecords))
		for _, rec := range ptrRecords {
			items = append(items, stringObj(rec))
		}
		return resultAndError(&object.Array{Elements: items}, nil)
	default:
		return resultAndError(nil, newError("argument 2 to `net_dns_query` must be one of A, AAAA, IP, CNAME, MX, TXT, NS, PTR; got %q", typeObj.Value))
	}
}

func NetCaptureRaw(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}
	return resultAndError(nil, newError("net_capture_raw unsupported: requires elevated privileges and packet capture backend"))
}

func NetPCAPAnalyze(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_pcap_analyze` must be STRING, got %s", args[0].Type()))
	}

	file, err := os.Open(pathObj.Value)
	if err != nil {
		return resultAndError(nil, newError("net_pcap_analyze: %s", err.Error()))
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return resultAndError(nil, newError("net_pcap_analyze: %s", err.Error()))
	}

	linkType := reader.LinkType()
	flows := map[string]*netFlowSummary{}

	packetCount := int64(0)
	bytesTotal := int64(0)
	ipv4Count := int64(0)
	ipv6Count := int64(0)
	tcpCount := int64(0)
	udpCount := int64(0)
	icmpCount := int64(0)
	otherCount := int64(0)

	firstTs := time.Time{}
	lastTs := time.Time{}

	for {
		data, ci, readErr := reader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return resultAndError(nil, newError("net_pcap_analyze: %s", readErr.Error()))
		}

		packetCount++
		bytesTotal += int64(len(data))

		if firstTs.IsZero() || ci.Timestamp.Before(firstTs) {
			firstTs = ci.Timestamp
		}
		if lastTs.IsZero() || ci.Timestamp.After(lastTs) {
			lastTs = ci.Timestamp
		}

		packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)

		src := ""
		dst := ""
		sport := int64(0)
		dport := int64(0)
		proto := "OTHER"

		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ipv4Count++
			if ip4, ok := ip4Layer.(*layers.IPv4); ok {
				src = ip4.SrcIP.String()
				dst = ip4.DstIP.String()
			}
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ipv6Count++
			if ip6, ok := ip6Layer.(*layers.IPv6); ok {
				src = ip6.SrcIP.String()
				dst = ip6.DstIP.String()
			}
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcpCount++
			proto = "TCP"
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				sport = int64(tcp.SrcPort)
				dport = int64(tcp.DstPort)
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udpCount++
			proto = "UDP"
			if udp, ok := udpLayer.(*layers.UDP); ok {
				sport = int64(udp.SrcPort)
				dport = int64(udp.DstPort)
			}
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
			icmpCount++
			proto = "ICMP"
		} else {
			otherCount++
		}

		if src != "" && dst != "" {
			k1 := fmt.Sprintf("%s|%s|%d|%s|%d", proto, src, sport, dst, dport)
			k2 := fmt.Sprintf("%s|%s|%d|%s|%d", proto, dst, dport, src, sport)
			key := k1
			if _, ok := flows[key]; !ok {
				if _, ok := flows[k2]; ok {
					key = k2
				}
			}

			summary, ok := flows[key]
			if !ok {
				summary = &netFlowSummary{src: src, dst: dst, sport: sport, dport: dport, proto: proto}
				flows[key] = summary
			}
			summary.packets++
			summary.bytes += int64(len(data))
		}
	}

	flowKeys := make([]string, 0, len(flows))
	for k := range flows {
		flowKeys = append(flowKeys, k)
	}
	sort.Strings(flowKeys)

	flowObjects := make([]object.Object, 0, len(flowKeys))
	for _, key := range flowKeys {
		summary := flows[key]
		flowObjects = append(flowObjects, makeHashObject(map[string]object.Object{
			"src":     stringObj(summary.src),
			"dst":     stringObj(summary.dst),
			"sport":   intObj(summary.sport),
			"dport":   intObj(summary.dport),
			"proto":   stringObj(summary.proto),
			"packets": intObj(summary.packets),
			"bytes":   intObj(summary.bytes),
		}))
	}

	durationMs := int64(0)
	if !firstTs.IsZero() && !lastTs.IsZero() && lastTs.After(firstTs) {
		durationMs = lastTs.Sub(firstTs).Milliseconds()
	}

	firstTS := ""
	if !firstTs.IsZero() {
		firstTS = firstTs.UTC().Format(time.RFC3339Nano)
	}
	lastTS := ""
	if !lastTs.IsZero() {
		lastTS = lastTs.UTC().Format(time.RFC3339Nano)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"file":          stringObj(pathObj.Value),
		"link_type":     stringObj(linkType.String()),
		"packet_count":  intObj(packetCount),
		"bytes_total":   intObj(bytesTotal),
		"ipv4_packets":  intObj(ipv4Count),
		"ipv6_packets":  intObj(ipv6Count),
		"tcp_packets":   intObj(tcpCount),
		"udp_packets":   intObj(udpCount),
		"icmp_packets":  intObj(icmpCount),
		"other_packets": intObj(otherCount),
		"first_ts":      stringObj(firstTS),
		"last_ts":       stringObj(lastTS),
		"duration_ms":   intObj(durationMs),
		"flows":         &object.Array{Elements: flowObjects},
	}), nil)
}

func NetFlowReconstruct(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	packetsObj, ok := args[0].(*object.Array)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_flow_reconstruct` must be ARRAY, got %s", args[0].Type()))
	}

	flows := map[string]*netFlowSummary{}
	for idx, packetObj := range packetsObj.Elements {
		packet, ok := packetObj.(*object.Hash)
		if !ok {
			return resultAndError(nil, newError("packet at index %d must be HASH", idx))
		}

		src, err := hashStringField(packet, "src")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		dst, err := hashStringField(packet, "dst")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		sport, err := hashIntField(packet, "sport")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		dport, err := hashIntField(packet, "dport")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		proto, err := hashStringField(packet, "proto")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}
		pktBytes, err := hashIntField(packet, "bytes")
		if err != nil {
			return resultAndError(nil, newError("packet at index %d: %s", idx, err.Error()))
		}

		k1 := fmt.Sprintf("%s|%s|%d|%s|%d", strings.ToUpper(proto), src, sport, dst, dport)
		k2 := fmt.Sprintf("%s|%s|%d|%s|%d", strings.ToUpper(proto), dst, dport, src, sport)
		key := k1
		if _, ok := flows[key]; !ok {
			if _, ok := flows[k2]; ok {
				key = k2
			}
		}

		summary, ok := flows[key]
		if !ok {
			summary = &netFlowSummary{src: src, dst: dst, sport: sport, dport: dport, proto: strings.ToUpper(proto)}
			flows[key] = summary
		}
		summary.packets++
		summary.bytes += pktBytes
	}

	keys := make([]string, 0, len(flows))
	for k := range flows {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	results := make([]object.Object, 0, len(keys))
	for _, key := range keys {
		summary := flows[key]
		results = append(results, makeHashObject(map[string]object.Object{
			"src":     stringObj(summary.src),
			"dst":     stringObj(summary.dst),
			"sport":   intObj(summary.sport),
			"dport":   intObj(summary.dport),
			"proto":   stringObj(summary.proto),
			"packets": intObj(summary.packets),
			"bytes":   intObj(summary.bytes),
		}))
	}

	return resultAndError(&object.Array{Elements: results}, nil)
}

func NetOSFingerprint(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	_, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_os_fingerprint` must be STRING, got %s", args[0].Type()))
	}
	_, ok = args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_os_fingerprint` must be INTEGER, got %s", args[1].Type()))
	}
	return resultAndError(nil, newError("net_os_fingerprint unsupported: requires raw packet analysis capabilities"))
}

func validatePortRange(opName string, startPort int64, endPort int64) *object.Error {
	if startPort < 1 || startPort > 65535 {
		return newError("argument 2 to `%s` must be a valid port in range 1-65535, got %d", opName, startPort)
	}
	if endPort < 1 || endPort > 65535 {
		return newError("argument 3 to `%s` must be a valid port in range 1-65535, got %d", opName, endPort)
	}
	if startPort > endPort {
		return newError("`%s` requires start_port <= end_port", opName)
	}
	return nil
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return "unknown"
	}
}

func hashStringField(hash *object.Hash, key string) (string, error) {
	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		return "", fmt.Errorf("missing key %q", key)
	}
	str, ok := value.(*object.String)
	if !ok {
		return "", fmt.Errorf("key %q must be STRING", key)
	}
	return str.Value, nil
}

func hashIntField(hash *object.Hash, key string) (int64, error) {
	value, ok := hashValueByStringKey(hash, key)
	if !ok {
		return 0, fmt.Errorf("missing key %q", key)
	}
	intValue, ok := value.(*object.Integer)
	if !ok {
		return 0, fmt.Errorf("key %q must be INTEGER", key)
	}
	return intValue.Value, nil
}
