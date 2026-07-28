package builtin

import (
	"testing"

	"mutant/object"
)

func TestDefangRefang(t *testing.T) {
	defanged := strResult(t, Defang(stringObj("http://evil.example.com/a@b")))
	if defanged != "hxxp://evil[.]example[.]com/a[at]b" {
		t.Fatalf("defang = %q", defanged)
	}
	// refang restores the original.
	if got := strResult(t, Refang(stringObj(defanged))); got != "http://evil.example.com/a@b" {
		t.Fatalf("refang round-trip = %q", got)
	}
	// refang tolerates other common styles.
	if got := strResult(t, Refang(stringObj("hxxps://bad(dot)site[dot]net"))); got != "https://bad.site.net" {
		t.Fatalf("refang variants = %q", got)
	}
}

func TestIPHelpers(t *testing.T) {
	if !IPIsPrivate(stringObj("10.1.2.3")).(*object.Boolean).Value {
		t.Fatal("10.1.2.3 should be private")
	}
	if IPIsPrivate(stringObj("8.8.8.8")).(*object.Boolean).Value {
		t.Fatal("8.8.8.8 should be public")
	}
	if !IPIsPrivate(stringObj("127.0.0.1")).(*object.Boolean).Value {
		t.Fatal("loopback should be private")
	}
	if !IPInCIDR(stringObj("192.168.1.50"), stringObj("192.168.1.0/24")).(*object.Boolean).Value {
		t.Fatal("ip should be in cidr")
	}
	if IPInCIDR(stringObj("192.168.2.50"), stringObj("192.168.1.0/24")).(*object.Boolean).Value {
		t.Fatal("ip should not be in cidr")
	}
	if got := IPVersion(stringObj("8.8.8.8")).(*object.Integer).Value; got != 4 {
		t.Fatalf("ip_version v4 = %d", got)
	}
	if got := IPVersion(stringObj("2001:db8::1")).(*object.Integer).Value; got != 6 {
		t.Fatalf("ip_version v6 = %d", got)
	}
	if got := IPVersion(stringObj("not-an-ip")).(*object.Integer).Value; got != 0 {
		t.Fatalf("ip_version invalid = %d", got)
	}

	// ip_to_int / int_to_ip round-trip.
	n := IPToInt(stringObj("1.2.3.4")).(*object.Integer).Value
	if n != 0x01020304 {
		t.Fatalf("ip_to_int = %#x", n)
	}
	if got := strResult(t, IntToIP(intObj(n))); got != "1.2.3.4" {
		t.Fatalf("int_to_ip = %q", got)
	}
	if _, ok := IntToIP(intObj(-1)).(*object.Error); !ok {
		t.Fatal("int_to_ip(-1) should error")
	}

	// cidr_hosts for a /30 = 4 addresses.
	hosts := CIDRHosts(stringObj("192.168.1.0/30")).(*object.Array)
	if len(hosts.Elements) != 4 {
		t.Fatalf("cidr_hosts /30 = %d hosts", len(hosts.Elements))
	}
	if _, ok := CIDRHosts(stringObj("10.0.0.0/8")).(*object.Error); !ok {
		t.Fatal("cidr_hosts of a huge range should error")
	}
}

func TestDomainHelpers(t *testing.T) {
	if got := strResult(t, DomainExtract(stringObj("https://sub.example.co.uk/path?q=1"))); got != "sub.example.co.uk" {
		t.Fatalf("domain_extract = %q", got)
	}
	if got := strResult(t, DomainExtract(stringObj("bare-host.com"))); got != "bare-host.com" {
		t.Fatalf("domain_extract bare = %q", got)
	}
	tld := TLDExtract(stringObj("sub.example.co.uk")).(*object.Hash)
	if got := tld.Pairs[(&object.String{Value: "etld1"}).HashKey()].Value.(*object.String).Value; got != "example.co.uk" {
		t.Fatalf("tld_extract etld1 = %q", got)
	}
	if got := tld.Pairs[(&object.String{Value: "suffix"}).HashKey()].Value.(*object.String).Value; got != "co.uk" {
		t.Fatalf("tld_extract suffix = %q", got)
	}
	if !IsValidDomain(stringObj("example.com")).(*object.Boolean).Value {
		t.Fatal("example.com should be valid")
	}
	if IsValidDomain(stringObj("not a domain")).(*object.Boolean).Value {
		t.Fatal("'not a domain' should be invalid")
	}
}

func TestExtractIOCs(t *testing.T) {
	text := "Contact evil[.]example[.]com at admin@evil.example.com, C2 hxxp://8.8.8.8/beacon, " +
		"hash d41d8cd98f00b204e9800998ecf8427e and sha256 " +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."

	res := ExtractIOCs(stringObj(text)).(*object.Hash)
	get := func(key string) []string {
		arr := res.Pairs[(&object.String{Value: key}).HashKey()].Value.(*object.Array)
		out := make([]string, len(arr.Elements))
		for i, el := range arr.Elements {
			out[i] = el.(*object.String).Value
		}
		return out
	}
	contains := func(list []string, want string) bool {
		for _, s := range list {
			if s == want {
				return true
			}
		}
		return false
	}

	if !contains(get("ipv4"), "8.8.8.8") {
		t.Fatalf("expected 8.8.8.8 in ipv4, got %v", get("ipv4"))
	}
	if !contains(get("urls"), "http://8.8.8.8/beacon") {
		t.Fatalf("expected refanged URL, got %v", get("urls"))
	}
	if !contains(get("emails"), "admin@evil.example.com") {
		t.Fatalf("expected email, got %v", get("emails"))
	}
	if !contains(get("domains"), "evil.example.com") {
		t.Fatalf("expected refanged domain, got %v", get("domains"))
	}
	if !contains(get("md5"), "d41d8cd98f00b204e9800998ecf8427e") {
		t.Fatalf("expected md5, got %v", get("md5"))
	}
	if !contains(get("sha256"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Fatalf("expected sha256, got %v", get("sha256"))
	}
}
