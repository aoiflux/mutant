package builtin

import (
	"encoding/binary"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"mutant/object"
)

// --- defang / refang ---

func Defang(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("defang", args)
	if errObj != nil {
		return errObj
	}
	out := strings.ReplaceAll(s, "http", "hxxp")
	out = strings.ReplaceAll(out, ".", "[.]")
	out = strings.ReplaceAll(out, "@", "[at]")
	return stringObj(out)
}

var refangReplacer = strings.NewReplacer(
	"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", " dot ", ".",
	"hxxps", "https", "hxxp", "http", "hXXp", "http",
	"[at]", "@", "(at)", "@", "[@]", "@", " at ", "@",
	"[:]", ":", "[://]", "://", "[/]", "/",
)

func Refang(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("refang", args)
	if errObj != nil {
		return errObj
	}
	return stringObj(refangReplacer.Replace(s))
}

// --- IP / CIDR ---

func IPIsPrivate(args ...object.Object) object.Object {
	ip, errObj := ipArg("ip_is_private", args)
	if errObj != nil {
		return errObj
	}
	return boolObj(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

func IPInCIDR(args ...object.Object) object.Object {
	if len(args) != 2 {
		return newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	ipStr, errObj := requireStringArg("ip_in_cidr", args[0], 1)
	if errObj != nil {
		return errObj
	}
	cidr, errObj := requireStringArg("ip_in_cidr", args[1], 2)
	if errObj != nil {
		return errObj
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return newError("ip_in_cidr: invalid IP %q", ipStr)
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return newError("ip_in_cidr: invalid CIDR %q: %s", cidr, err.Error())
	}
	return boolObj(network.Contains(ip))
}

func CIDRHosts(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("cidr_hosts", args)
	if errObj != nil {
		return errObj
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return newError("cidr_hosts: invalid CIDR %q: %s", s, err.Error())
	}
	ones, bits := network.Mask.Size()
	const maxHosts = 1 << 20
	if bits-ones > 20 {
		return newError("cidr_hosts: range too large (%d host bits); max is 20", bits-ones)
	}

	hosts := make([]object.Object, 0)
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)
	for network.Contains(ip) {
		hosts = append(hosts, stringObj(ip.String()))
		if len(hosts) > maxHosts {
			break
		}
		incrementIP(ip)
	}
	return &object.Array{Elements: hosts}
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func IPVersion(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("ip_version", args)
	if errObj != nil {
		return errObj
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return intObj(0)
	}
	if ip.To4() != nil {
		return intObj(4)
	}
	return intObj(6)
}

func IPToInt(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("ip_to_int", args)
	if errObj != nil {
		return errObj
	}
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		return newError("ip_to_int: requires a valid IPv4 address, got %q", s)
	}
	return intObj(int64(binary.BigEndian.Uint32(ip)))
}

func IntToIP(args ...object.Object) object.Object {
	if len(args) != 1 {
		return newError("wrong number of arguments. got=%d, want=1", len(args))
	}
	n, errObj := requireIntArg("int_to_ip", args[0], 1)
	if errObj != nil {
		return errObj
	}
	if n < 0 || n > 0xFFFFFFFF {
		return newError("int_to_ip: value %d out of IPv4 range (0..4294967295)", n)
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	return stringObj(net.IP(buf).String())
}

// --- domains ---

func DomainExtract(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("domain_extract", args)
	if errObj != nil {
		return errObj
	}
	raw := strings.TrimSpace(s)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return stringObj("")
	}
	return stringObj(strings.ToLower(u.Hostname()))
}

func TLDExtract(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("tld_extract", args)
	if errObj != nil {
		return errObj
	}
	domain := strings.ToLower(strings.TrimSpace(s))
	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return stringObj("")
	}
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return makeHashObject(map[string]object.Object{
		"domain": stringObj(domain),
		"etld1":  stringObj(etld1),
		"suffix": stringObj(suffix),
	})
}

var domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func IsValidDomain(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("is_valid_domain", args)
	if errObj != nil {
		return errObj
	}
	d := strings.TrimSpace(s)
	if len(d) == 0 || len(d) > 253 {
		return boolObj(false)
	}
	return boolObj(domainRe.MatchString(d))
}

// --- IOC extraction ---

var (
	iocIPv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	iocURLRe    = regexp.MustCompile(`\bhttps?://[^\s<>"'\]\)]+`)
	iocEmailRe  = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	iocDomainRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	iocMD5Re    = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	iocSHA1Re   = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	iocSHA256Re = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
)

func ExtractIOCs(args ...object.Object) object.Object {
	s, errObj := strOneStringArg("extract_iocs", args)
	if errObj != nil {
		return errObj
	}
	// Refang first so defanged IOCs (hxxp, [.]) are captured too.
	text := refangReplacer.Replace(s)

	ipv4 := filterValidIPv4(iocIPv4Re.FindAllString(text, -1))
	rawURLs := iocURLRe.FindAllString(text, -1)
	for i := range rawURLs {
		rawURLs[i] = strings.TrimRight(rawURLs[i], ".,;:!?)]}'\"")
	}
	urls := uniqueSortedStrings(rawURLs)
	emails := uniqueSortedStrings(lowerAll(iocEmailRe.FindAllString(text, -1)))

	// Domains are extracted independently; a domain that also appears inside a URL
	// or email is still a valid domain IOC and is listed (deduped) here.
	domains := uniqueSortedStrings(lowerAll(iocDomainRe.FindAllString(text, -1)))

	// Hashes: sha256(64) and sha1(40) take precedence over md5(32) matches that
	// are substrings; the regexes use \b so lengths are exact already.
	md5s := uniqueSortedStrings(lowerAll(iocMD5Re.FindAllString(text, -1)))
	sha1s := uniqueSortedStrings(lowerAll(iocSHA1Re.FindAllString(text, -1)))
	sha256s := uniqueSortedStrings(lowerAll(iocSHA256Re.FindAllString(text, -1)))

	return makeHashObject(map[string]object.Object{
		"ipv4":    stringArrayObj(ipv4),
		"urls":    stringArrayObj(urls),
		"domains": stringArrayObj(domains),
		"emails":  stringArrayObj(emails),
		"md5":     stringArrayObj(md5s),
		"sha1":    stringArrayObj(sha1s),
		"sha256":  stringArrayObj(sha256s),
	})
}

// --- shared helpers ---

func ipArg(op string, args []object.Object) (net.IP, *object.Error) {
	s, errObj := strOneStringArg(op, args)
	if errObj != nil {
		return nil, errObj
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil, newError("%s: invalid IP address %q", op, s)
	}
	return ip, nil
}

func filterValidIPv4(candidates []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if ip := net.ParseIP(c); ip != nil && ip.To4() != nil {
			out = append(out, c)
		}
	}
	return uniqueSortedStrings(out)
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func uniqueSortedStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
