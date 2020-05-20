package tcpdump

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Packet struct {
	Ts      time.Time
	Proto   string
	Flags   string
	Src     net.IP
	SrcPort int
	Dst     net.IP
	DstPort int
	Length  int
}

func DetermineProtocol(line string) string {
	proto := line[18:21]

	return proto
}

var parseIpExp *regexp.Regexp

func init() {
	regex := `(?P<ts>\d+)\.(?P<ns>\d+) (?P<protocol>\S+) \(tos (?P<tos>[^\s]+) ttl (?P<ttl>[^,]+), id (?P<id>[^,]+), offset (?P<offset>[^,]+), flags (?P<flags>[^,]+), proto (?P<proto>[^,]+), length (?P<length>[^\)]+)\)\s+(?P<src>\S+) > (?P<dst>[^:]+)(?P<rest>.+)`
	parseIpExp = regexp.MustCompile(regex)
}

func parseIPAndPort(ip string) (net.IP, int) {
	p := strings.Split(ip, ".")
	lastPart := p[len(p)-1]

	port, err := strconv.ParseInt(lastPart, 10, 64)
	if err != nil {
		fmt.Println("failed to parse port")
		return nil, 0
	}
	xip := net.ParseIP(ip[0 : len(ip)-1-len(lastPart)])
	return xip, int(port)
}

func ParseIPV4Line(line string) Packet {
	match := parseIpExp.FindStringSubmatch(line)
	result := make(map[string]string)
	for i, name := range parseIpExp.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	ts, err := strconv.ParseInt(result["ts"], 10, 64)
	if err != nil {
		fmt.Println("failed to parse timestamp")
	}

	ns, err := strconv.ParseInt(result["ns"], 10, 64)
	if err != nil {
		fmt.Println("failed to parse ns timestamp")
	}
	t := time.Unix(ts, ns)

	src, srcPort := parseIPAndPort(result["src"])
	dst, dstPort := parseIPAndPort(result["dst"])

	length, err := strconv.ParseInt(result["length"], 10, 64)
	if err != nil {
		fmt.Println("failed to parse int")
	}

	p := Packet{
		Ts:      t,
		Src:     src,
		Dst:     dst,
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  int(length),
	}

	return p
}
