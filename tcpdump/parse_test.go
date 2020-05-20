package tcpdump

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var ipv4_str = "1590013369.251967 IP (tos 0x0, ttl 64, id 30548, offset 0, flags [DF], proto TCP (6), length 156)     192.168.188.23.50830 > 216.58.205.234.443: tcp 104"
var ipv4_udp_str = "1590016989.099948 IP (tos 0x2,ECT(0), ttl 58, id 31922, offset 0, flags [none], proto UDP (17), length 109)    94.130.141.248.60001 > 192.168.188.23.46473: UDP, length 81"
var ipv6_str = "1590012397.879500 IP6 (flowlabel 0xf6988, hlim 124, next-header TCP (6) payload length: 32) 2a00:1450:4016:801::2003.80 > 2003:e4:e712:fe00:efa4:d852:62e0:91b3.56652: tcp 0"

func TestDetermineProtocol(t *testing.T) {
	assert.Equal(t, "IP6", DetermineProtocol(ipv6_str))
	assert.Equal(t, "IP ", DetermineProtocol(ipv4_str))
}

func TestParseIPV4_UDPLine(t *testing.T) {
	p := ParseIPV4Line(ipv4_udp_str)

	assert.Equal(t, time.Unix(1590016989, 99948), p.Ts)
	assert.Equal(t, net.ParseIP("94.130.141.248"), p.Src)
	assert.Equal(t, 60001, p.SrcPort)
	assert.Equal(t, net.ParseIP("192.168.188.23"), p.Dst)
	assert.Equal(t, 46473, p.DstPort)
	assert.Equal(t, 109, p.Length)
}

func TestParseIPV4Line(t *testing.T) {
	p := ParseIPV4Line(ipv4_str)

	assert.Equal(t, time.Unix(1590013369, 251967), p.Ts)
	assert.Equal(t, net.ParseIP("192.168.188.23"), p.Src)
	assert.Equal(t, 50830, p.SrcPort)
	assert.Equal(t, net.ParseIP("216.58.205.234"), p.Dst)
	assert.Equal(t, 443, p.DstPort)
	assert.Equal(t, 156, p.Length)
}
