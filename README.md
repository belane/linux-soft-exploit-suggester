# linux-soft-exploit-suggester

linux-soft-exploit-suggester finds exploits for all vulnerable software in a system helping with the privilege escalation. It focuses on software packages instead of Kernel vulnerabilities.
It uses [exploit database](https://github.com/offensive-security/exploit-database) to evaluate the security of packages and search for exploits, so you should download it on first run.

```
> python linux-soft-exploit-suggester.py -h

  |  _         __ _  _ |    _    _ | _  |    __    __  __  _  __ |   _  _
  |·| || |\/  (_ | ||_ |-  /_)\/| \|| |·|-  (_ | ||  )|  )/_)(_  |- /_)|
  ||| ||_|/\  __)|_||  |_  \_ /\|_/||_|||_  __)|_||_/ |_/ \_ __) |_ \_ |
                                |                 _/  _/

linux-soft-exploit-suggester:
  Search for Exploitable Software from package list.

optional arguments:
  -h, --help            Show this help message and exit
  -f FILE, --file FILE  Package list file
  --clean               Use clean package list, if used 'dpkg-query -W'
  --duplicates          Show duplicate exploits
  --db DB               Exploits csv file [default: files_exploits.csv]
  --update              Download latest version of exploits db
  -d debian|redhat, --distro debian|redhat
                        Linux flavor, debian or redhat [default: debian]
  --dos                 Include DoS exploits
  --intense             Include intense package name search,
                        when software name doesn't match package name (experimental)
  -l 1-5, --level 1-5   Software version search variation [default: 1]                        
                          level 1: Same version                        
                          level 2: Micro and Patch version                        
                          level 3: Minor version                        
                          level 4: Major version                        
                          level 5: All versions
  --type TYPE           Exploit type; local, remote, webapps, dos.
                          e.g.	--type local
                        	--type remote
  --filter FILTER       Filter exploits by string
                          e.g.	--filter "escalation"

usage examples:     
  Get Package List:
	debian/ubuntu: dpkg -l > package_list
	redhat/centos: rpm -qa > package_list

  Update exploit database:
	python linux-soft-exploit-suggester.py --update

  Basic usage:
	python linux-soft-exploit-suggester.py --file package_list

  Specify exploit db:
	python linux-soft-exploit-suggester.py --file package_list --db files_exploits.cve

  Use Redhat/Centos format file:
	python linux-soft-exploit-suggester.py --file package_list --distro redhat

  Search exploit for major version:
	python linux-soft-exploit-suggester.py --file package_list --level 4

  Filter by remote exploits:
	python linux-soft-exploit-suggester.py --file package_list --type remote

  Search specific words in exploit title:
	python linux-soft-exploit-suggester.py --file package_list --filter Overflow

  Advanced usage:
	python linux-soft-exploit-suggester.py --file package_list --level 3 --type local --filter escalation

```
### Output
```
> python linux-soft-exploit-suggester.py --file packages --db files_exploits.csv

  |  _         __ _  _ |    _    _ | _  |    __    __  __  _  __ |   _  _
  |·| || |\/  (_ | ||_ |-  /_)\/| \|| |·|-  (_ | ||  )|  )/_)(_  |- /_)|
  ||| ||_|/\  __)|_||  |_  \_ /\|_/||_|||_  __)|_||_/ |_/ \_ __) |_ \_ |
                                |                 _/  _/

[!] DNSTracer 1.9 - Buffer Overflow - local
  	 From: dnstracer 1.9
  	 File: /usr/share/exploitdb/platforms/linux/local/42424.py
  	 Url: https://www.exploit-db.com/exploits/42424
[!] GNU Wget < 1.18 - Arbitrary File Upload / Remote Code Execution - remote
  	 From: wget 1.17.1
  	 File: /usr/share/exploitdb/platforms/linux/remote/40064.txt
  	 Url: https://www.exploit-db.com/exploits/40064
[!] GNU Screen 4.5.0 - Privilege Escalation (PoC) - local
  	 From: screen 4.3.1
  	 File: /usr/share/exploitdb/platforms/linux/local/41152.txt
  	 Url: https://www.exploit-db.com/exploits/41152
[!] Ghostscript 9.21 - Type Confusion Arbitrary Command Execution (Metasploit) - local
  	 From: ghostscript 9.21
  	 File: /usr/share/exploitdb/platforms/linux/local/41955.rb
  	 Url: https://www.exploit-db.com/exploits/41955
[!] KeepNote 0.7.8 - Command Execution - local
  	 From: keepnote 0.7.8
  	 File: /usr/share/exploitdb/platforms/multiple/local/40440.py
  	 Url: https://www.exploit-db.com/exploits/40440
[!] MAWK 1.3.3-17 - Local Buffer Overflow - local
  	 From: mawk 1.3.3
  	 File: /usr/share/exploitdb/platforms/linux/local/42357.py
  	 Url: https://www.exploit-db.com/exploits/42357
[!] Sudo 1.8.20 - 'get_process_ttyname()' Privilege Escalation - local
  	 From: sudo 1.8.20
  	 File: /usr/share/exploitdb/platforms/linux/local/42183.c
  	 Url: https://www.exploit-db.com/exploits/42183

...
```

### Generate package list
#### Debian
`
dpkg -l > package_list
`

#### Red Hat
`
rpm -qa > package_list
`
### TIP. Packages from running processes and SETUID binaries

##### Running packages
```
> for i in $(ps auex|sed -e ':l;s/  / /g;t l'|cut -d' ' -f11|grep -v '\['|grep '/'|sort -u); \
  do \
  dpkg -l | grep "^ii  `dpkg -S $i 2>&1|cut -d':' -f1`" |tee -a potentials; \
  done
```
##### SETUID Binaries
```
> for i in $(find / -perm -4000 -o -perm -2000 -type f 2>/dev/null); \
  do \
  dpkg -l | grep "^ii  `dpkg -S $i 2>&1|cut -d':' -f1`"|tee -a potentials; \
  done
```
##### Eliminate duplicates and Run
```
> sort -u potentials > potentials_no_duplicates
> python linux-soft-exploit-suggester.py --file potentials_no_duplicates --level 2 --type local

  |  _         __ _  _ |    _    _ | _  |    __    __  __  _  __ |   _  _
  |·| || |\/  (_ | ||_ |-  /_)\/| \|| |·|-  (_ | ||  )|  )/_)(_  |- /_)|
  ||| ||_|/\  __)|_||  |_  \_ /\|_/||_|||_  __)|_||_/ |_/ \_ __) |_ \_ |
                                |                 _/  _/

[!] Sudo 1.8.20 - 'get_process_ttyname()' Privilege Escalation - local
  	 From: sudo 1.8.20
  	 File: /usr/share/exploitdb/platforms/linux/local/42183.c
  	 Url: https://www.exploit-db.com/exploits/42183
[!] Fuse 2.9.3-15 - Privilege Escalation - local
  	 From: fuse 2.9.7
  	 File: /usr/share/exploitdb/platforms/linux/local/37089.txt
  	 Url: https://www.exploit-db.com/exploits/37089

```
