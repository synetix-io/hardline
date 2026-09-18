# 2026-09-15 21:03:10 by RouterOS 7.24.2
# software id = 9XK2-PL0A
#
# model = CCR2004-16G-2S+
/interface ethernet
set [ find default-name=sfp-sfpplus1 ] name=sfp1-upstream
set [ find default-name=ether1 ] name=ether1-mgmt
/interface list
add name=WAN
add name=LAN
add name=MGMT
/interface list member
add interface=sfp1-upstream list=WAN
add interface=ether1-mgmt list=LAN
add interface=ether1-mgmt list=MGMT
/ip address
add address=41.76.100.2/30 interface=sfp1-upstream network=41.76.100.0
add address=10.10.10.1/24 interface=ether1-mgmt network=10.10.10.0
/ip dns
set allow-remote-requests=no servers=1.1.1.1
/ip firewall filter
add action=accept chain=input comment="established" connection-state=established,related,untracked
add action=drop chain=input comment="invalid" connection-state=invalid
add action=accept chain=input comment="icmp" protocol=icmp
add action=accept chain=input comment="mgmt" in-interface-list=MGMT
add action=drop chain=input comment="drop wan" in-interface-list=WAN log=yes log-prefix=WAN-DROP
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh address=10.10.10.0/24 disabled=no port=22
set api address=10.10.10.5/32 disabled=no
set api-ssl disabled=yes
set winbox address=10.10.10.0/24 disabled=no
set www-ssl disabled=yes
/ip ssh
set strong-crypto=yes forwarding-enabled=no
/ip neighbor discovery-settings
set discover-interface-list=MGMT
/ip upnp
set enabled=no
/snmp
set enabled=yes location=DC-JHB1
/snmp community
set [ find default=yes ] addresses=10.10.10.5/32 name=Kx93pQ2m read-access=yes security=private authentication-protocol=SHA1 encryption-protocol=AES
/system clock
set time-zone-name=Africa/Johannesburg
/system identity
set name=JHB1-CORE-01
/system logging action
add name=syslog remote=10.10.10.20 remote-port=514 src-address=10.10.10.1 target=remote
/system logging
add action=syslog topics=info
add action=syslog topics=error
add action=syslog topics=warning
add action=syslog topics=critical
/system ntp client
set enabled=yes servers=za.pool.ntp.org
/tool bandwidth-server
set enabled=no
/tool mac-server
set allowed-interface-list=MGMT
/tool mac-server mac-winbox
set allowed-interface-list=MGMT
/tool romon
set enabled=no
/user
add name=yukesh.r allowed-address=10.10.10.0/24 group=full
add name=svc-splynx allowed-address=10.10.10.5/32 group=full
/user set admin disabled=yes
