# 2026-09-17 06:41:09 by RouterOS 7.16.1
# software id = 7HJK-2N4R
#
# model = CCR2004-1G-12S+2XS
# serial number = HE4098A1C22F
/interface bridge
add name=br-mgmt protocol-mode=none
/interface ethernet
set [ find default-name=ether1 ] name=ether1-mgmt
set [ find default-name=sfp-sfpplus1 ] name=sfp1-fibre-upstream
set [ find default-name=sfp-sfpplus2 ] name=sfp2-sector-north
set [ find default-name=sfp-sfpplus3 ] name=sfp3-sector-south
set [ find default-name=sfp-sfpplus4 ] name=sfp4-backhaul-tower9
/interface vlan
add interface=sfp1-fibre-upstream name=vlan100-transit vlan-id=100
add interface=sfp2-sector-north name=vlan201-cust-north vlan-id=201
add interface=sfp3-sector-south name=vlan202-cust-south vlan-id=202
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=vlan100-transit list=WAN
add interface=sfp4-backhaul-tower9 list=WAN
add interface=br-mgmt list=LAN
add interface=vlan201-cust-north list=LAN
add interface=vlan202-cust-south list=LAN
/interface bridge port
add bridge=br-mgmt interface=ether1-mgmt
/ip pool
add name=pool-north ranges=100.64.1.10-100.64.1.250
add name=pool-south ranges=100.64.2.10-100.64.2.250
/ip dhcp-server
add address-pool=pool-north interface=vlan201-cust-north name=dhcp-north
add address-pool=pool-south interface=vlan202-cust-south name=dhcp-south
/ip address
add address=41.185.22.130/30 interface=vlan100-transit network=41.185.22.128
add address=10.7.0.1/24 interface=br-mgmt network=10.7.0.0
add address=100.64.1.1/24 interface=vlan201-cust-north network=100.64.1.0
add address=100.64.2.1/24 interface=vlan202-cust-south network=100.64.2.0
add address=172.16.9.2/30 interface=sfp4-backhaul-tower9 network=172.16.9.0
/ip dns
set allow-remote-requests=yes servers=41.185.0.2,41.185.0.3
/ip firewall address-list
add address=10.7.0.0/24 list=mgmt
add address=41.185.22.1 list=noc
/ip firewall filter
add action=accept chain=input comment="established/related" connection-state=established,related
add action=accept chain=input comment="mgmt subnet" src-address-list=mgmt
add action=accept chain=input comment="noc" src-address-list=noc
add action=accept chain=input comment="dns for customers" dst-port=53 protocol=udp
add action=accept chain=input comment="winbox from anywhere - temp for tower9 install" dst-port=8291 protocol=tcp
add action=accept chain=input protocol=icmp
add action=drop chain=input comment="drop rest" in-interface-list=WAN
add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes
add action=accept chain=forward connection-state=established,related
add action=drop chain=forward connection-state=invalid
/ip firewall nat
add action=masquerade chain=srcnat out-interface=vlan100-transit src-address=100.64.0.0/10
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www address=10.7.0.0/24
set ssh port=2222
set api disabled=no
set winbox disabled=no
set api-ssl disabled=yes
/ip neighbor discovery-settings
set discover-interface-list=all
/ip upnp
set enabled=no
/ppp profile
set *0 local-address=100.64.0.1 rate-limit=20M/20M
/routing bgp connection
add as=64620 local.role=ebgp name=transit-upstream remote.address=41.185.22.129 remote.as=37457 router-id=41.185.22.130
/snmp
set contact="noc@skywave.example" enabled=yes location="Tower 7 - Hartbeespoort" trap-community=public
/snmp community
set [ find default=yes ] addresses=0.0.0.0/0 name=public
add addresses=10.7.0.20/32 name=librenms read-access=yes
/system clock
set time-zone-name=Africa/Johannesburg
/system identity
set name=TWR7-CCR-HBP
/system logging action
set 0 memory-lines=500
/system note
set show-at-login=no
/system ntp client
set enabled=yes
/system ntp client servers
add address=za.pool.ntp.org
/system scheduler
add interval=1d name=nightly-backup on-event="/system backup save name=nightly dont-encrypt=yes; /tool fetch url=\"http://10.7.0.30/upload.php\" mode=http http-method=post src-path=nightly.backup upload=yes" policy=ftp,read,write,test start-time=02:00:00
/tool bandwidth-server
set enabled=yes
/tool mac-server
set allowed-interface-list=all
/tool mac-server mac-winbox
set allowed-interface-list=all
/tool romon
set enabled=yes
/user
add name=admin group=full
add name=splynx-api allowed-address=10.7.0.25/32 group=full
add name=noc group=full
add name=tower-tech group=write
/user aaa
set use-radius=no
