## Required dependecies ## 
```shell
apt install libnfnetlink_queue-dev
apt install libpcap-dev
pip install python-pip
pip install scapy
pip install NetfilterQueue
```

## Binary deployment ## 
```shell
pip install pyinstaller
pyinstaller pcontrol.py
```

## Required rules (TESTING) ## 
```shell
iptables -N LOGGING
iptables -F LOGGING -v
iptables -F OUTPUT -v
iptables -F INPUT -v
iptables -F FORWARD -v
iptables -P OUTPUT ACCEPT
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
# Get all the DNS Answers coming from source port 53
/usr/sbin/iptables -A output_rule -o br-lan -p udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
# Get all request to dest port 80, 443
/usr/sbin/iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 0 --queue-bypass
```

## Required rules (PROD) ## 
### OpenWRT ###
```shell
opkg install python3
opkg install python3-dev
opkg install python3-pip
opkg install git-http
opkg install gcc
pip3 install NetfilterQueue
```
#### NetfilterQueue from source ####
```shell
-- libnfnetlink

root@f144d7e2bb64:~# wget https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.1.tar.bz2
root@ubud:~# tar xvjf libnfnetlink-1.0.1.tar.bz2
root@ubud:~# cp -r libnfnetlink-1.0.1 /home/riccic/

root@f144d7e2bb64:~# scp -r riccic@ubud.lan:/home/riccic/libnfnetlink-1.0.1 .
root@f144d7e2bb64:~# cp -r libnfnetlink-1.0.1/include/libnfnetlink /usr/include/

-- libnetfilter-queue - 2017-06-27-601abd1c-1

root@ubud:~# wget https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.3.tar.bz2
root@ubud:~# tar xvjf libnetfilter_queue-1.0.3.tar.bz2
root@ubud:~# cp -r libnetfilter_queue-1.0.3 /home/riccic/

root@f144d7e2bb64:~# scp -r riccic@ubud.lan:/home/riccic/libnetfilter_queue-1.0.3 .
root@f144d7e2bb64:~# cp -r libnetfilter_queue-1.0.3/include/libnetfilter_queue /usr/include/

root@f144d7e2bb64:~# ln -s /usr/lib/libnetfilter_queue.so.1.4.0 /usr/lib/libnetfilter_queue.so
root@f144d7e2bb64:~# pip3 install NetfilterQueue
```
#### Scapy ####
```shell
pip3 install scapy
```
#### DPACO ####
```shell
git clone https://github.com/christianricci/dpaco.git dpaco
```
#### sqlite client ####
```shell
opkg install sqlite3-cli
```
#### install nfqueue module ####
```shell
opkg install iptables-mod-nfqueue
```
#### openwrt - add custom rule ####
```shell
# Get all the DNS Answers coming from source port 53
/usr/sbin/iptables -A output_rule -o br-lan -p udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
# Get all request to dest port 80, 443
/usr/sbin/iptables -A forwarding_rule -i br-lan -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 0 --queue-bypass
```
#### Check iptables -L -n -v input_rule ####
```shell
Chain input_rule (1 references)
 pkts bytes target     prot opt in     out     source               destination
    1   318 NFQUEUE    udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp spt:53 NFQUEUE num 0 bypass
```
#### run ####
```shell 
cd /root/dpaco; python3 pcontrol.py
```

## TODO ## 
* Multithreaded - main NFQ run
* Rest API to get stats
* Rest API to reset the cache
* Rest API to add/remove/update access_control

Markdown rules in https://github.com/tchapi/markdown-cheatsheet/blob/master/README.md