#!/bin/bash

rede interna
GTW=192.168.1.1
INT=192.168.1.10
DTC=192.168.1.20
STG=192.168.1.30
CLI=192.168.1.100
LAN=192.168.1.0/24

# Link Dedicado
FWL1=200.50.100.10
FWL2=200.50.100.20
FWL3=200.50.100.30
EXT=200.50.100.100
LNK=200.50.100.0/24

# Internet
DIP=`ifconfig enp0s3 | grep broadcast | awk -F" " '{print $2}'`
WAN=`route -n | grep enp0s3 | grep 255 | awk -F" " '{print $1}'`/24

# VPN
CVP=10.0.0.100
SVP=10.0.0.200
VPN=10.0.0.0/24

# Habilita o passagem de pacotes
echo 1 > /proc/sys/net/ipv4/ip_forward

# Politicas padroes do firewall
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Limpa todas chains
iptables -t nat -F
iptables -t filter -F


iptables -A POSTROUTING -t nat -s $LAN  -o enp0s3 -j MASQUERADE
