#!/bin/bash

LAN="192.168.255.0/24"

#Politica Básica
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Limpa regras
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F

# Habilitar a passagem de pacotes
echo 1 > /proc/sys/net/ipv4/ip_forward

# Liberar acesso de pacotes mascadado
iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE
