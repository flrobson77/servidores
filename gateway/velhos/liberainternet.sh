#!/bin/bash

## Script de Firewall
## Redirecionando os pacotes simulando a rede o IFSP Câmpus Guarulhos
## 
## Preparar aulas


# Rede Interna
LAN=192.168.16.0/24

# Habilita a passagem de pacotes
echo 1 > /proc/sys/net/ipv4/ip_forward

# Limpa todas as CHAINS
iptables -F
iptables -t nat -F
iptables -t mangle -F

### NAT SESSION ###
# Habilita o acesso a internet para LAN
iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE
