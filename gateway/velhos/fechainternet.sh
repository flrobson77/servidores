#!/bin/bash

## Script de Firewall
## Redirecionando os pacotes simulando a rede o IFSP Câmpus Guarulhos
## 
## Preparar aulas


# Rede Interna
LAN=192.168.16.0/24

# Habilita a passagem de pacotes
echo 0 > /proc/sys/net/ipv4/ip_forward

# Limpa todas as CHAINS
iptables -F
iptables -t nat -F
iptables -t mangle -F
