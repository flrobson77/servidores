#!/bin/bash
######## Firewall ########
# IFSP Câmpus Guarulhos  #
# Autor Robson Lopes     #
# Versao 3.0             #
##########################

# Configuracoes iniciais
GTW="192.168.255.201"
WEB="192.168.255.202"
WIN="192.168.255.203"
OPE="192.168.255.110"
ES1="192.168.255.1"
ES2="192.168.255.2"
LAN="192.168.255.0/24"
PTS="1024:65535"
NET="0/0"
EXT="192.168.16.246"
WAN="192.168.16.0/24"
ETE="enp0s3"
ETI="enp0s8"

### Politica Básica ###
for CHAINS in INPUT FORWARD OUTPUT
do
	iptables -P $CHAINS DROP
done

# Limpa regras
for TABELA in filter nat mangle
do
	iptables -t $TABELA -F
done

# Zera os contadores do iptables
iptables -Z

# Limpa as chais de usuarios
iptables -X

## Excecções

# Habilita o retorno de conhexoes ja estabelecidas e relacionadas 
for CHAINS in INPUT FORWARD OUTPUT
do
	iptables -A $CHAINS -m state --state ESTABLISHED,RELATED -j ACCEPT
done

# Habilita o loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Habilita o ICMP
iptables -A OUTPUT -p icmp --icmp-type 8 -o $ETE -j ACCEPT
iptables -A OUTPUT -s $LAN -p icmp --icmp-type 8 -o $ETI -j ACCEPT
iptables -A INPUT -s $LAN -p icmp --icmp-type 8 -i $ETI -j ACCEPT
iptables -A FORWARD -s $LAN -p icmp --icmp-type 8 -o $ETE -j ACCEPT

# Habilita consulta DNS para o servidor GATEWAY
iptables -A INPUT -i $ETE -p udp --sport 53 -j ACCEPT
iptables -A INPUT -i $ETE -p icmp --icmp-type 3 -j ACCEPT
iptables -A OUTPUT -o $ETE -p udp --dport 53 -j ACCEPT

# Habilita ao serviço NTP para o servidor GATEWAY
iptables -A INPUT -i $ETE -p udp --sport 123 -j ACCEPT
iptables -A OUTPUT -o $ETE -p udp --dport 123 -j ACCEPT


# Habilita a consulta DNS para os hosts interno da rede
iptables -A INPUT -p udp -s $LAN --sport $PTS -d $GTW --dport 53 -j ACCEPT

iptables -A INPUT -p udp -s $LAN --sport $PTS -d $GTW --dport 123 -j ACCEPT

# Habilita a consulta DNS para que trabalha externo
iptables -A INPUT -p udp -s $NET --sport $PTS -d $EXT --dport 53 -j ACCEPT

## Habilitar acesso HTTP e HTTPS para o servidor
for PORTAS in 80 443
do
   iptables -A OUTPUT -o $ETE -p tcp -d $NET --dport $PORTAS -j ACCEPT
done

# Habilitar acesso serviços internos
for IP in $WEB $OPE $WIN $ES1 $ES2
do
   for PORTAS in 22 80 443 3128 3389
   do
         iptables -A INPUT -p tcp -d $GTW --dport $PORTAS -j ACCEPT
   done
done

# Habilita passagem de pacotes pelo firewall para os serviços de rede (FTP, HTTP, HTTPS, ...) disponiveis em outras máquinas da rede
	iptables -A FORWARD -i $ETE -p tcp -s $NET -m multiport --dports 22,80,443 -j ACCEPT
   iptables -A FORWARD -o $ETE -p tcp -s $NET -m multiport --dports 80,443 -j ACCEPT
	iptables -A FORWARD -i $ETI -o $ETE -p tcp -s $LAN -m multiport --dports 21,22,80,443 -j ACCEPT
#	iptables -A FORWARD -o $ETI -p tcp -s $LAN -m multiport --dports 21,22,80,443 -j ACCEPT

### Regras de Passagem e NAT
# Habilita o rotemento dos pacotes
echo 1 > /proc/sys/net/ipv4/ip_forward

# 1 - Ativando o marcaramento de pacotes
iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE

# 2 - Habilita a passagem de pacotes dos serviços de rede em outros servidores
for PORTAS in 80 443
do
   iptables -t nat -A PREROUTING -p tcp -s $NET --sport $PTS -d $EXT --dport $PORTAS -j DNAT --to-destination $WEB:$PORTAS
done

# 3 - Habilita a acesso externo ao ssh na operacao
   iptables -t nat -A PREROUTING -p tcp -s 192.168.16.201 --sport $PTS -d $EXT --dport 22 -j DNAT --to-destination $OPE:22


### Protecao Adicionais ###
# Habilita a proteção "syn-flood, DoS, etc"
iptables -A FORWARD -p tcp -m limit --limit 1/s -j DROP

# Habilita a protecao contra PORT SCANNERS
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST,PSH ACK,RST,URG -m limit --limit 1/s -j DROP
iptables -A FORWARD -p tcp --tcp-flags NONE SYN,ACK -m limit --limit 1/s -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL SYN,ACK -j DROP

# Habilita a proteção contra o ping da morte
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j DROP

### Monitoramento ###
# Habilita monitoramento de serviços TCP (FTP, SSH, SMTP, MYSQL, SQUID...)
for CHAINS in INPUT FORWARD
do
	for PORTAS in 21 22 23 25 110 139 143 3128 3306 3389 5432 5900 8080
	do
	      iptables -A $CHAINS -p tcp --dport $PORTAS -j LOG --log-prefix "LOG_$PORTAS "
	done
done
