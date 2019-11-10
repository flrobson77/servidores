#!/bin/bash
######## Firewall ########
# IFSP Câmpus Guarulhos  #
# Autor Robson Lopes     #
# Versao 4.0             #
##########################

# Configuracoes iniciais
#Rede Interna
GTW="203.0.113.101"
WEB="203.0.113.102"
EML="203.0.113.103"
INT="203.0.113.51"
LAN="203.0.113.0/24"
PTS="1024:65535"
NET="0/0"

#Link Dedicado (WAN)
EXT="200.0.0.230"
EX2="200.0.0.231"
CEX="200.0.0.51"
WAN="200.0.0.0/24"

#VPN
SVP="10.0.0.101"
CVP="10.0.0.51"
RVP="10.0.0.0/24"

case $1 in
   start)
        echo -e "\nAtivando a Firewall..."

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

# Habilita o retorno de conhexoes ja estabelecidas e relacionadas 
for CHAINS in INPUT FORWARD OUTPUT
do
	iptables -A $CHAINS -m state --state ESTABLISHED,RELATED -j ACCEPT
done

## Excecções

# Habilita o loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Habilita o ICMP
iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -i enp0s8 -s $CEX -p icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -i enp0s9 -s $LAN -p icmp --icmp-type 8 -j ACCEPT
iptables -A FORWARD -o enp0s3 -s $LAN -p icmp --icmp-type 8 -j ACCEPT
iptables -A FORWARD -o enp0s9 -s $LAN -p icmp --icmp-type 8 -j ACCEPT

# Habilita consulta DNS para o servidor GATEWAY
iptables -A INPUT -i enp0s3 -p udp --sport 53 -j ACCEPT
iptables -A INPUT -i enp0s3 -p icmp --icmp-type 3 -j ACCEPT
iptables -A OUTPUT -o enp0s3  -p udp --dport 53 -j ACCEPT

# Habilita ao serviço NTP para o servidor GATEWAY
iptables -A INPUT -i enp0s3 -p udp --sport 123 -j ACCEPT
iptables -A OUTPUT -o enp0s3 -p udp --dport 123 -j ACCEPT

# Habilitar acesso HTTP e HTTPS para o servidor
for PORTAS in 80 443
do
   iptables -A OUTPUT -o enp0s3 -p tcp -d $NET --dport $PORTAS -j ACCEPT
done

# Habilita a consulta DNS para os hosts interno da rede
iptables -A INPUT -p udp -s $LAN --sport $PTS -d $GTW --dport 53 -j ACCEPT
iptables -A INPUT -p udp -s $LAN --sport $PTS -d $WEB --dport 53 -j ACCEPT
iptables -A INPUT -p udp -s $LAN --sport $PTS -d $GTW --dport 123 -j ACCEPT

# Habilita a consulta DNS para quem trabalha externo
iptables -A INPUT -p udp -i enp0s8 -s $CEX -d $EXT --dport 53 -j ACCEPT

# Habilitar acesso serviços internos
for IP in $WEB $INT
do
   for PORTAS in 22 80 443
   do
         iptables -A INPUT -p tcp -d $GTW --dport $PORTAS -j ACCEPT
   done
done

# Habilita passagem de pacotes pelo firewall para os serviços de rede (FTP, HTTP, HTTPS, ...) disponiveis em outras máquinas da rede
iptables -A FORWARD -i enp0s8 -p tcp -s $NET -m multiport --dports 21,80,443 -j ACCEPT
iptables -A FORWARD -o enp0s8 -p tcp -s $NET -m multiport --dports 21,80,443 -j ACCEPT
iptables -A FORWARD -i enp0s9 -p tcp -s $LAN -m multiport --dports 21,22,80,443,3128 -j ACCEPT
iptables -A FORWARD -o enp0s9 -p tcp -s $LAN -m multiport --dports 21,22,80,443,3128 -j ACCEPT
iptables -A FORWARD -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -p udp --sport 53 -j ACCEPT

### Regras de Passagem e NAT
# Habilita o rotemento dos pacotes
echo 1 > /proc/sys/net/ipv4/ip_forward

# 1 - Ativando o marcaramento de pacotes
iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE


# 2 - Habilita a passagem de pacotes dos serviços de rede em outros servidores
for PUDP in 53
do
iptables -t nat -A PREROUTING -p udp -i enp0s9 -s $CEX -d $EXT --dport $PUDP -j DNAT --to-destination $GTW:$PUDP
iptables -t nat -A PREROUTING -p udp -i enp0s9 -s $CEX -d $EX2 --dport $PUDP -j DNAT --to-destination $WEB:$PUDP
#iptables -t nat -A PREROUTING -p udp -s $CVP --sport $PTS -d $SVP --dport $PORTAS -j DNAT --to-destination $GTW:$PORTAS
done

# 2 - Habilita a passagem de pacotes dos serviços de rede em outros servidores
for PORTAS in 21 80 443
do
   iptables -t nat -A PREROUTING -p tcp -s $NET --sport $PTS -d $EXT --dport $PORTAS -j DNAT --to-destination $WEB:$PORTAS
done

# 3 - Habilita a acesso externo ao ssh na operacao
iptables -t nat -A PREROUTING -p tcp -s $CEX --sport $PTS -d $EXT --dport 22 -j DNAT --to-destination $OPE:22

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

        sleep 3
        clear
        echo -e "\nFirewall Ativado"
        ;;

stop)
        echo "Desativando a Firewall..."
        # Habilita o passagem de pacotes
        echo 1 > /proc/sys/net/ipv4/ip_forward
        # Politicas padroes do firewall
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -P FORWARD ACCEPT
        # Limpa todas chains
        iptables -t nat -F
        iptables -t filter -F
        iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE
        sleep 3
        clear
        echo -e "\nCuidado! Firewall Desligado..."
        ;;
        -h)
        clear
        echo -e "\n $0 start | stop | help"
        ;;
     --help)
        clear
        echo -e "*** Firewall integrado *** \n"
        echo -e "Firewall 4.0 é a junção de todos os scripts com objetivos de melhorar a proteçao\n"
        echo -e "Suas opcoes são:\n"
        echo -e "start --> libera a passagem de pacotes\n"
        echo -e "stop --> bloqueia a passagem de pacotes\n"
        echo -e "help --> Ajuda\n"
        echo -e "-h --> sintaxe\n"
        ;;
     *)
        echo -e "\nErro! $0 faltando parametro start | stop"
        ;;
esac
