#!/bin/bash
######## Firewall ########
# IFSP Câmpus Guarulhos  #
# Autor Robson Lopes     #
# Disciplina SOPD2       #
# Versao 4.2             #
##########################

# Configuracoes iniciais
#Rede Interna
GTW="192.168.255.101"
APL="192.168.255.102"
OPE="192.168.255.151"
LAN="192.168.255.0/24"
PTS="1024:65535"
NET="0/0"

#Link Dedicado (WAN)
EXT="200.0.0.100"
CEX="200.0.0.150"
WAN="200.0.0.0/24"

for TABELA in filter nat mangle
do
	iptables -t $TABELA -F
done

# Zera os contadores do iptables
iptables -Z

case $1 in
   start)
        echo -e "\nAtivando a passagem de pacotes."
        echo -e "\nRedirecionamento para o Servidor WEB"

        # 1 -  Habilita o rotemento dos pacotes
        echo 1 > /proc/sys/net/ipv4/ip_forward

        # 2 - Ativando o marcaramento de pacotes
        iptables -t nat -A POSTROUTING -s $LAN -o enp0s3 -j MASQUERADE

        # 3 - Habilita a acesso aos serviços de rede
        for PORTAS in 80
        do
        iptables -t nat -A PREROUTING -p tcp -s $NET --sport $PTS -d $EXT --dport $PORTAS -j DNAT --to-destination $APL:$PORTAS
        done
        # 4 - Habilita a acesso externo ao ssh na operacao
        iptables -t nat -A PREROUTING -p tcp -s $CEX --sport $PTS -d $EXT --dport 22 -j DNAT --to-destination $OPE:22

        sleep 3
        clear
        echo -e "\nPassagem de pacotes e servidor WEB Ativados"
        ;;
    close)
        echo "Parando redirecionamento para Servidor WEB"
        # Limpa todas chains
        iptables -t nat -F
        iptables -t filter -F
        sleep 3
        clear
        echo -e "\nCuidado! Firewall Desligado..."
        ;;
    stop)
        echo "Desativando acesso da LAN a internet..."
        # 1- Desafivando a passagem de pacotes
        echo 0 > /proc/sys/net/ipv4/ip_forward
        # Limpa todas chains
        iptables -t nat -F
        iptables -t filter -F
        sleep 3
        clear
        echo -e "\nLAN com Acesso a internet desativado..."
        ;;
        -h)
        clear
        echo -e "\n $0 start | close | stop | help"
        ;;
    --help)
        clear
        echo -e "*** Firewall básico para sistema operacional *** \n"
        echo -e "FBSO é um script básico de firewall que libera \n"
        echo -e "a passagem de pacotes entre as placas de rede e\n"
        echo -e "e o redirecionamento para que o servidor WEB\n"
        echo -e "possa ser acessado da Internet.\n"
        echo -e "Suas opcoes são:\n"
        echo -e "start --> libera a passagem de pacotes\n"
        echo -e "close --> fecha o redirecionamento para servidor WEB\n"
        echo -e "stop --> bloqueia a passagem de pacotes\n"
        echo -e "help --> Ajuda\n"
        echo -e "-h --> sintaxe\n"
        ;;
     *)
        echo -e "\nErro! $0 faltando parametro start | stop | close"
        ;;
esac
