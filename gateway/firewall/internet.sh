#!/bin/bash
### SCRIPT LIBERACAO DE PACOTES
### Versao 1.1
### Criado em: 21/10/2018
### Atualizado em: 26/05/2019
### Elaborado por: Prof. Robson

#Parametros Iniciais
ETH="enp0s3"
LAN="10.0.0.0/24"

# Limpa Regras
for TABELA in filter nat mangle
do
   iptables -t $TABELA -F
done

# Zerar contadores
iptables -Z

#Politica de redirecionamento de pacotes
case $1 in
   start)
        echo -e "\nAtivando a internet para rede local"
        echo 1 > /proc/sys/net/ipv4/ip_forward
        iptables -t nat -A POSTROUTING -s $LAN -o $ETH -j MASQUERADE
        sleep 3
        clear
        echo -e "\nLiberando a passagem de pacotes"
        ;;
     stop)
        echo "Desativando a internet para rede local..."
        echo 0 > /proc/sys/net/ipv4/ip_forward
        iptables -t nat -D POSTROUTING -s $LAN -o $ETH -j MASQUERADE
        sleep 3
        clear
        echo -e "\nBloqueado a passagem de pacotes"
        ;;
     -h)
        clear
        echo -e "\n $0 start | stop | help"
        ;;
     --help)
        clear
        echo -e "*** Script de liberacao de pacotes da rede local *** \n"
        echo -e "Internet é um script elaborado para liberar a passagem de pacotes entre placas de redes\n"
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
