#!/bin/bash
## Criado em: quinta-feira 28/12/2017 - 0h16
## Autor: Robson Lopes
## Rotinas administrativas da ASF.COM
## Versão 1.2

if [ `uname -a | awk -F" " '{ print $6 }'` = "Debian" ]
then
	clear
	echo "voce está em $HOSTNAME"
	systemctl restart ntp && echo "reiniciando servidor ntp..."
	sleep 10
	ntpq -c pe > /dev/null && echo "atualizando hora..." || ntpdate -u 192.168.15.1 > /dev/null 

	echo "hoje eh:" && date 
	echo "testando conectividade com a infra da asf.com..."
	ping 192.168.15.1 -qc1 > /dev/null && echo "Gateway......UP" || echo "Gateway......DOWN"
	ping 192.168.15.10 -qc1 > /dev/null && echo "Intranet.....UP" || echo "Intranet.....DOWN"
	ping 192.168.15.20 -qc1 > /dev/null && echo "Datacenter...UP" || echo "Datacenter...DOWN"
	ping 192.168.15.30 -qc1 > /dev/null && echo "Storage......UP" || echo "Storage......DOWN"

	echo "testando conexão com a Internet"
	ping 4.2.2.2 -qc1 > /dev/null && echo "Internet.....UP" || "Internet.....DOWN" 
	if [ $? = 0 ] 
	then
		sleep 5
		echo "atualizando repositorio..." && aptitude -y upgrade > /dev/null
	else
		echo "Verifique configuracao da rede."
	fi
else
	clear
	echo "voce está em $HOSTNAME"
	systemctl restart ntpd && echo "reiniciando servidor ntp..."
	sleep 10
	ntpq -c pe > /dev/null && echo "atualizando hora..." || ntpdate -u pool.ntp.br > /dev/null 
	echo "hoje eh:" && date 

	echo "testando conectividade com a infra da asf.com..."
	ping 192.168.15.1 -qc1 > /dev/null && echo "Gateway......UP" || echo "Gateway......DOWN"
	ping 192.168.15.10 -qc1 > /dev/null && echo "Intranet.....UP" || echo "Intranet.....DOWN"
	ping 192.168.15.20 -qc1 > /dev/null && echo "Datacenter...UP" || echo "Datacenter...DOWN"
	ping 192.168.15.30 -qc1 > /dev/null && echo "Storage......UP" || echo "Storage......DOWN"

	echo "testando conexão com a Internet"
	ping 4.2.2.2 -qc1 > /dev/null && echo "Internet.....UP" || "Internet.....DOWN" 
	if [ $? = 0 ]
	then
		sleep 5
		echo "atualizando repositorio..." && yum -y update > /dev/null
	else
		echo "Verifique configuracao da rede."
	fi
fi																																														
