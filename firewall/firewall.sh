#!/bin/bash 
# Atualizado em 31/08/16 por Rui Ribeiro - rui.ribeiro@cafe.rnp.br

RULES_FILE="/etc/default/firewall"

RETVAL=0

# To start the firewall 
start() {

	# Termina se nao existe iptables 
	[ -x /sbin/iptables ] || exit 0

	# Arquivo com as regras propriamente ditas 
	if [ -f "$RULES_FILE" ]; then
		echo "Carregando regras de firewall ..." 
		. $RULES_FILE
	else
		echo "Arquivo de regras inexistente: $RULES_FILE" 
		stop
		RETVAL=1
	fi

	RETVAL=0

}

# To stop the firewall 
stop() {

	echo "Removendo todas as regras de firewall ..." 
	iptables -P INPUT ACCEPT
	iptables -F
	iptables -X
	iptables -Z
	RETVAL=0

}

case $1 in

	start)
		start
		;;
	stop)
		stop
		;;
	restart)
		stop
		start
		;;
	status)
		/sbin/iptables -L
		/sbin/iptables -t nat -L
		RETVAL=0
		;;
	*)
		echo "Uso: $1 {start|stop|restart|status}" 
		RETVAL=1;;

esac

exit $RETVAL