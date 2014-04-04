#!/bin/bash

#
#Version 3.1.1
#

#Configuraci¢n general del script

#----Interfaces por defecto-----#
## Interface externa (usada, si EXTIF si no se pasa como parametro)
## Es la interface utilizada para conectarse a internet 
DEFAULT_EXTIF="eth1"

## Interface interna (usada, si INTIF si no se pasa como parametro)
## Es la interface que se conecta a la red interna
DEFAULT_INTIF="eth0"

#----DansGuardian instalado-----#
## Configurar con "SI" o "NO" 
DANSGUARDIAN="NO"

##Puerto donde escucha el dansguardian
DANS_PORT=8080

#----Ubicacion del comando-----#
# Lugar donde se encuentra el comando IPTABLES
IPTABLES="/sbin/iptables"

# Lugar donde se encuentra el comando SQUID
SQUID="/usr/sbin/squid"

#----Puerto donde escucha el Squid-----#
SQUID_PORT=3128

#----Tiempo en segundos para re-escanaer los dominios-----#
TIMEOUT=300

#----Tiempo en DIAS de expiraci¢n de una IP resuelta por los DNS-----#
EXPIRE=30

#----Directorio de configuraci¢n del squid----#
SQUID_DIR="/etc/squid/"

#####################################################################
#####################################################################
#####################################################################
#####################################################################

##----Variables internas NO MODIFICAS SI NO ESTAS SEGURO

# IP para todo el mundo
UNIVERSE="0.0.0.0/0"

# Especificacion para puertos altos
UNPRIVPORTS="1024:65535"

#Directorio de trabajo
DIRNAME=$(dirname $0)

#Directorio de permitidos
PERM_DIR="permitidos"

#Directorio de procesamiento
PROC_DIR=".ip"

#Tiempo inicial de verificacion de dominios
TIME=1

#Defino el archivo de log
LOG=/var/log/firewall.log

####################################################################
#
# Definicion de funciones
#
####################################################################

#Funcion que arma el listado de IPs y Redes para habilitar en el squid
function actualizasquid() {

	#Tomo las IPs_Habilitadas
	cat $DIRNAME/$PERM_DIR/$PROC_DIR/.ip $DIRNAME/$PERM_DIR/$PROC_DIR/* | cut -d: -f 1 | grep -v \/ > $SQUID_DIR/ips_habilitadas

	#Tomo las redes habilitadas
	echo 172.16.0.0/16 > $SQUID_DIR/redes_habilitadas
	cat $DIRNAME/$PERM_DIR/$PROC_DIR/.ip | cut -d: -f 1 | grep \/ >> $SQUID_DIR/redes_habilitadas

	#Reconfiguro el squid
	$SQUID -k reconfigure
}


#####################################################################
#####################################################################
#####################################################################

# Verifico la opci¢n de arranque pasada (start, stop, etc..)
case "$1" in

	stop)
	
	#Verifico si el firewall se encuentrea activo
	if [ -f /var/run/$0 ]; then

		#Mato el proceso
		kill $(cat /var/run/$0) &> /dev/null
		rm /var/run/$(basename $0) &> /dev/null

	 fi

	#Registro en el log
	echo $(date +%Y-%m-%d-%H:%M) - Firewall Detenido >> $LOG

	$IPTABLES -F
	$IPTABLES -F -t nat
	$IPTABLES -X
	$IPTABLES -X -t nat 
	$IPTABLES -P INPUT ACCEPT
	$IPTABLES -P OUTPUT ACCEPT
	$IPTABLES -P FORWARD ACCEPT
	;;

status)
	echo $"Tabla: filter"
	iptables --list -n
	echo ""
	echo $"Tabla: nat"
	iptables -t nat --list -n
	;;

restart|reload)
	$0 stop
	$0 start
	;;

start)
	#Verifico si el firewall se encuentrea activo
	if [ -f /var/run/$0 ]; then
		$0 stop		
	fi
	echo "Arrancando el Firewall..."
	echo ""


##--------------------------Comienzo Firewall---------------------------------##
#----Idedntificacion automatica de las interfaces-----#

### Interface Externa:

## Toma la interface de la linea de comandos
## Si no se especifica se toma de la variable $DEFAULT_EXTIF 
## y se asigna a EXTIF
if [ "x$2" != "x" ]; then
	EXTIF=$2
else
	EXTIF=$DEFAULT_EXTIF
fi
echo Interface externa: $EXTIF

## Determino la IP externa
EXTIP="`ip addr show dev $EXTIF | grep global | cut -d/ -f1 | cut -d\  -f6`"
if [ "$EXTIP" = '' ]; then
	echo "Cancelando...: No se puede deeterminar la direccion IP de $EXTIF !"
	exit 1
fi
echo IP externa: $EXTIP

## Determino el gateway externo
EXTGW=$(ip r | grep default | cut -d\  -f3)
echo GW por defecto: $EXTGW

echo " --- "

### Interface interna:LAN

## Toma la interface de la linea de comandos
## Si no se especifica se toma de la variable $DEFAULT_OCINTIF 
## y se asigna a INTIF
if [ "x$3" != "x" ]; then
	INTIF=$3
else
	INTIF=$DEFAULT_INTIF
fi
echo Interface interna: $INTIF

## Determine internal IP
INTIP="`ip addr show dev $INTIF | grep global | cut -d/ -f1 | cut -d\  -f6`"
if [ "$INTIP" = '' ]; then
	echo "Cancelando...: No se puede deeterminar la direccion IP de $INTIF !"
	exit 1
fi
echo IP interna: $INTIP

## Determino la direccion de red de la red interna
INTLAN=$(ip route list scope link | grep "proto kernel" | grep $INTIF| cut -d\  -f1 )
echo RED interna: $INTLAN

echo ""

#Registro en el log
echo "" >> $LOG
echo $(date +%Y-%m-%d-%H:%M) - Iniciando Firewall >> $LOG
	
##Determino el puesto de redireccion para el trafico HTTP
REDIRECT_PORT=$SQUID_PORT

if [ $DANSGUARDIAN = "SI" ]; then
	REDIRECT_PORT=$DANS_PORT
fi


#----Reseteo y borro todas las cadenas que puedan estar definidas-----#

#Limpio todas las reglas/cadenas de IPTABLES

#Flush 
$IPTABLES -F
$IPTABLES -F -t nat

#Delete
$IPTABLES -X
$IPTABLES -X -t nat

echo " --- "

#----Creacion delas reglas-----#
echo "Implementando las reglas del firewall ..."


#######################
## Reglas de INPUT ##
#######################

# Verifico si el servidor es virtualizado
ping -c1 -w1 host.miescuela.local &> /dev/null

if [ $? = 0 ]; then 

	#Bloqueo ssh si no viene del host.miescuela.local
	$IPTABLES -A INPUT -p tcp ! -s host.miescuela.local --dport 22 -j DROP 

else

	#Bloqueo ssh si no viene del host.miescuela.local
	$IPTABLES -A INPUT -p tcp -s $INTLAN --dport 22 -j DROP 

fi

###################
##POSTROUTING##
###################


# COLOCAR LAS REGLAS ESPECIFICAS A PARTIR DE ESTE LUGAR
#
#
#


#Nateo de una maquina espec¡fica
#Masquerade para maquinas de la red interna hacia Internet ( Cambiar IP_MAQUINA )
#	$IPTABLES -A POSTROUTING -t nat -s IP_MAQUINA -o $EXTIF -j MASQUERADE

#Nateo de puertos espec¡ficos
#Enmascaramiento para el puerto 25 (smtp) 
#	$IPTABLES -A POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF --dport 25 -j MASQUERADE

#Enmascaramiento para el puerto 110 (POP)
#	$IPTABLES -A POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF --dport 110 -j MASQUERADE


#
#
#
# FIN REGLAS ESPECIFICAS


#Redirecciono el trafico http al PROXY o DANSGUARDIAN
$IPTABLES -A PREROUTING -t nat -p tcp -i $INTIF ! -d $INTIP --dport http -j REDIRECT --to $REDIRECT_PORT

# Redirijo los pedidos directos al proxy squid al DANSGUARDIAN. SI se encuentra definido DANSGUARDIAN="SI"
# Con esta regla evito que alguien desde la Red Interna saltee el control de contenidos. Por ejemplo
# Si alguien en la RED Interna configura el proxy en el browser saltearia el DANSGUARDIAN.
if [ $DANSGUARDIAN = "SI" ]; then

	$IPTABLES -A PREROUTING -t nat -p tcp -i $INTIF -d $INTIP --dport $SQUID_PORT -j REDIRECT --to $REDIRECT_PORT

fi
	
#Verifico si existe el directorio permitidos
if [ ! -d $DIRNAME/$PERM_DIR ]; then

	# Renombro el archivo permitidos
	mv $DIRNAME/$PERM_DIR $DIRNAME/$PERM_DIR.conf &> /dev/nul

	# Creo el directorio permitidos
	mkdir $DIRNAME/$PERM_DIR

	# Muevo el archivo de permitidos al directorio permitidos
	mv $DIRNAME/$PERM_DIR.conf $DIRNAME/$PERM_DIR &> /dev/null

fi

#Verifico si existe el directorio permitidos por ip
if [ ! -d $DIRNAME/$PERM_DIR/$PROC_DIR ]; then

	# Creo el directorio permitidos
	mkdir $DIRNAME/$PERM_DIR/$PROC_DIR

fi

# Habilitaci¢n de destinos espec¡ficos para trafico https. Si se encuentra definido el archivo "permitidos"
# Verifico si existe algun archivo de dominios o ips pemitidas
ls -1 $DIRNAME/$PERM_DIR/*.conf &> /dev/null

if [ "$?" = "0" ]; then

	#Tomo el pid del proceso
	PID=$(echo $$)

	#Guardo el pid
	echo $$ > /var/run/$0

	#Optengo la cantidad de direcciones ip a preocesar
	CANTIP=0

	#Borro el archivo de ips definidos en los .conf
	echo "" > $DIRNAME/$PERM_DIR/$PROC_DIR/.ip

	#Verifico si esxiten archivos para procesar
	ls -1 $DIRNAME/$PERM_DIR/$PROC_DIR/* &> /dev/null
	if [ $? = 0 ]; then

		#Registro de log
		echo $(date +%Y-%m-%d-%H:%M) - Cargando IPs previamente calculadas  >> $LOG

		# Bucle para buscar los dominios permitidos
		for i in $(cat $DIRNAME/$PERM_DIR/*.conf | grep -v \#); do
		
			# Recorro las IP del dominio ya calculados
			for j in $( cat $DIRNAME/$PERM_DIR/$PROC_DIR/${i} 2> /dev/null | cut -d\: -f1); do

				#Cargo la regla de acceso
	 	 		$IPTABLES -A POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF -d $j --dport 443 -j MASQUERADE

				#Incremento el contador
				let CANTIP=CANTIP+1

			done

		done

		#Registro de log
		echo $(date +%Y-%m-%d-%H:%M)" -      Cantidad de IPs habilitadas: " $CANTIP  >> $LOG

	fi

	#Bucle para la habilitacion de los dominios definidos
	while $(sleep $TIME); do

		#Tomo la fecha y hora actual
		TIMESTAMP=$(date +%Y%m%d%H%M)

		for a in $(ls -1 $DIRNAME/$PERM_DIR/*.conf); do

			#Muestro mensaje sobre el archivo de configuracion que se esta procesando
			echo $(date +%Y-%m-%d-%H:%M) - "Procesando -> "$( basename ${a} ) >> $LOG

			# Recorro el archivo .conf 
			for i in $(cat ${a} | grep -v \#); do

				# Registro analizado
				echo $(date +%Y-%m-%d-%H:%M) - "   Dominio -> "${i} >> $LOG

				#Determino si es un dominio o una IP o una red
				echo ${i} | grep -oE "([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/2[5-9]|/30)?$" > /dev/null
				if [ "$?" != "0" ]; then

					#Determino el rango de ips
					RANGO=$(host $i | grep address | grep -v IPv6 | cut -d\  -f4 )

					#Verifico si es un dominio valido
					if [ "$RANGO" = "" ]; then

						#Registro en el log
						echo $(date +%Y-%m-%d-%H:%M)" *        NO SE PUDO RESOLVER EL DOMINIO - ESTO PUEDE SER UN ERROR TEMPORAL"  >> $LOG

					else

						#Verifico si esxiste el archivo de IPs del Dominio
						if [ ! -f $DIRNAME/$PERM_DIR/$PROC_DIR/${i} ]; then touch $DIRNAME/$PERM_DIR/$PROC_DIR/${i};fi

						# Recorro las direcciones obtenidas
						for j in $RANGO; do

							#Verifico si es una IP existente en cualquier dominio
							grep $j: $DIRNAME/$PERM_DIR/$PROC_DIR/* > /dev/null
							if [ $? != 0 ]; then
		
								#Agrego la IP nueva a la tabla
								echo $j:$TIMESTAMP >> $DIRNAME/$PERM_DIR/$PROC_DIR/${i}

								#Registro en el log
								echo $(date +%Y-%m-%d-%H:%M) -"       IP: "$j agregada al dominio: ${i} >> $LOG

								#Verifico si la misma fue agregada manualmente para no agregarla 2 veces
								grep $j $DIRNAME/$PERM_DIR/$PROC_DIR/.ip > /dev/null
								if [ $? != 0 ]; then

									#Genero la regla para la nueva IP
									$IPTABLES -A POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF -d $j --dport 443 -j MASQUERADE

									#Actualizo el squid
									actualizasquid

								fi

							else
					
								#Actualizo su timestamp
								sed -i 's/'${j}':.*/'${j}'\:'${TIMESTAMP}'/g' $DIRNAME/$PERM_DIR/$PROC_DIR/* &> /dev/null

							fi

				 		done

					fi

				else

					#Verifico si es una IP existente en alguno de los dominios analizados
					grep $i: $DIRNAME/$PERM_DIR/$PROC_DIR/* > /dev/null
					if [ $? != 0 ]; then
						
						#Verifico si la IP ya fue procesada
						grep $i: $DIRNAME/$PERM_DIR/$PROC_DIR/.ip > /dev/null
						if [ $? != 0 ]; then

							#Genero la regla para la nueva IP
							$IPTABLES -A POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF -d $i --dport 443 -j MASQUERADE

							#Agrego la IP nueva a la tabla
							echo $i:$TIMESTAMP >> $DIRNAME/$PERM_DIR/$PROC_DIR/.ip

							#Actualizo el squid
							actualizasquid

						fi

					else

						#Registro en el log
						echo $(date +%Y-%m-%d-%H:%M)" *        DIRECCION IP YA ANALIZADA LA MISMA SE DEBERIA BORRAR"  >> $LOG
						
					fi

				fi

			done

		done

		#Elimino las entradas que tienen mas de un mes
		EXPIREDATE=$( date --date=$EXPIRE" days ago" +%Y%m%d%H%M )

		for n in $(ls -1 $DIRNAME/$PERM_DIR/$PROC_DIR/*); do

			#Tomo la longitud del archivo
			SIZE=$(stat -c%s ${n})

			if [ $SIZE -lt 8 ]; then

				#Borro el archivo
				rm ${n}

			else

				#Bucle para eliminar las entradas viejas
				for j in $(cat ${n}); do
							
					#Tomo la fecha de actualizacion
					ACT_DATE=$(echo ${j} | cut -d\: -f2)

					#Verifico si la fecha de actualizacion esta vencida
					if [ $ACT_DATE -lt $EXPIREDATE ]; then
								
						#Tomo la ip
						IP=$(echo ${j} | cut -d\: -f1)

						#Elimino la entrada
						sed -i '/'${IP}':.*/d' ${n}

						#Elimino la regla para esa IP
						$IPTABLES -D POSTROUTING -t nat -p tcp -s $INTLAN -o $EXTIF -d $IP --dport 443 -j MASQUERADE

						#Registro en el log
						echo $(date +%Y-%m-%d-%H:%M)" * IP: $IP tiempo expirado en -> "$(basename ${n}) >> $LOG

					fi

				done

			fi

		done

		#Seteo el tiempo de espera
		TIME=$TIMEOUT
		
		#Registro en el log
		echo $(date +%Y-%m-%d-%H:%M) - Esperando $TIMEOUT segundos para analizar nuevamente los dominios >> $LOG
		echo "" >> $LOG

	done

else

	echo ""
	echo "ATENCION - ATENCION - ATENCION - ATENCION"
	echo "ATENCION - ATENCION - ATENCION - ATENCION"
	echo "ATENCION - ATENCION - ATENCION - ATENCION"
	echo "ATENCION - ATENCION - ATENCION - ATENCION"
	echo ""
	echo "No se han definidos dominios https"
	echo ""
	echo "FIREWALL NO RESIDENTE"
fi


##--------------------------------End Firewall---------------------------------##

	;;
	*)
	 echo "Usar: firewall.sh (start|stop|restart|status) EXTIF INTIF"
	 exit 1
esac

exit 0

