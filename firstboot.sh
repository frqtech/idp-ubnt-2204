#!/bin/bash

#title              firstboot.sh
#description        Configuration script for CAFe IDP
#author             Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor   Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date               2022/08/08
#version            4.2.0
#
#changelog          4.0.0 - 2021/05/02 - Initial version for Ubuntu 20.04.
#changelog          4.1.0 - 2021/10/19 - Adapting to new IDP layout version.
#changelog          4.1.1 - 2022/01/26 - Shibboleth IDP 4.1.5.
#changelog          4.1.2 - 2022/04/19 - Shibboleth IDP 4.2.1.
#changelog          4.2.0 - 2022/08/08 - Initial version for Ubuntu 22.04.
#changelog          4.2.1 - 2023/02/20 - Shibboleth IDP 4.3.0.

RET=""
DEBUG="1"
F_DEBUG="/root/cafe-firstboot.debug"
REPOSITORY="https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main"
SRCDIR="/root/shibboleth-identity-provider-4.3.1"
SHIBDIR="/opt/shibboleth-idp"

function cleanup {
    cp /etc/shadow.original /etc/shadow
    mv /root/.bash_profile_old /root/.bash_profile
    echo ""
}

function ctrl_c {
    echo ""
    echo ""
    echo "ATENCAO - Você pressinou CTRL+C"
    echo ""
    while [ true ] ; do
        echo "Ao finalizar este script as configurações por ele alteradas"
        echo "(senhas, parametros do IDP, etc) retornarao ao estado inici"
        echo "al."
        echo ""
        read -p "Você realmente deseja finalizar este script (s/n):" RCTRLC
        case $RCTRLC in
            s) cleanup ; exit ;;
            n) break ;;
            *) echo "Apenas s ou n são respostas válidas" ;;
        esac
    done
}

trap ctrl_c SIGINT

function cabecalho {
    echo ""
    echo "------------------------------------------------------------"
    echo "          RNP - Rede Nacional de Ensino e Pesquisa          "
    echo "            CAFe - Comunidade Acadêmica Federada            "   
    echo "------------------------------------------------------------"
    echo "Script: firstboot.sh                  Versao: 4.0 08/08/2022"
    echo "------------------------------------------------------------"
    echo ""
    echo "ATENCAO: Voce pode interromper este script a qualquer momen-"
    echo "         to pressionando as teclas CTRL+C"
    echo ""
}

function rodape {
    echo ""   
    echo "------------------------------------------------------------"
    echo ""
}

function ler {
    read -p "$1 " VALOR
    while [ -z "$VALOR" ] ; do
        echo "O campo $2 não pode ser vazio"
        read -p "$1 " VALOR
    done
    RET=$VALOR
}

function lerIP {
    ler "$1" "$2"
    ipvalido=$(echo $RET | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$')
    while [ "$ipvalido" == "" ] ; do
        echo "ERRO - O endereço IP informado não é válido."
        ler "$1" "$2"
        ipvalido=$(echo $RET | egrep '^(([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$')
    done
}

function lerOpcoes {
    echo "${1}"
    for (( i=4 ; i <= ${#} ; i++)) ; do
        index=$(( $i - 3 ))
        echo "${index} - ${!i}"
    done
    valorValido=0
    while [ ${valorValido} -eq 0 ] ; do
        read -p "$2 " VALOR
        if [ ${VALOR} -ge 1 ] && [ ${VALOR} -le $(( ${#} - 3 )) ] ; then
            while [ true ] ; do
                read -p "O valor de $3 realmente é \"$VALOR\"? (s/n) " RESP
                case $RESP in
                    s) valorValido=1 ; break ;;
                    n) valorValido=0 ; break ;;
                    *) echo "Apenas s ou n são respostas válidas" ;;
                esac
            done
        else
            echo "Opção inválida!"
        fi
    done
    RET=$VALOR
}

function lerURL {
    ler "$1" "$2"
    urlvalida=$(echo $RET | egrep '^https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]')
    while [ "$urlvalida" == "" ] ; do
        echo "ERRO - A URL informada não é valida."
        ler "$1" "$2"
        urlvalida=$(echo $RET | egrep '^https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]')
    done
}

function setProperty {
    #Based on: https://gist.github.com/kongchen/6748525
    awk -v pat="^$1 ?=" -v value="$1 = $2" '{ if ($0 ~ pat) print value; else print $0; }' $3 > $3.tmp
    mv $3.tmp $3
}

function confirma {
    while [ true ] ; do
        read -p "O valor de $1 realmente é \"$RET\"? (s/n) " RESP
        case $RESP in
            s) break ;;
            n) ler "$3";;
            *) echo "Apenas s ou n são respostas válidas" ;;
        esac
    done
}

function confirmaIP {
    while [ true ] ; do
        read -p "O valor de $1 realmente é \"$RET\"? (s/n) " RESP
        case $RESP in
            s) break ;;
            n) lerIP "$3" "$1";;
            *) echo "Apenas s ou n são respostas válidas" ;;
        esac
    done
}

function confirmaInicio {
    echo "Antes de iniciar este processo de instalação, certifique-se"
    echo "que possui as seguintes informações:"
    echo ""
    echo "- Denominação da máquina (hostname e dominio);"
    echo "- Configuração de rede (IP, mascara de rede, gateway e DNS);"
    echo "- Dados para acesso ao diretório (tipo de diretório, endere-"
    echo "  ço, porta, uso de SSL, DN para consulta, DN do usuário de "
    echo "  leitura e senha do usuário de leitura);"
    echo "- Dados de contato da instituição (nome e e-mail dos conta-"
    echo "  tos técnico e administrativo);"
    echo "- Dados da instituição (nome da instituição, sigla, endere-"
    echo "  ço do website, dominio da instituição, departamento res-"
    echo "  ponsável pelo IDP, cidade/estado sede da instituição)."
    echo ""
    echo "Para cancelar o processo de instalação precione CTRL+C, para"
    read -p "continuar precione ENTER" 
    echo ""
}

function main {
    if ! grep -q "noninteractive" /proc/cmdline ; then
        if [ -z ${IFILE} ] ; then

            stty sane
    
            #Hostname
            echo ""
            MSG="Digite o hostname (somente o nome da maquina):"
            CMP="hostname"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            HN="$RET"

            MSG="Digite o dominio (ex.: instituicao.br):"
            CMP="dominio"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            HN_DOMAIN="$RET"

            #INTERFACE
            MSG1="Este servidor possui as seguintes interfaces de rede:"
            MSG2="Qual interface de rede deve ser utilizada?"
            CMP="interface de rede"
            OPS=(`ls /sys/class/net/`)
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" `ls /sys/class/net/`
            NRINTERFACE="${RET}"
            INTERFACE=${OPS[${ESCOLHA}]}
            
            #IP
            MSG="Digite o endereco IP:"
            CMP="IP"
            lerIP "$MSG" "$CMP"
            confirmaIP "$CMP" "$RET" "$MSG"
            IP=$RET
            
            MSG="Digite a mascara (em numero de bits significativos - ex.: digitar 24 para 255.255.255.0):"
            CMP="mascara"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            MASK=$RET
            
            MSG="Digite o gateway:"
            CMP="gateway"
            lerIP "$MSG" "$CMP"
            confirmaIP "$CMP" "$RET" "$MSG"
            GATEWAY=$RET
            
            MSG="Digite o IP do DNS primário (ex.: 8.8.8.8):"
            CMP="DNS primário"
            lerIP "$MSG" "$CMP"
            confirmaIP "$CMP" "$RET" "$MSG"
            DNS1=$RET

            MSG1="Quanto ao uso de DNS secundário:"
            MSG2="Qual a opção escolhida?"
            CMP="uso de DNS secundário"
            OPT1="Configurar"
            OPT2="Não configurar"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            USODNS2=$RET

            if [ ${USODNS2} -eq 1 ] ; then    
                MSG="Digite o IP do DNS secundário (ex.: 8.8.4.4):"
                CMP="DNS secundário"
                lerIP "$MSG" "$CMP"
                confirmaIP "$CMP" "$RET" "$MSG"
                DNS2=$RET
            else
                DNS2=""
            fi

        else
            if [ -f ${IFILE} ] ; then
                . ${IFILE}
            else
                echo ""
                echo "ERRO - O arquivo informado não existe"
                echo ""
                exit 1
            fi
        fi    
        
        if [ ${DEBUG} -eq 1 ] ; then
            echo "### FIRSTBOOT - INFORMACOES DE DEBUG ###" | tee -a ${F_DEBUG}
            echo "" | tee -a ${F_DEBUG}
            echo "Variáveis lidas:" | tee -a ${F_DEBUG}
            echo "" | tee -a ${F_DEBUG}
            echo "HN               = ${HN}" | tee -a ${F_DEBUG} 
            echo "HN_DOMAIN        = ${HN_DOMAIN}" | tee -a ${F_DEBUG}
            echo "INTERFACE        = ${INTERFACE}" | tee -a ${F_DEBUG}
            echo "IP               = ${IP}" | tee -a ${F_DEBUG}
            echo "MASK             = ${MASK}" | tee -a ${F_DEBUG}
            echo "GATEWAY          = ${GATEWAY}" | tee -a ${F_DEBUG}
            echo "DNS1             = ${DNS1}" | tee -a ${F_DEBUG}
            echo "USODNS2          = ${USODNS2}" | tee -a ${F_DEBUG}
            echo "DNS2             = ${DNS2}" | tee -a ${F_DEBUG}
        fi
        
        if [ ${USODNS2} -eq 1 ] ; then
            DNS="${DNS1}, ${DNS2}"
        else
            DNS="${DNS1}"
        fi

        cat > /etc/netplan/00-installer-config.yaml <<-EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${INTERFACE}:
      addresses: [${IP}/${MASK}]
      gateway4: ${GATEWAY}
      nameservers:
        addresses: [${DNS}]
EOF

        hostnamectl set-hostname ${HN}.${HN_DOMAIN}

        # Ajuste Stub DNS
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

    fi

    echo "Gerando novas chaves para o Servidor SSH..."
    find /etc/ssh -name "ssh_host_*_key*" -exec rm {} \;
    DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical dpkg-reconfigure openssh-server
    echo ""
    echo "Geracao de chaves finalizada"
    
    echo
    echo "Aplicando configurações de rede..."
    netplan apply
    sleep 5
    
        THRESHOLD=3
        TRY=1
       
        while [ ${TRY} -le ${THRESHOLD} ] ; do
        NETTEST=`curl -s ${REPOSITORY}/network.test`
            if [ "${NETTEST}" = "Network test OK." ] ; then
                apt update
                apt dist-upgrade -y
                break
            else
                echo "ATENCAO - Falha no teste de comunicacao de rede - ${TRY}/${THRESHOLD}"
                if [ ${TRY} -lt ${THRESHOLD} ] ; then
                    echo "          Nova tentativa em 5 segundos..."
                    sleep 5
                netplan apply
                else
                    echo ""
                    echo "ATENCAO - Nao foi possivel testar a comunicacao com a rede."
                    echo "          Nao sera executada a rotina de atualizacao dos pacotes."
                    echo ""
                    echo "          Caso queira interromper a instalacao para verificar este"
                    echo "          problema utilize o comando CTRL+C"
                    echo ""
                    read -p "          Pressione [enter] para continuar..."
               fi
            fi
            let TRY++
        done
   
    # Baixa arquivo remoto e verifica integridade para continuar a instalação
    wget ${REPOSITORY}/firstboot-complement.sh -O /usr/local/sbin/firstboot-complement.sh
    wget ${REPOSITORY}/firstboot-complement.md5 -O /usr/local/sbin/firstboot-complement.md5
    cd /usr/local/sbin/
    md5sum -c /usr/local/sbin/firstboot-complement.md5

        if [ $? -eq "0" ] ; then
        if [ ${DEBUG} -eq 1 ] ; then
            echo "O arquivo /usr/local/sbin/firstboot-complement.sh está integro." | tee -a ${F_DEBUG}
        fi
        . /usr/local/sbin/firstboot-complement.sh
    else
        if [ ${DEBUG} -eq 1 ] ; then
            echo "O arquivo /usr/local/sbin/firstboot-complement.sh não está integro." | tee -a ${F_DEBUG}
        fi
        exit 1
       fi

    # Remove permissão de execução do firstboot
    chmod -x /usr/local/sbin/firstboot.sh

    # Altera senha do usuario cafe do servidor
    getent passwd cafe > /dev/null
    if [ $? -eq 0 ] ; then
        echo ""
        echo "Digite uma nova senha para o usuario cafe:"
        while ! passwd cafe ; do : ; done
    fi
 
    # Altera senha de root do servidor
    echo ""
    echo "Digite uma nova senha para o usuario root:"
    while ! passwd ; do : ; done

    /sbin/reboot
}

ami=`whoami`
IFILE=""

#Tratamento de parâmentros
while getopts "f:" OPT; do
    case "$OPT" in
        "f") IFILE=${OPTARG} ;;
        "?") exit -1;;
    esac
done

if [ "$ami" == "root" ] ; then
    mv /root/.bash_profile /root/.bash_profile_old
    cp /etc/shadow /etc/shadow.original
    cabecalho
    confirmaInicio
    main
    rodape
else
    cabecalho
    echo "ERROR - Voce deve executar este script com permissao de root."
    rodape
fi
