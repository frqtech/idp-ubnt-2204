#!/bin/bash

#title              idp-updater.sh
#description        Update script for CAFe IDP
#author             Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor   Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date               2024/02/01
#version            1.0.0
#
#changelog          1.0.0 - 2024/02/01 - Initial version.

DEBUG="1"
F_LOG="/root/cafe-idp-updater.log"
VERSAO="1.0.0"
SYSDATE=`date +"%Y-%m-%d %H:%M:%S %z"`
SO_DISTID=`lsb_release -i | awk '{ print $3 }'` 
SO_RELEASE=`lsb_release -r | awk '{ print $2 }'`
SHIBDIR="/opt/shibboleth-idp"
SHIBVER=`${SHIBDIR}/bin/version.sh`
SHIBZIP="https://shibboleth.net/downloads/identity-provider/archive/4.3.2/shibboleth-identity-provider-4.3.2.zip"
SHIBSUM="https://shibboleth.net/downloads/identity-provider/archive/4.3.2/shibboleth-identity-provider-4.3.2.zip.sha256" 
REPOSITORY="https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main"
SRCDIR="/root/shibboleth-identity-provider-4.3.2"
RET=""

function main {

    if [ ${DEBUG} -eq 1 ] ; then
        echo "### CAFe IDP UPDATER ###" | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        echo "Data: ${SYSDATE}" | tee -a ${F_LOG}
        echo "Versão: ${VERSAO}" | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        echo "Variáveis:" | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
        echo "SO_DISTID = ${SO_DISTID}" | tee -a ${F_LOG}
        echo "SO_RELEASE = ${SO_RELEASE}" | tee -a ${F_LOG}
        echo "SHIBDIR = ${SHIBDIR}" | tee -a ${F_LOG}
        echo "SHIBVER = ${SHIBVER}" | tee -a ${F_LOG}
        echo "SHIBZIP = ${SHIBZIP}" | tee -a ${F_LOG}
        echo "SHIBSUM = ${SHIBSUM}" | tee -a ${F_LOG}
        echo "REPOSITORY = ${REPOSITORY}" | tee -a ${F_LOG}
        echo "SRCDIR = ${SRCDIR}" | tee -a ${F_LOG}
        echo "" | tee -a ${F_LOG}
    fi

    #Faz download de arquivos remotos
    wget ${REPOSITORY}/idp-updater.md5 -O /root/idp-updater.md5
    if [ $? -ne 0 ] ; then
        echo "ERRO: Falha no download do arquivo ${REPOSITORY}/idp-updater.md5." | tee -a ${F_LOG}
        exit 1
    fi

    wget ${SHIBZIP} -O /root/shibboleth-identity-provider-4.3.2.zip 
    if [ $? -ne 0 ] ; then
        echo "ERRO: Falha no download do arquivo ${SHIBZIP}." | tee -a ${F_LOG}
        exit 1
    fi

    wget ${SHIBSUM} -O /root/shibboleth-identity-provider-4.3.2.zip.sha256 
    if [ $? -ne 0 ] ; then
        echo "ERRO: Falha no download do arquivo ${SHIBSUM}." | tee -a ${F_LOG}
        exit 1
    fi

    cd /root

    #Verifica integridade deste script e do Shibboleth
    md5sum -c /root/idp-updater.md5
    if [ $? -eq 0 ] ; then
        if [ ${DEBUG} -eq 1 ] ; then
            echo "O arquivo /root/idp-updater.sh está integro." | tee -a ${F_LOG}
        fi
    else
        echo "ERRO: O arquivo /root/idp-updater.sh não está integro." | tee -a ${F_LOG}
        exit 1
    fi

    sha256sum -c /root/shibboleth-identity-provider-4.3.2.zip.sha256 
    if [ $? -eq 0 ] ; then
        if [ ${DEBUG} -eq 1 ] ; then
            echo "O arquivo /root/shibboleth-identity-provider-4.3.2.zip está integro." | tee -a ${F_LOG}
        fi
    else
        echo "ERRO: O arquivo /root/shibboleth-identity-provider-4.3.2.zip não está integro." | tee -a ${F_LOG}
        exit 1
    fi

    #Verifica a compatibilidade de versão do SO e do Shibboleth
    if [ "${SO_DISTID}" = "Ubuntu" -a \( "${SO_RELEASE}" = "20.04" -o "${SO_RELEASE}" = "22.04" \) ] ; then
        echo "INFO: Sistema operacional compatível." | tee -a ${F_LOG}

        if [ "${SHIBVER}" = "4.1.0" -o \
             "${SHIBVER}" = "4.1.1" -o \
             "${SHIBVER}" = "4.1.2" -o \
             "${SHIBVER}" = "4.1.3" -o \
             "${SHIBVER}" = "4.1.4" -o \
             "${SHIBVER}" = "4.1.5" -o \
             "${SHIBVER}" = "4.1.6" -o \
             "${SHIBVER}" = "4.1.7" -o \
             "${SHIBVER}" = "4.2.0" -o \
             "${SHIBVER}" = "4.2.1" -o \
             "${SHIBVER}" = "4.3.0" -o \
             "${SHIBVER}" = "4.3.1" \
             ] ; then

            #Faz backup da instalação atual
            tar -zcvf /opt/shibboleth-idp-backup-`date +%Y%m%d-%H%M%S`.tar.gz /opt/shibboleth-idp
            if [ $? -ne 0 ] ; then
                echo "ERRO: Falha ao fazer backup da instalação atual do Shibboleth IDP." | tee -a ${F_LOG}
                exit 1
            fi

            #Executa atualização
            unzip /root/shibboleth-identity-provider-4.3.2.zip
            ${SRCDIR}/bin/install.sh \
            -Didp.src.dir=${SRCDIR} \
            -Didp.target.dir=${SHIBDIR}
            if [ $? -eq 0 ] ; then
                echo "INFO: Atualização realizada com sucesso" | tee -a ${F_LOG}
            else
                echo "ERRO: Falha ao fazer backup da instalação atual do Shibboleth IDP." | tee -a ${F_LOG}
                exit 1
            fi

            #Corrige access-control.xml
#            cat > /opt/shibboleth-idp/conf/access-control.xml <<-EOF
#<?xml version="1.0" encoding="UTF-8"?>
#<beans xmlns="http://www.springframework.org/schema/beans"
#       xmlns:context="http://www.springframework.org/schema/context"
#       xmlns:util="http://www.springframework.org/schema/util"
#       xmlns:p="http://www.springframework.org/schema/p"
#       xmlns:c="http://www.springframework.org/schema/c"
#       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
#       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
#                           http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
#                           http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd"
#
#       default-init-method="initialize"
#       default-destroy-method="destroy">
#
#    <util:map id="shibboleth.AccessControlPolicies">
#
#        <entry key="AccessByIPAddress">
#            <bean id="AccessByIPAddress" parent="shibboleth.IPRangeAccessControl"
#                    p:allowedRanges="#{ {'127.0.0.1/32', '::1/128', '1.2.3.4/32'} }" />
#        </entry>
#
#    </util:map>
#
#</beans>
#EOF

            chown root:root /opt/shibboleth-idp/conf/access-control.xml
            chmod 644 /opt/shibboleth-idp/conf/access-control.xml

        else
            echo "ERRO: Versão do Shibboleth IDP não compatível." | tee -a ${F_LOG}
            echo "      Versão: ${SHIBVER}" | tee -a ${F_LOG}
            exit 1
        fi

    else
        echo "ERRO: Sistema operacional não compatível." | tee -a ${F_LOG}
        echo "      Distribuição: ${SO_DISTID}" | tee -a ${F_LOG}
        echo "      Release: ${SO_RELEASE}" | tee -a ${F_LOG}
        exit 1
    fi

}

ami=`whoami`

if [ "$ami" == "root" ] ; then
    main
else
    echo "ERROR - Voce deve executar este script com permissao de root." | tee -a ${F_LOG}
fi