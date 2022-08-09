#!/bin/bash

#title              cafe-idp-validador.sh
#description        Script de validacao de IDP CAFe - Shibboleth e suas dependencias
#author             Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor   Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date               2021/12/08
#version            4.0.0
#
#changelog          4.0.0 - 2021/12/08 - Versão inicial para Shibboleth IDP 4.


SAIDA="/root/cafe-homolog-shib4.log"
ERRO="0"

function cabecalho {
    echo ""
    echo "------------------------------------------------------------"
    echo "          RNP - Rede Nacional de Ensino e Pesquisa          "
    echo "            CAFe - Comunidade Academica Federada            "   
    echo "------------------------------------------------------------"
    echo "Script: cafe-idp-validador.sh         Versao: 4.0 08/12/2021"
    echo "------------------------------------------------------------"
    echo "Hostname: `hostname -f`"
    echo "------------------------------------------------------------"
    echo "Data e horario: `date -R`"
    echo "------------------------------------------------------------"
    echo ""
}

function rodape {
    echo ""   
    echo "------------------------------------------------------------"
    echo ""
}

function main {
 
    MSGIMPED="       Ponto impeditivo para avancar no processo de adesao."
    IP_TEST="8.8.8.8"

    clear
    cabecalho | tee -a ${SAIDA}

    echo ""
    echo "COLETANDO INFORMACOES DE REDE"
    echo ""
    HOSTN_COL=`hostname -f`
    echo "."
    OS=`lsb_release -d | awk '{ print $2" "$3" "$4}'`
    echo "."
    INT_GW=`ip r | grep default | awk '{ print $5 }'`
    echo "."
    INT_ADDR=`ip addr show ${INT_GW} | grep 'inet ' | awk '{ print $2 }' | awk -F'/' '{ print $1}'`
    echo "."
    INT_NMASK=`ip addr show ${INT_GW} | grep 'inet ' | awk '{ print $2 }' | awk -F'/' '{ print $2}'`
    echo "."
    INT_ADDR_GW=`ip r | grep default | awk '{ print $3 }'`
    echo "."
    PING_GW=`ping -c 5 $INT_ADDR_GW | grep packet | awk '{ print $6 }' | sed s/%//`
    echo "."
    PING_INTERNET=`ping -c 5 $IP_TEST | grep packet | awk '{ print $6 }' | sed s/%//`
    echo "."

    echo "CONFIGURACOES DE REDE" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}
    echo "INFO - HOSTNAME: ${HOSTN_COL}" | tee -a ${SAIDA}
    echo "INFO - SISTEMA OPERACIONAL: ${OS}" | tee -a ${SAIDA}
    echo "INFO - ENDERECO: ${INT_ADDR}" | tee -a ${SAIDA}
    echo "INFO - MASCARA: ${INT_NMASK}" | tee -a ${SAIDA}
    echo "INFO - GATEWAY: ${INT_ADDR_GW}" | tee -a ${SAIDA}
    echo "INFO - PERDA DE PACOTES GATEWAY: ${PING_GW}" | tee -a ${SAIDA}
    if [ $PING_GW -ne "0" ] ; then
        echo "$MSGIMPED"
        ERRO="1"
    fi
    echo "INFO - PERDA DE PACOTES INTERNET: ${PING_INTERNET}" | tee -a ${SAIDA}
    if [ $PING_INTERNET -ne "0" ] ; then
        echo "$MSGIMPED"
        ERRO="1"
    fi
    echo "" | tee -a ${SAIDA}

    echo "PACOTES" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}

    for i in 'apache2' 'jetty9' ; do
        PACK_TEST=`dpkg -s $i 2> /dev/null`
        if [ $? -eq "0" ] ; then
            echo "OK - Pacote $i instalado." | tee -a ${SAIDA}
        else
            echo "ERRO - Pacote $i nao esta instalado." | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    echo "" | tee -a ${SAIDA}
    echo "CONFIGURACAO JAVA/JETTY" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}

    for i in '/var/lib/jetty9/webapps/idp.xml' ; do
        XML_TEST=`xmllint $i --noout 2> /dev/null`
        if [ $? -eq "0" ] ; then
            echo "OK - Arquivo $i esta integro." | tee -a ${SAIDA}
        else
            echo "ERRO - Arquivo $i nao esta integro." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    echo "" 
    echo "CONFIGURACAO APACHE"
    echo ""
 
    if [ -e /etc/apache2/sites-available/01-idp.conf ] ; then 
        echo "OK - Arquivo 01-idp.conf existe." | tee -a ${SAIDA}
    else
        echo "ERRO - Arquivo 01-idp.conf nao existe." | tee -a ${SAIDA}
        echo "$MSGIMPED" | tee -a ${SAIDA}
        ERRO="1"
    fi

    for i in 'ssl' 'headers' 'proxy_http' ; do
        MOD_TEST=`a2query -m $i 2> /dev/null`
        if [ $? -eq "0" ] ; then
            echo "OK - Modulo $i esta ativo." | tee -a ${SAIDA}
        else
            echo "ERRO - Modulo $i nao esta ativo." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    for i in '01-idp' ; do
        MOD_TEST=`a2query -s $i 2> /dev/null`
        if [ $? -eq "0" ] ; then
            echo "OK - Site $i esta ativo." | tee -a ${SAIDA}
        else
            echo "ERRO - Site $i nao esta ativo." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    APACHE_CONF=`apache2ctl -t 2> /dev/null`
    if [ $? -eq "0" ] ; then
        echo "OK - Sintaxe dos arquivos de configuracao esta correta." | tee -a ${SAIDA}
    else
        echo "ERRO - Sintaxe dos arquivos de configuracao esta incorreta." | tee -a ${SAIDA}
        echo "$MSGIMPED" | tee -a ${SAIDA}
        ERRO="1"
    fi
  
    echo "" | tee -a ${SAIDA}
    echo "CERTIFICADOS" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}
  
    if [ -e /opt/shibboleth-idp/credentials/idp.crt ] ; then
        echo "OK - Arquivo idp.crt existe" | tee -a ${SAIDA}
        AFTER=`openssl x509 -in /opt/shibboleth-idp/credentials/idp.crt -dates | grep notAfter | awk -F= '{print $2}'`
        BEFORE=`openssl x509 -in /opt/shibboleth-idp/credentials/idp.crt -dates | grep notBefore | awk -F= '{print $2}'`
        DTAFTER=`date -d "$AFTER" +%s`
        DTBEFORE=`date -d "$BEFORE" +%s`
        DTDELTA=$(( ( $DTAFTER - $DTBEFORE ) / 86400 ))
        if [ $DTDELTA -eq 1095 ] ; then
            echo "OK - Validade do certificado do Shibboleth IdP. Recomendacao: 1095 dias. Econtrado: $DTDELTA dias." | tee -a ${SAIDA}
        else
            echo "ERRO - Certificado do Shibboleth IdP com validade diferente do especificado. Recomendacao: 1095 dias. Econtrado: $DTDELTA dias." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    else
        echo "ERRO - Arquivo idp.crt nao existe"
        ERRO="1"
    fi

    echo "" | tee -a ${SAIDA}
    echo "CONFIGURACAO SHIBBOLETH" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}

    for i in '/opt/shibboleth-idp/conf/attribute-filter.xml' '/opt/shibboleth-idp/conf/attribute-resolver.xml' '/opt/shibboleth-idp/conf/metadata-providers.xml' '/opt/shibboleth-idp/conf/saml-nameid.xml' '/opt/shibboleth-idp/conf/attributes/brEduPerson.xml' '/opt/shibboleth-idp/conf/attributes/default-rules.xml' '/opt/shibboleth-idp/conf/attributes/schac.xml' '/opt/shibboleth-idp/conf/access-control.xml' '/opt/shibboleth-idp/metadata/idp-metadata.xml'; do
        XML_TEST=`xmllint $i --noout 2> /dev/null`
        if [ $? -eq "0" ] ; then
            echo "OK - Arquivo $i esta integro." | tee -a ${SAIDA}
        else
            echo "ERRO - Arquivo $i nao esta integro." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    for i in 'credentials' 'logs' 'metadata' ; do
        PERM_TEST=`ls -lah /opt/shibboleth-idp/ | grep "^d.*jetty.*jetty.*\s*$i$"`
        if [ $? -eq "0" ] ; then
            echo "OK - Permissao correta no diretorio /opt/shibboleth-idp/$i." | tee -a ${SAIDA}
        else
            echo "ERRO - Permissao incorreta no diretorio /opt/shibboleth-idp/$i ou diretorio nao existe." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    LDAP_URL=`grep "^idp.authn.LDAP.ldapURL" /opt/shibboleth-idp/conf/ldap.properties | awk '{ print $3}'`
    LDAP_BIND_DN=`grep "^idp.authn.LDAP.bindDN" /opt/shibboleth-idp/conf/ldap.properties | awk '{ print $3}'`
    LDAP_PWD=`grep "^idp.authn.LDAP.bindDNCredential" /opt/shibboleth-idp/credentials/secrets.properties | awk '{ print $3 }'`

    LDAP_BIND=`ldapwhoami -H "${LDAP_URL}" -D "${LDAP_BIND_DN}" -w "${LDAP_PWD}"`
    if [ $? -eq "0" ] ; then
        echo "OK - Bind no LDAP realizado com sucesso." | tee -a ${SAIDA}
    else
        echo "ATENCAO - Falha ao testar bind no LDAP." | tee -a ${SAIDA}
    fi

    echo "" | tee -a ${SAIDA}
    echo "MONITORAMENTO" | tee -a ${SAIDA}
    echo "" | tee -a ${SAIDA}

    for i in 'check_idp' 'check_mem' 'check_uptime' ; do
        if [ -e /usr/lib/nagios/plugins/$1 ] ; then
            echo "OK - Arquivo /usr/lib/nagios/plugins/$i existe." | tee -a ${SAIDA}
        else
            echo "ERRO - Arquivo /usr/lib/nagios/plugins/$i nao existe." | tee -a ${SAIDA}
            echo "$MSGIMPED" | tee -a ${SAIDA}
            ERRO="1"
        fi
    done

    /usr/lib/nagios/plugins/check_idp http://${HOSTN_COL}/idp/status all | tee -a ${SAIDA}

    rodape | tee -a ${SAIDA}
    if [ $ERRO -eq 0 ] ; then
        echo "OK - Nao foram encontrados pontos impeditivos para o processo de adesao." | tee -a ${SAIDA}
        echo "     Envie o arquivo de log gerado (${SAIDA}) para o Service" | tee -a ${SAIDA}
        echo "     Desk da RNP para dar continuidade ao atendimento." | tee -a ${SAIDA}
    else
        echo "ERRO - Foram encontrados pontos impeditivos para o processo de adesao." | tee -a ${SAIDA}
        echo "       Solucione os erros e execute novamente este script." | tee -a ${SAIDA}
    fi
    rodape | tee -a ${SAIDA}
}

ami=`whoami`

if [ "$ami" == "root" ] ; then
  
    XML_PACK=`dpkg -l | grep libxml2-utils`
    if [ $? -eq 0 ] ; then
        main
    else
        clear
        cabecalho
        echo "ERRO - E necessario a presenca do pacote libxml2-utils"
        rodape
    fi
else
    clear
    cabecalho
    echo "ERRO - Voce deve executar este script com permissao de root."
    rodape
fi