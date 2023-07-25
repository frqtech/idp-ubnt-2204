#!/bin/bash

#title                  firstboot-complement.sh
#description            Complement script for CAFe IDP firstboot.sh
#author                 Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#lastchangeauthor       Rui Ribeiro - rui.ribeiro@cafe.rnp.br
#date                   2022/08/08
#version                2.3.0
#
#changelog              1.0.0 - 2018/10/18 - Initial version for Ubuntu 18.04.
#changelog              1.0.1 - 2019/07/12 - Adequation of certificate generation considering the new package version. 
#changelog              1.0.2 - 2019/07/31 - Added SIRTFI pre-configuration and corrected directory permissions.
#changelog              1.0.2 - 2019/07/31 - Correcao do path do java jre.
#changelog              1.0.2 - 2019/07/31 - Correcao da permissao do idp.key e idp.crt para 644.
#changelog              1.0.2 - 2019/07/31 - Added F-Ticks pre-configuration and corrected directory permissions.
#changelog              1.0.3 - 2020/01/27 - Added scapes for rsyslog.conf file.
#changelog              1.0.4 - 2020/02/06 - General improvement in rsyslog.conf file.
#changelog              1.0.4 - 2020/02/06 - General improvement in rsyslog.conf file.
#changelog              2.0.0 - 2021/05/02 - Initial version for Ubuntu 20.04.
#changelog              2.1.0 - 2021/10/19 - Changes related to new IDP Layout version.
#changelog              2.2.0 - 2021/11/05 - General improvement in metadata and monitoring.
#changelog              2.2.1 - 2022/01/26 - Security improvements.
#changelog              2.3.0 - 2022/08/08 - Initial version for Ubuntu 22.04.

#
# COLETA DE DADOS
#
        if [ -z ${IFILE} ] ; then

            stty sane
    
            #DIRETORIO
            MSG1="Este instalador suporta dois tipos de servidor de diretório:"
            MSG2="Qual o diretório utilizado pela instituição?"
            CMP="tipo de diretório"
            OPT1="AD"
            OPT2="LDAP"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            DIRETORIO="${RET}"

            if [ ${DIRETORIO} -eq 1 ] ; then
                MSG="Digite o dominio AD que será utilizado (ex.: ad.instituicao.br):"
                CMP="dominio AD"
                ler "$MSG" "$CMP"
                confirma "$CMP" "$RET" "$MSG"
                LDAPADDOMAIN="$RET"
            else
                LDAPADDOMAIN=""
            fi

            MSG="Digite o endereco do servidor de diretório (ex.: dc01.ad.instituicao.br ou ldap1.instituicao.br):"
            CMP="endereço do servidor de diretório"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPSERVER="$RET"
            
            MSG="Digite a porta do servidor de diretório (ex.: 389):"
            CMP="porta servidor de diretório"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPSERVERPORT=$RET
            
            MSG1="Escolha uma das opões com relação a configuração de SSL do servidor de diretório:"
            MSG2="O diretório indicado utiliza SSL?"
            CMP="uso de SSL"
            OPT1="Utiliza SSL"
            OPT2="Não utiliza SSL"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            LDAPSERVERSSL=$RET
            
            MSG="Digite o DN para consulta no servidor de diretório (ex.: CN=Users,DC=instituicao,DC=br e ou=People,dc=instituicao,dc=br):"
            CMP="DN"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPDN=$RET
            
            MSG="Digite o DN do usuários de leitura no servidor de diretório (ex.: conta_servico@instituicao.br ou cn=leitor-shib,dc=instituicao,dc=br):"
            CMP="DN do usuários de leitura"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPUSER=$RET
            
            MSG="Digite a senha do usuário de leitura do servidor de diretório:"
            CMP="senha"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            LDAPPWD=$RET
            
            # Dados Gerais
            echo ""
            
            MSG="Digite o nome do contato tecnico do servico (ex.: Joao da Silva):"
            CMP="nome do contato tecnico"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CONTACT=$RET
            
            MSG="Digite o e-mail do contato tecnico do servico (ex.: joao.silva@instituicao.br):"
            CMP="e-mail"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CONTACTMAIL=$RET
            
            MSG="Digite o nome da instituicao por exetenso (ex.: Rede Nacional de Ensino e Pesquisa):"
            CMP="nome da instituicao"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            ORGANIZATION=$RET

            MSG="Digite a sigla da instituicao (ex.: RNP):"
            CMP="nome da instituicao"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            INITIALS=$RET

            MSG="Digite o endereco do site da instituicao (ex.: www.instituicao.br):"
            CMP="endereco do site"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            URL=$RET

            MSG="Digite o dominio da instituicao (ex.: instituicao.br):"
            CMP="dominio"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            DOMAIN=$RET
            
            MSG="Digite o nome departamento da instituicao que eh responsavel por este servico (ex.: CPD):"
            CMP="departamento"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            OU=$RET
            
            MSG="Digite o nome da cidade onde esta sediada a instituicao (ex.: Porto Alegre):"
            CMP="cidade"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            CITY=$RET

            MSG="Digite a sigla da Unidade Federativa onde esta sediada a instituicao (ex.: RS para Rio Grande do Sul):"
            CMP="Unidade Federativa"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            UF=$RET

            MSG="Digite o texto a ser exibido para o usuário de forma que ele saiba o que deve preencher para se autenticar (ex.: Seu email @rnp.br):"
            ler "$MSG" "$CMP"
            confirma "$CMP" "$RET" "$MSG"
            MSG_AUTENTICACAO=$RET

            MSG1="Link de recuperação de senha (ex.: https://urlpaginarecuperacaodesenha.instituicao.br):"
            MSG2="A instituicao possui uma pagina para recuperacao de senha?"
            CMP="SIM/NAO"
            OPT1="SIM"
            OPT2="NAO"
            lerOpcoes "${MSG1}" "${MSG2}" "${CMP}" "${OPT1}" "${OPT2}"
            MSG_URL_RECUPERACAO_SENHA_SIM="${RET}"

            if [ ${MSG_URL_RECUPERACAO_SENHA_SIM} -eq 1 ] ; then
                MSG="Digite a url para a pagina de recuperacao de senha (ex.: https://urlpaginarecuperacaodesenha.instituicao.br):"
                CMP="URL página recuperacao de senha"
                lerURL "$MSG" "$CMP"
                confirma "$CMP" "$RET" "$MSG"
                MSG_URL_RECUPERACAO_SENHA=$RET
            else
                MSG_URL_RECUPERACAO_SENHA=""
            fi

            if [ ${DIRETORIO} -eq 1 ] ; then
                LDAPATTR="sAMAccountName"
                LDAPFORM="%s@${LDAPADDOMAIN}"
                LDAPSUBTREESEARCH="true"
            else
                LDAPATTR="uid"
                LDAPFORM="${LDAPATTR}=%s,${LDAPDN}"
                LDAPSUBTREESEARCH="true"
            fi

            if [ ${LDAPSERVERSSL} -eq 1 ] ; then
                LDAPSERVERSSLUSE="true"
                LDAPSERVERPROTO="ldaps://"
            else
                LDAPSERVERSSLUSE="false"
                LDAPSERVERPROTO="ldap://"
            fi
            
            UFUPPER=`echo ${UF} | sed 'y/áÁàÀãÃâÂéÉêÊíÍóÓõÕôÔúÚçÇ/aAaAaAaAeEeEiIoOoOoOuUcC/' | sed 's/[^a-zA-Z]//g' | tr [a-z] [A-Z]`
            POLLER=""

            case $UFUPPER in
                "AC") STATE="ACRE" ; POLLER="200.139.7.155" ;;
                "AL") STATE="ALAGOAS" ; POLLER="200.17.116.88" ;;
                "AP") STATE="AMAPA" ; POLLER="200.129.167.57" ;;
                "AM") STATE="AMAZONAS" ; POLLER="200.129.156.99" ;;
                "BA") STATE="BAHIA" ; POLLER="200.128.2.8" ;;
                "CE") STATE="CEARA" ; POLLER="200.129.0.78" ;;
                "DF") STATE="DISTRITO FEDERAL" ; POLLER="200.130.35.155" ;;
                "ES") STATE="ESPIRITO SANTO" ; POLLER="200.137.76.148" ;;
                "GO") STATE="GOIAS" ; POLLER="200.18.160.2" ;;
                "MA") STATE="MARANHAO" ; POLLER="200.137.129.30" ;;
                "MG") STATE="MATO GROSSO" ; POLLER="200.129.240.123" ;;
                "MS") STATE="MATO GROSSO DO SUL" ; POLLER="200.129.207.181" ;;
                "MG") STATE="MINAS GERAIS" ; POLLER="200.131.2.173" ;;
                "PA") STATE="PARA" ; POLLER="200.129.149.55" ;;
                "PB") STATE="PARAIBA" ; POLLER="200.129.64.151" ;;
                "PR") STATE="PARANA" ; POLLER="200.134.255.33" ;;
                "PE") STATE="PERNANBUCO" ; POLLER="200.133.0.40" ;;
                "PI") STATE="PIAUI" ; POLLER="200.137.160.141" ;;
                "RR") STATE="RORAIMA" ; POLLER="200.129.139.172" ;;
                "RO") STATE="RONDONIA" ; POLLER="200.129.143.210" ;;
                "RJ") STATE="RIO DE JANEIRO" ; POLLER="200.159.254.108" ;;
                "RN") STATE="RIO GRANDE DO NORTE" ; POLLER="200.137.0.199" ;;
                "RS") STATE="RIO GRANDE DO SUL" ; POLLER="200.132.1.92" ;;
                "SC") STATE="SANTA CATARINA" ; POLLER="200.237.193.28" ;;
                "SP") STATE="SAO PAULO" ; POLLER="200.133.192.42" ;;
                "SE") STATE="SERGIPE" ; POLLER="200.17.118.192" ;;
                "TO") STATE="TOCANTINS" ; POLLER="200.139.26.32" ;;
                *) STATE="NULL" ; POLLER="NULL" ;;
            esac

            PERSISTENTDIDSALT=`openssl rand -base64 32`
            COMPUTEDIDSALT=`openssl rand -base64 32`
            FTICKSSALT=`openssl rand -base64 32`

        fi

#
# DEBUG
#
        if [ ${DEBUG} -eq 1 ] ; then
            echo "### FIRSTBOOT COMPLEMENT - INFORMACOES DE DEBUG ###" | tee -a ${F_DEBUG}
            echo "" | tee -a ${F_DEBUG}
            echo "Variáveis lidas:" | tee -a ${F_DEBUG}
            echo "DIRETORIO                 = ${DIRETORIO}" | tee -a ${F_DEBUG}
            echo "LDAPADDOMAIN              = ${LDAPADDOMAIN}" | tee -a ${F_DEBUG}
            echo "LDAPSERVER                = ${LDAPSERVER}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERPORT            = ${LDAPSERVERPORT}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERSSL             = ${LDAPSERVERSSL}" | tee -a ${F_DEBUG} 
            echo "LDAPSERVERSSLUSE          = ${LDAPSERVERSSLUSE}" | tee -a ${F_DEBUG}
            echo "LDAPSERVERPROTO           = ${LDAPSERVERPROTO}" | tee -a ${F_DEBUG}
            echo "LDAPDN                    = ${LDAPDN}" | tee -a ${F_DEBUG}
            echo "LDAPUSER                  = ${LDAPUSER}" | tee -a ${F_DEBUG}
            echo "LDAPPWD                   = ${LDAPPWD}" | tee -a ${F_DEBUG}
            echo "CONTACT                   = ${CONTACT}" | tee -a ${F_DEBUG}
            echo "CONTACTMAIL               = ${CONTACTMAIL}" | tee -a ${F_DEBUG}
            echo "ORGANIZATION              = ${ORGANIZATION}" | tee -a ${F_DEBUG}
            echo "INITIALS                  = ${INITIALS}" | tee -a ${F_DEBUG}
            echo "URL                       = ${URL}" | tee -a ${F_DEBUG}
            echo "DOMAIN                    = ${DOMAIN}" | tee -a ${F_DEBUG}
            echo "OU                        = ${OU}" | tee -a ${F_DEBUG}
            echo "CITY                      = ${CITY}" | tee -a ${F_DEBUG}
            echo "UF                        = ${UF}" | tee -a ${F_DEBUG}
            echo "UFUPPER                   = ${UFUPPER}" | tee -a ${F_DEBUG}
            echo "STATE                     = ${STATE}" | tee -a ${F_DEBUG}
            echo "POLLER                    = ${POLLER}" | tee -a ${F_DEBUG}
            echo "MSG_AUTENTICACAO          = ${MSG_AUTENTICACAO}" | tee -a ${F_DEBUG}
            echo "MSG_URL_RECUPERACAO_SENHA = ${MSG_URL_RECUPERACAO_SENHA}" | tee -a ${F_DEBUG}            
            echo "COMPUTEDIDSALT            = ${COMPUTEDIDSALT}" | tee -a ${F_DEBUG}
            echo "PERSISTENTDIDSALT         = ${PERSISTENTDIDSALT}" | tee -a ${F_DEBUG}
            echo "FTICKSSALT                = ${FTICKSSALT}" | tee -a ${F_DEBUG}
        fi

#
# PACOTES
#
        echo "" 
        echo "Instalando pacotes"
        wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
        echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
        apt update
        apt install -y apache2 libapache2-mod-xforward jetty9 rsyslog filebeat nagios-nrpe-server nagios-plugins

#
# OPENSSL - arquivo de config
#
        echo "" 
        echo "Gerando arquivo de configuração do OpenSSL"
        cat > /tmp/openssl.cnf <<-EOF
[ req ]
default_bits = 2048 # Size of keys
string_mask = nombstr # permitted characters
distinguished_name = req_distinguished_name
  
[ req_distinguished_name ]
# Variable name   Prompt string
#----------------------   ----------------------------------
0.organizationName = Nome da universidade/organização
organizationalUnitName = Departamento da universidade/organização
emailAddress = Endereço de email da administração
emailAddress_max = 40
localityName = Nome do município (por extenso)
stateOrProvinceName = Unidade da Federação (por extenso)
countryName = Nome do país (código de 2 letras)
countryName_min = 2
countryName_max = 2
commonName = Nome completo do host (incluíndo o domínio)
commonName_max = 64
  
# Default values for the above, for consistency and less typing.
# Variable name   Value
#------------------------------   ------------------------------
0.organizationName_default = ${INITIALS} - ${ORGANIZATION}
emailAddress_default = ${CONTACTMAIL}
organizationalUnitName_default = ${OU}
localityName_default = ${CITY}
stateOrProvinceName_default = ${STATE}
countryName_default = BR
commonName_default = ${HN}.${HN_DOMAIN}
EOF

#
# SHIB - Instalação
#
        echo "" 
        echo "Instalando Shibboleth IDP"
        ${SRCDIR}/bin/install.sh \
        -Didp.src.dir=${SRCDIR} \
        -Didp.target.dir=${SHIBDIR} \
        -Didp.sealer.password=changeit \
        -Didp.keystore.password=changeit \
        -Didp.conf.filemode=644 \
        -Didp.host.name=${HN}.${HN_DOMAIN} \
        -Didp.scope=${DOMAIN} \
        -Didp.entityID=https://${HN}.${HN_DOMAIN}/idp/shibboleth

#
# OpenSSL - Geração de certificados shib
#
        echo "" 
        echo "Gerando certificado digital para o Shibboleth IDP"
        cd ${SHIBDIR}/credentials/
        rm -f idp*
        openssl genrsa -out idp.key 2048
        openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key idp.key -set_serial 00 -config /tmp/openssl.cnf -out idp.crt
        if [ ${DEBUG} -eq 1 ] ; then
            echo "" 
            echo "Certificado Shibboleth" | tee -a ${F_DEBUG}
            openssl x509 -in ${SHIBDIR}/credentials/idp.crt -text -noout >> /root/cafe-firstboot.debug | tee -a ${F_DEBUG}
        fi

#
# SHIB - Arquivos estáticos
#
        echo "" 
        echo "Obtendo arquivos de configuração estáticos"
        wget ${REPOSITORY}/conf/attribute-filter.xml -O ${SHIBDIR}/conf/attribute-filter.xml
        wget ${REPOSITORY}/conf/attribute-resolver.xml -O ${SHIBDIR}/conf/attribute-resolver.xml
        wget ${REPOSITORY}/conf/metadata-providers.xml -O ${SHIBDIR}/conf/metadata-providers.xml
        wget ${REPOSITORY}/conf/saml-nameid.xml -O ${SHIBDIR}/conf/saml-nameid.xml
        wget ${REPOSITORY}/conf/admin/admin.properties -O ${SHIBDIR}/conf/admin/admin.properties
        wget ${REPOSITORY}/conf/attributes/brEduPerson.xml -O ${SHIBDIR}/conf/attributes/brEduPerson.xml
        wget ${REPOSITORY}/conf/attributes/default-rules.xml -O ${SHIBDIR}/conf/attributes/default-rules.xml
        wget ${REPOSITORY}/conf/attributes/schac.xml -O ${SHIBDIR}/conf/attributes/schac.xml
        wget ${REPOSITORY}/conf/attributes/custom/eduPersonTargetedID.properties -O ${SHIBDIR}/conf/attributes/custom/eduPersonTargetedID.properties

#
# SHIB - ldap-properties
#
        echo "" 
        echo "Configurando ldap.properties"
        cat > ${SHIBDIR}/conf/ldap.properties <<-EOF
# LDAP authentication (and possibly attribute resolver) configuration
# Note, this doesn't apply to the use of JAAS authentication via LDAP

## Authenticator strategy, either anonSearchAuthenticator, bindSearchAuthenticator, directAuthenticator, adAuthenticator
idp.authn.LDAP.authenticator                       = bindSearchAuthenticator

## Connection properties ##
idp.authn.LDAP.ldapURL                             = ${LDAPSERVERPROTO}${LDAPSERVER}:${LDAPSERVERPORT}
idp.authn.LDAP.useStartTLS                         = false
# Time in milliseconds that connects will block
idp.authn.LDAP.connectTimeout                      = PT3S
# Time in milliseconds to wait for responses
idp.authn.LDAP.responseTimeout                     = PT3S
# Connection strategy to use when multiple URLs are supplied, either ACTIVE_PASSIVE, ROUND_ROBIN, RANDOM
#idp.authn.LDAP.connectionStrategy                 = ACTIVE_PASSIVE

## SSL configuration, either jvmTrust, certificateTrust, or keyStoreTrust
idp.authn.LDAP.sslConfig                           = certificateTrust
## If using certificateTrust above, set to the trusted certificate's path
idp.authn.LDAP.trustCertificates                   = %{idp.home}/credentials/ldap-server.crt
## If using keyStoreTrust above, set to the truststore path
#idp.authn.LDAP.trustStore                         = %{idp.home}/credentials/ldap-server.truststore

## Return attributes during authentication
idp.authn.LDAP.returnAttributes                    = ${LDAPATTR}

## DN resolution properties ##

# Search DN resolution, used by anonSearchAuthenticator, bindSearchAuthenticator
# for AD: CN=Users,DC=example,DC=org
idp.authn.LDAP.baseDN                              = ${LDAPDN}
idp.authn.LDAP.subtreeSearch                       = ${LDAPSUBTREESEARCH}
idp.authn.LDAP.userFilter                          = (${LDAPATTR}={user})
# bind search configuration
# for AD: idp.authn.LDAP.bindDN=adminuser@domain.com
idp.authn.LDAP.bindDN                              = ${LDAPUSER}

# Format DN resolution, used by directAuthenticator, adAuthenticator
# for AD use idp.authn.LDAP.dnFormat=%s@domain.com
idp.authn.LDAP.dnFormat                            = ${LDAPFORM}

# pool passivator, either none, bind or anonymousBind
#idp.authn.LDAP.bindPoolPassivator                 = none

# LDAP attribute configuration, see attribute-resolver.xml
# Note, this likely won't apply to the use of legacy V2 resolver configurations
idp.attribute.resolver.LDAP.ldapURL                = %{idp.authn.LDAP.ldapURL}
idp.attribute.resolver.LDAP.connectTimeout         = %{idp.authn.LDAP.connectTimeout:PT3S}
idp.attribute.resolver.LDAP.responseTimeout        = %{idp.authn.LDAP.responseTimeout:PT3S}
idp.attribute.resolver.LDAP.connectionStrategy     = %{idp.authn.LDAP.connectionStrategy:ACTIVE_PASSIVE}
idp.attribute.resolver.LDAP.baseDN                 = %{idp.authn.LDAP.baseDN:undefined}
idp.attribute.resolver.LDAP.bindDN                 = %{idp.authn.LDAP.bindDN:undefined}
idp.attribute.resolver.LDAP.useStartTLS            = %{idp.authn.LDAP.useStartTLS:true}
idp.attribute.resolver.LDAP.trustCertificates      = %{idp.authn.LDAP.trustCertificates:undefined}
idp.attribute.resolver.LDAP.searchFilter           = (${LDAPATTR}=\$resolutionContext.principal)
idp.attribute.resolver.LDAP.multipleResultsIsError = false

# LDAP pool configuration, used for both authn and DN resolution
#idp.pool.LDAP.minSize                             = 3
#idp.pool.LDAP.maxSize                             = 10
#idp.pool.LDAP.validateOnCheckout                  = false
#idp.pool.LDAP.validatePeriodically                = true
#idp.pool.LDAP.validatePeriod                      = PT5M
#idp.pool.LDAP.validateDN                          =
#idp.pool.LDAP.validateFilter                      = (objectClass=*)
#idp.pool.LDAP.prunePeriod                         = PT5M
#idp.pool.LDAP.idleTime                            = PT10M
#idp.pool.LDAP.blockWaitTime                       = PT3S 
EOF

#
# SHIB - secrets.properties
#
        echo "" 
        echo "Configurando secrets.properties"
        cat  > ${SHIBDIR}/credentials/secrets.properties <<-EOF
# Access to internal AES encryption key
idp.sealer.storePassword = changeit
idp.sealer.keyPassword = changeit

# Default access to LDAP authn and attribute stores.
idp.authn.LDAP.bindDNCredential              = ${LDAPPWD}
idp.attribute.resolver.LDAP.bindDNCredential = %{idp.authn.LDAP.bindDNCredential:undefined}

# Salt used to generate persistent/pairwise IDs, must be kept secret
idp.persistentId.salt  = ${PERSISTENTDIDSALT}

idp.cafe.computedIDsalt = ${COMPUTEDIDSALT}
EOF

#
# SHIB - idp-properties
#
        echo "" 
        echo "Configurando idp.properties"
        cat  > ${SHIBDIR}/conf/idp.properties <<-EOF
idp.searchForProperties= true

idp.additionalProperties= /credentials/secrets.properties

idp.entityID= https://${HN}.${HN_DOMAIN}/idp/shibboleth

idp.scope= ${DOMAIN}
 
idp.csrf.enabled=true

idp.sealer.storeResource=%{idp.home}/credentials/sealer.jks
idp.sealer.versionResource=%{idp.home}/credentials/sealer.kver

idp.signing.key=%{idp.home}/credentials/idp.key
idp.signing.cert=%{idp.home}/credentials/idp.crt
idp.encryption.key=%{idp.home}/credentials/idp.key
idp.encryption.cert=%{idp.home}/credentials/idp.crt

idp.encryption.config=shibboleth.EncryptionConfiguration.GCM

idp.trust.signatures=shibboleth.ExplicitKeySignatureTrustEngine

idp.storage.htmlLocalStorage=true

idp.session.trackSPSessions=true
idp.session.secondaryServiceIndex=true

idp.bindings.inMetadataOrder=false

idp.ui.fallbackLanguages=pt-br,en

idp.fticks.federation = CAFE
idp.fticks.algorithm = SHA-256
idp.fticks.salt = ${FTICKSSALT}
idp.fticks.loghost= localhost
idp.fticks.logport= 514

idp.audit.shortenBindings=true

#idp.loglevel.idp = DEBUG
#idp.loglevel.ldap = DEBUG
#idp.loglevel.messages = DEBUG
#idp.loglevel.encryption = DEBUG
#idp.loglevel.opensaml = DEBUG
#idp.loglevel.props = DEBUG
#idp.loglevel.httpclient = DEBUG
EOF

#
# SHIB - saml-nameid.properties
#
        echo "" 
        echo "Configurando saml-nameid.properties"
        cat  > ${SHIBDIR}/conf/saml-nameid.properties <<-EOF
idp.persistentId.sourceAttribute = ${LDAPATTR}
idp.persistentId.encoding = BASE32
EOF

#
# SHIB - idp-metadata.xml
#
        echo "" 
        echo "Configurando idp-metadata.xml"
        cp ${SHIBDIR}/credentials/idp.crt /tmp/idp.crt.tmp
        sed -i '$ d' /tmp/idp.crt.tmp
        sed -i 1d /tmp/idp.crt.tmp
        CRT=`cat /tmp/idp.crt.tmp`
        rm -rf /tmp/idp.crt.tmp
        cat > /opt/shibboleth-idp/metadata/idp-metadata.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
 
<EntityDescriptor  xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:xml="http://www.w3.org/XML/1998/namespace" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://${HN}.${HN_DOMAIN}/idp/shibboleth">
 
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">
 
                <Extensions>
                        <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
 
                        <mdui:UIInfo>
                                <mdui:OrganizationName xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:OrganizationName>
                                <mdui:DisplayName xml:lang="en">${INITIALS} - ${ORGANIZATION}</mdui:DisplayName>
                                <mdui:OrganizationURL xml:lang="en">http://www.${DOMAIN}/</mdui:OrganizationURL>
                        </mdui:UIInfo>
 
                        <md:ContactPerson contactType="technical">
                                <md:SurName>${CONTACT}</md:SurName>
                                <md:EmailAddress>${CONTACTMAIL}</md:EmailAddress>
                        </md:ContactPerson>
                </Extensions>
 
                <KeyDescriptor>
                        <ds:KeyInfo>
                                <ds:X509Data>
                                        <ds:X509Certificate>
${CRT}
                                        </ds:X509Certificate>
                                        </ds:X509Data>
                                </ds:KeyInfo>
                </KeyDescriptor>
 
                <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/ArtifactResolution" index="1"/>
                <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/ArtifactResolution" index="2"/>
                <!--
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SLO"/>
                <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/SLO"/>
                -->
                <NameIDFormat>urn:mace:shibboleth:1.0:nameIdentifier</NameIDFormat>
                <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
                <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://${HN}.${HN_DOMAIN}/idp/profile/Shibboleth/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/POST-SimpleSign/SSO"/>
                <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://${HN}.${HN_DOMAIN}/idp/profile/SAML2/Redirect/SSO"/>
        </IDPSSODescriptor>
 
        <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">

                <Extensions>
                        <shibmd:Scope regexp="false">${DOMAIN}</shibmd:Scope>
                </Extensions>

                <KeyDescriptor>
                        <ds:KeyInfo>
                                <ds:X509Data>
                                        <ds:X509Certificate>
${CRT}
                                        </ds:X509Certificate>
                                </ds:X509Data>
                        </ds:KeyInfo>
                </KeyDescriptor>

                <AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML1/SOAP/AttributeQuery"/>
                <!-- <AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://${HN}.${HN_DOMAIN}:8443/idp/profile/SAML2/SOAP/AttributeQuery"/> -->
                <!-- If you uncomment the above you should add urn:oasis:names:tc:SAML:2.0:protocol to the protocolSupportEnumeration above -->

        </AttributeAuthorityDescriptor>
</EntityDescriptor>
EOF

#
# SHIB - access-control.xml
#
        echo "" 
        echo "Configurando access-control.xml"
        cat > /opt/shibboleth-idp/conf/access-control.xml <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:util="http://www.springframework.org/schema/util"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:c="http://www.springframework.org/schema/c"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
                           http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd
                           http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd"

       default-init-method="initialize"
       default-destroy-method="destroy">

    <util:map id="shibboleth.AccessControlPolicies">

        <entry key="AccessByIPAddress">
            <bean id="AccessByIPAddress" parent="shibboleth.IPRangeAccessControl"
                    p:allowedRanges="#{ {'127.0.0.1/32', '::1/128', '${IP}/32', '${POLLER}/32'} }" />
        </entry>

    </util:map>

</beans>
EOF

#
# SHIB - Personalização layout
#
        #Copiando arquivo para personalizacao
        mkdir /tmp/shib-idp
        cd /tmp/shib-idp
        wget ${REPOSITORY}/layout/pacote-personalizacao-layout-4.1.tar.gz -O /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz
        tar -zxvf /tmp/shib-idp/pacote-personalizacao-layout-4.1.tar.gz
        mkdir ${SHIBDIR}/edit-webapp/api
        cp /tmp/shib-idp/views/*.vm ${SHIBDIR}/views/
        cp /tmp/shib-idp/views/client-storage/*.vm ${SHIBDIR}/views/client-storage/
        cp /tmp/shib-idp/edit-webapp/css/*.css ${SHIBDIR}/edit-webapp/css/
        cp -R /tmp/shib-idp/edit-webapp/api/* ${SHIBDIR}/edit-webapp/api/
        cp -R /tmp/shib-idp/edit-webapp/images/* ${SHIBDIR}/edit-webapp/images/
        cp /tmp/shib-idp/messages/*.properties ${SHIBDIR}/messages/

        #Configurando mensagens
        setProperty "idp.login.username.label" "${MSG_AUTENTICACAO}" "${SHIBDIR}/messages/messages_pt_BR.properties"
        setProperty "idp.url.password.reset" "${MSG_URL_RECUPERACAO_SENHA}" "${SHIBDIR}/messages/messages_pt_BR.properties"

        #Atualizacao do war
        echo "" 
        echo "Build/update WAR"
        ${SHIBDIR}/bin/build.sh \
        -Didp.target.dir=${SHIBDIR}

#
# APACHE - config site, modules e certificados - 01-idp.conf
#
        echo "" 
        echo "Configurando Apache"
        wget ${REPOSITORY}/apache/security.conf -O /etc/apache2/conf-available/security.conf
        cat > /etc/apache2/sites-available/01-idp.conf <<-EOF
<VirtualHost ${IP}:80>

    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    Redirect permanent "/" "https://${HN}.${HN_DOMAIN}/"

</VirtualHost>

<VirtualHost ${IP}:443>
 
    ServerName ${HN}.${HN_DOMAIN}
    ServerAdmin ${CONTACTMAIL}

    CustomLog /var/log/apache2/${HN}.${HN_DOMAIN}.access.log combined
    ErrorLog /var/log/apache2/${HN}.${HN_DOMAIN}.error.log

    SSLEngine On
    SSLProtocol -all +TLSv1.1 +TLSv1.2
    SSLCipherSuite ALL:+HIGH:+AES256:+GCM:+RSA:+SHA384:!AES128-SHA256:!AES256-SHA256:!AES128-GCM-SHA256:!AES256-GCM-SHA384:-MEDIUM:-LOW:!SHA:!3DES:!ADH:!MD5:!RC4:!NULL:!DES
    SSLHonorCipherOrder on
    SSLCompression off
    SSLCertificateKeyFile /etc/ssl/private/chave-apache.key
    SSLCertificateFile /etc/ssl/certs/certificado-apache.crt

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port 443
    ProxyPass /idp http://localhost:8080/idp
    ProxyPassReverse /idp http://localhost:8080/idp

    Redirect permanent "/" "https://${URL}/"

</VirtualHost>
EOF

        # Chave e Certificado Apache
        openssl genrsa -out /etc/ssl/private/chave-apache.key 2048
        openssl req -batch -new -x509 -nodes -days 1095 -sha256 -key /etc/ssl/private/chave-apache.key -set_serial 00 \
            -config /tmp/openssl.cnf -out /etc/ssl/certs/certificado-apache.crt
        if [ ${DEBUG} -eq 1 ] ; then
            echo "" 
            echo "Certificado Apache" | tee -a ${F_DEBUG}
            openssl x509 -in /etc/ssl/certs/certificado-apache.crt -text -noout >> /root/cafe-firstboot.debug | tee -a ${F_DEBUG}
        fi
        chown root:ssl-cert /etc/ssl/private/chave-apache.key /etc/ssl/certs/certificado-apache.crt
        chmod 640 /etc/ssl/private/chave-apache.key

        a2dissite 000-default.conf
        a2enmod ssl headers proxy_http
        a2ensite 01-idp.conf
        systemctl restart apache2

#
# FTICKS - Filebeat / rsyslog
#
        echo "" 
        echo "Configurando FTICKS"
        cat > /etc/rsyslog.conf <<-EOF
#  /etc/rsyslog.conf    Configuration file for rsyslog.
#
#                       For more information see
#                       /usr/share/doc/rsyslog-doc/html/rsyslog_conf.html
#
#  Default logging rules can be found in /etc/rsyslog.d/50-default.conf

#################
#### MODULES ####
#################

#module(load="imuxsock") # provides support for local system logging
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

# provides kernel logging support and enable non-kernel klog messages
module(load="imklog" permitnonkernelfacility="on")

###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
#\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Filter duplicated messages
\$RepeatedMsgReduction on

#
# Set the default permissions for all log files.
#
\$FileOwner syslog
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022
\$PrivDropToUser syslog
\$PrivDropToGroup syslog

#
# Where to place spool and state files
#
\$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
\$IncludeConfig /etc/rsyslog.d/*.conf
EOF

        cat > /etc/rsyslog.d/01-fticks.conf <<-EOF
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" /var/log/fticks.log
:msg, contains, "Shibboleth-FTICKS F-TICKS/CAFE" ~
EOF

        touch /var/log/fticks.log
        chmod 0640 /var/log/fticks.log
        chown syslog:adm /var/log/fticks.log
        systemctl restart rsyslog
        cat > /etc/filebeat/filebeat.yml <<-EOF
#============================ Filebeat inputs ================================

filebeat.inputs:

- type: log

  enabled: true

  paths:
    - /var/log/fticks.log

#============================= Filebeat modules ==============================

filebeat.config.modules:

  path: \${path.config}/modules.d/*.yml

  reload.enabled: false

#----------------------------- Logstash output --------------------------------

output.logstash:
  hosts: ["estat-ls.cafe.rnp.br:5044"]

#================================ Processors ==================================

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
EOF

        systemctl restart filebeat
        systemctl enable filebeat

        cat > /etc/logrotate.d/fticks <<-EOF
/var/log/fticks.log {
    su root root
    create 0640 syslog adm
    daily
    rotate 180
    compress
    nodelaycompress
    dateext
    missingok
    postrotate
        systemctl restart rsyslog
    endscript
}
EOF

#
# FAIL2BAN
#
        echo "" 
        echo "Configurando Fail2ban"
	apt install -y fail2ban
	cat > /etc/fail2ban/filter.d/shibboleth-idp.conf <<-EOF
# Fail2Ban filter for Shibboleth IDP
#
# Author: rui.ribeiro@cafe.rnp.br
#
[INCLUDES]
before          = common.conf

[Definition]
_daemon         = jetty
failregex       = <HOST>.*Login by.*failed
EOF

	cat > /etc/fail2ban/jail.local <<-EOF
[shibboleth-idp]
enabled = true
filter = shibboleth-idp
port = all
banaction = iptables-allports
logpath = /opt/shibboleth-idp/logs/idp-process.log
findtime = 300
maxretry = 5
EOF

#
# KEYSTORE - Popular com certificados
#

        # Se LDAP usa SSL, pega certificado e adiciona no keystore
        if [ ${LDAPSERVERSSL} -eq 1 ] ; then
            echo "" 
            echo "Configurando Certificados LDAPS"
            openssl s_client -showcerts -connect ${LDAPSERVER}:${LDAPSERVERPORT} < /dev/null 2> /dev/null | openssl x509 -outform PEM > /opt/shibboleth-idp/credentials/ldap-server.crt
            /usr/lib/jvm/java-11-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /usr/lib/jvm/java-11-amazon-corretto/lib/security/cacerts -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit
            /usr/lib/jvm/java-11-amazon-corretto/bin/keytool -import -noprompt -alias ldap.local -keystore /opt/shibboleth-idp/credentials/ldap-server.truststore -file /opt/shibboleth-idp/credentials/ldap-server.crt -storepass changeit
            sed -i -e 's/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\"/principalCredential=\"%{idp.attribute.resolver.LDAP.bindDNCredential}\" trustFile=\"%{idp.attribute.resolver.LDAP.trustCertificates}\"/' /opt/shibboleth-idp/conf/attribute-resolver.xml
        fi

#
# RNP - Monitoramento
#
        echo "" 
        echo "Configurando Monitoramento RNP"
        cat > /etc/nagios/nrpe.cfg <<-EOF
log_facility=daemon
debug=0
pid_file=/run/nagios/nrpe.pid
server_port=5666
nrpe_user=nagios
nrpe_group=nagios
allowed_hosts=127.0.0.1,::1,${IP},${POLLER}
dont_blame_nrpe=0
allow_bash_command_substitution=0
command_timeout=60
connection_timeout=300
disable_syslog=0

## Configuracao de infra do IDP
command[check_load]=/usr/lib/nagios/plugins/check_load -r -w .40,.35,.30 -c .60,.55,.50
command[check_sda1]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /dev/sda1
command[check_mem]=/usr/lib/nagios/plugins/check_mem
command[check_uptime]=/usr/lib/nagios/plugins/check_uptime
command[check_http]=/usr/lib/nagios/plugins/check_tcp -p 80
command[check_https]=/usr/lib/nagios/plugins/check_tcp -p 443
 
## Configuracao de uso do status page.
command[check_idp_uptime]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpuptime
command[check_idp_status]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpstatus
command[check_idp_lastmetadata]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idplastmetadata
command[check_idp_idpversion]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" idpversion
command[check_idp_jdkversion]=/usr/lib/nagios/plugins/check_idp "https://${HN}.${HN_DOMAIN}/idp/status" jdkversion

include=/etc/nagios/nrpe_local.cfg
include_dir=/etc/nagios/nrpe.d/
EOF

        # Download de checks
        wget ${REPOSITORY}/nagios/check_idp -O /usr/lib/nagios/plugins/check_idp
        wget ${REPOSITORY}/nagios/check_mem -O /usr/lib/nagios/plugins/check_mem
        wget ${REPOSITORY}/nagios/check_uptime -O /usr/lib/nagios/plugins/check_uptime

        # Corrige permissões
        chmod 755 /usr/lib/nagios/plugins/check_idp
        chmod 755 /usr/lib/nagios/plugins/check_mem
        chmod 755 /usr/lib/nagios/plugins/check_uptime

        systemctl restart nagios-nrpe-server.service

#
# JETTY - Configuração
#
        echo "" 
        echo "Configurando Jetty"
        sed -i 's/^ReadWritePaths=\/var\/lib\/jetty9\/$/ReadWritePaths=\/var\/lib\/jetty9\/ \/opt\/shibboleth-idp\/credentials\/ \/opt\/shibboleth-idp\/logs\/ \/opt\/shibboleth-idp\/metadata\//' /lib/systemd/system/jetty9.service
        systemctl daemon-reload
        wget ${REPOSITORY}/jetty/idp.ini -O /etc/jetty9/start.d/idp.ini
        #sed -i 's/^--module=deploy,http,jsp,jstl,websocket,ext,resources$/--module=deploy,http,jsp,jstl,websocket,ext,resources,http-forwarded/' /etc/jetty9/start.ini
        sed -i '/<param-name>dirAllowed<\/param-name>/!b;n;c\ \ \ \ \ \ <param-value>false<\/param-value>' /etc/jetty9/webdefault.xml

        # Corrige permissões
        chown -R jetty:jetty ${SHIBDIR}/{credentials,logs,metadata}

        # Configura contexto no Jetty
        cat > /var/lib/jetty9/webapps/idp.xml <<-EOF
<Configure class="org.eclipse.jetty.webapp.WebAppContext">
  <Set name="war">${SHIBDIR}/war/idp.war</Set>
  <Set name="contextPath">/idp</Set>
  <Set name="extractWAR">false</Set>
  <Set name="copyWebDir">false</Set>
  <Set name="copyWebInf">true</Set>
  <Set name="persistTempDirectory">false</Set>
</Configure>
EOF
