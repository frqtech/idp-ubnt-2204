# Roteiro de Criação da Máquina Virtual - Ubnt 22.04 + Shib 4.3.1

_Elaborado por Rui Ribeiro - rui.ribeiro@cafe.rnp.br_

## 1. Introdução

O conjunto de atividades necessárias para configuração do `Virtual Appliance` estão divididas em dois scripts. Essa abordagem tem o intuíto de proporcionais maior flexibilidade em caso de alterações futuras. Os arquivos estão organizados conforme segue:

* firstboot.sh - contém as configurações básicas do sistema operacional
* firstboot-complement.sh - contém as configurações avançadas relativas ao Shibboleth e suas dependências.

Adicionalmente foi criado um terceiro arquivo chamado `firstboot-complement.md5` que possui o hash MD5 do arquivo `firstboot-complement.sh`. A finalidade desse arquivo é promover uma verificação de integridade em relação ao `firstboot-complement.sh`.

## 2. Sistema Operacional

O Virtual Applicance deve ser configurado tendo como base máquina virtual recem instalada com o Linux distribuição Ubuntu 22.04 LTS.

## 3. Configurações Básicas

3.1. Inicialmente será feira a configuração do `hostname`. Tal configuração deve ser feita através do comando `hostnamectl`. Um exemplo deste comando é exibido abaixo.

```
hostnamectl set-hostname "idp.instituicao.edu.br"
```

3.2. A configuração do arquivo de hosts é feita através do arquivo `/etc/hosts`. Um exemplo do conteúdo deste arquivo é exibido abaixo.

```
127.0.0.1    localhost
10.0.0.1     idp.instituicao.edu.br  idp
```

3.3. Considerando que esta máquina será utilizada como um `Virtual Appliance` recomenda-se que como configuração inicial e de caráter temporário, a máquina esteja configurada com DHCP. Isso permitirá que, havendo servidor DHCP, a máquina ingresse brevemente na rede da instituição. O script firstboot reconfigurará a máquina de forma a fazê-la utilizar IP estático.

A configuração deve ser feita no arquivo `/etc/netplan/00-installer-config.yaml` de acordo com o exemplo abaixo:

```
network:
  version: 2
  renderer: networkd
  ethernets:
    enp3s0:
      dhcp4: true
```

3.4. As linhas a seguir tem por objetivo fazer a remoção de pacotes desnecessários, atualização da distribuição e ainda instalação de pacotes úteis.

```
apt update
apt remove --purge -y vim-tiny
apt dist-upgrade -y
apt install -y less vim bzip2 unzip ssh dialog ldap-utils build-essential net-tools
```

3.5. A fim de otimizar o espaço ocupado pelos arquivos de LOG, deverá ser habilitada a opção de compressão no arquivo `/etc/logrotate.conf`. Para tanto garanta que as linhas a seguir estejam presentes e descomentadas no referido arquivo.

```
compress
 
nodelaycompress
dateext
```

 3.6. O firewall será composto por três arquivos:

* `/etc/default/firewall` - arquivo com as regras de firewall
* `/etc/systemd/system/firewall.service` - arquivo de configuração para o systemd
* `/opt/rnp/firewall/firewall.sh` - script de manipulação do firewall

O bloco abaixo apresenta o conteúdo do arquivo `/etc/default/firewall`:

```
#!/bin/sh
 
# Atualizado em 31/08/2016 por Rui Ribeiro - rui.ribeiro@cafe.rnp.br
 
# Apaga todas as regras pré-existentes
iptables -F
# Politica padrão DROP
iptables -P INPUT DROP
 
iptables -A INPUT -i lo -j ACCEPT
 
# Só aceita ate 10 pacotes icmp echo-request por segundo. Previne flooding.
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -p icmp -j ACCEPT
 
# Libera conexões já estabelecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
 
# Libera acesso SSH
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
 
# Libera acesso WEB
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
 
# ntp - servidor de hora
# descomente a linha a seguir para habilitar o acesso a partir da rede local ao servidor em /etc/ntp.conf
#iptables -A INPUT -p udp -m udp --dport 123 -j ACCEPT
```

O arquivo acima descrito pode ser baixado através do seguinte comando:

```
wget https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main/firewall/firewall.rules -O /etc/default/firewall
```

3.7. O bloco abaixo apresenta o conteúdo do arquivo `/etc/systemd/system/firewall.service`:

```
[Unit]
Description=Firewall Basico - RNP/CAFe - v1.0
 
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/rnp/firewall/firewall.sh start
ExecStop=/opt/rnp/firewall/firewall.sh stop
 
[Install]
WantedBy=multi-user.target
```

O arquivo acima descrito pode ser baixado através do seguinte comando:

```
wget https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main/firewall/firewall.service -O /etc/systemd/system/firewall.service
```

3.8. O bloco abaixo apresenta o conteúdo do arquivo `/opt/rnp/firewall/firewall.sh`:

```
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
```

O arquivo acima descrito pode ser baixado através do seguinte comando:

```
mkdir -p /opt/rnp/firewall/
wget https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main/firewall/firewall.sh -O /opt/rnp/firewall/firewall.sh
```

3.9. Uma vez que os dois arquivos estejam nos locais apropriados, é necessário executar as seguintes linhas de comando:

```
chmod 755 /opt/rnp/firewall/firewall.sh
chmod 664 /etc/systemd/system/firewall.service
systemctl daemon-reload
systemctl enable firewall.service
```

Ao executar tais linhas serão atribuídas as devidas permissões aos arquivos e será configurado o firewall no `systemd`.

3.10. A sincronização do relógio do servidor será feita pelo `ntp`. Para tanto é necessário desabilitar tal funcionalidade no `timedatectl` e então fazer a instalação do pacote `ntp`:

```
timedatectl set-ntp no
apt install -y ntp
```

3.11. Após fazer a instalação é necessário modificar o arquivo `/etc/ntp.conf` que deverá ficar com o seguinte conteúdo:

```
# /etc/ntp.conf, configuracao do ntpd
 
# Atualizado em 01/04/2013 por Rui Ribeiro - rui.ribeiro@cafe.rnp.br
 
driftfile /var/lib/ntp/ntp.drift
statsdir /var/log/ntpstats/
 
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable
 
# Servidores ntp do nic.br
server a.ntp.br
server b.ntp.br
server c.ntp.br
 
# By default, exchange time with everybody, but don't allow configuration.
# See /usr/share/doc/ntp-doc/html/accopt.html for details.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery
 
# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
restrict ::1
 
# Para habilitar o servidor de hora para acesso a partir da rede
# local, altere a linha abaixo:
#broadcast 192.168.123.255
```

O arquivo acima descrito pode ser baixado através do seguinte comando:

```
wget https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main/ntp/ntp.conf -O /etc/ntp.conf
```

3.12. Crie o usuário cafe que será utilizado posteriormente durante a execução do script de `firstboot.sh`.

```
useradd cafe -s /bin/bash
```

## 4. Configuração Java/Jetty

4.1 Adicione o repositório para instalação do Java Amazon Corretto 11. Para tanto execute os comandos abaixo:

```
wget -O- https://apt.corretto.aws/corretto.key | sudo apt-key add -
add-apt-repository 'deb https://apt.corretto.aws stable main'
```

4.2. Adicione a variável `JAVA_HOME` ao arquivo `/etc/environment`. Para tanto execute o seguintes comandos:

```
echo "JAVA_HOME=\"/usr/lib/jvm/java-11-amazon-corretto\"" >> /etc/environment
source /etc/environment
```

4.3. Para proceder a instalação do Java Amazon Corretto 11, execute a linha de comando a seguir.

```
apt update; sudo apt install -y java-11-amazon-corretto-jdk
```

4.4. Para proceder a instalado do Jetty, execute a linha de comando a seguir.

```
apt install -y jetty9 ; systemctl enable jetty9
```

## 5. Finalização

5.1. Executar os seguintes comandos:

```
cd /root/
wget https://shibboleth.net/downloads/identity-provider/4.3.1/shibboleth-identity-provider-4.3.1.zip
unzip shibboleth-identity-provider-4.3.1.zip
wget https://raw.githubusercontent.com/frqtech/idp-ubnt-2204/main/firstboot.sh -O /usr/local/sbin/firstboot.sh
chmod +x /usr/local/sbin/firstboot.sh
echo "/usr/local/sbin/firstboot.sh" >> /root/.bash_profile
```

5.2. Neste momento o Virtual Appliance estará configurado e já pode ser desligado.