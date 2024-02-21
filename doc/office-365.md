# Integrando o Office 365 com Shibboleth IDP - Ubnt 22.04 + Shib 4.3.1

_Elaborado por Rui Ribeiro - rui.ribeiro@cafe.rnp.br_

## 1. Introdução (#intro)

Essa página tem como objetivo auxiliar na configuração do seu Provedor de Identidade Shibboleth IDP para acesso SSO junto ao Office 365.

A configuração ocorrerá em duas etapas:

1. [Configuração no Shibbboleth IDP](#2-configuração-no-shibbboleth-idp)
2. [Configuração no Microsoft Entra](#3-configuração-no-microsoft-entra)

## 2. Configuração no Shibbboleth IDP

Durante essa etapa serão manipulados os seguintes arquivos:

* /opt/shibboleth-idp/conf/relying-party.xml
* /opt/shibboleth-idp/conf/saml-nameid.xml
* /opt/shibboleth-idp/conf/attribute-resolver.xml
* /opt/shibboleth-idp/conf/attributes/custom/ImmutableID.properties
* /opt/shibboleth-idp/conf/attributes/custom/UserId.properties
* /opt/shibboleth-idp/conf/metadata-providers.xml
* /opt/shibboleth-idp/metadata/office365-md.xml
* /opt/shibboleth-idp/conf/attribute-filter.xml

> **ATENÇÃO**
>
> É fortemente recomendada a realização de backup do IDP antes de executar esse procedimento

2.1. No arquivo `/opt/shibboleth-idp/conf/relying-party.xml`, sob o item `<util:list id="shibboleth.RelyingPartyOverrides">`, adicione a configuração abaixo:

```xml
<bean id="Office365" parent="RelyingPartyByName" c:relyingPartyIds="urn:federation:MicrosoftOnline">
   <property name="profileConfigurations">
      <list>
         <bean parent="SAML2.SSO" p:encryptAssertions="false" p:signAssertions="true" p:signResponses="false" />
         <bean parent="SAML2.ECP" p:encryptAssertions="false" p:signAssertions="true" p:signResponses="false" p:nameIDFormatPrecedence="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" />
      </list>
   </property>
</bean>
```

2.2. Já no arquivo `/opt/shibboleth-idp/conf/saml-nameid.xml`, dentro do item `<util:list id="shibboleth.SAML2NameIDGenerators">`, adicione a configuração abaixo:

```xml
<!-- CAFe- Persistent NameID -->
<bean parent="shibboleth.SAML2PersistentGenerator">
   <property name="activationCondition">
      <bean parent="shibboleth.Conditions.NOT">
         <constructor-arg>
            <bean parent="shibboleth.Conditions.RelyingPartyId" c:candidate="urn:federation:MicrosoftOnline" />
         </constructor-arg>
      </bean>
   </property>
</bean>

<!-- CAFe - Persistent NameID exclusivo para Microsoft -->
<bean parent="shibboleth.SAML2AttributeSourcedGenerator"
      p:omitQualifiers="true"
      p:format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      p:attributeSourceIds="#{ {'ImmutableID'} }">
   <property name="activationCondition">
      <bean parent="shibboleth.Conditions.RelyingPartyId" c:candidate="urn:federation:MicrosoftOnline" />
   </property>
</bean>
```

2.3. Para criar os atribututos que serão usados (`ImmutableID` e `UserId`), altere o arquivo `/opt/shibboleth-idp/conf/attribute-resolver.xml` adicionando as linhas a seguir:

```xml
<!-- CAFe - ImmutableID para Microsoft -->
<AttributeDefinition xsi:type="Simple" id="ImmutableID">
   <InputDataConnector ref="dcLDAP" attributeNames="entryUUID"/>
</AttributeDefinition>

<!-- CAFe - UserId para Microsoft -->
<AttributeDefinition scope="%{idp.scope}" xsi:type="Scoped" id="UserId">
   <InputDataConnector ref="dcLDAP" attributeNames="uid"/>
 </AttributeDefinition>
```

Ainda no arquivo `/opt/shibboleth-idp/conf/attribute-resolver.xml`, adicione o atributo `entryUUID` à lista de atributos retornaveis do dataconnector `dcLDAP`. Exemplo:

```xml
<ReturnAttributes>%{idp.authn.LDAP.returnAttributes} mail cn givenName sn brPersonCPF schacDateOfBirth entryUUID</ReturnAttributes>
```

> **ATENÇÃO**
>
> O uso dos atributos `entryUUID` e `uid` é apropriado para ambientes OpenLDAP. Caso esteja utilizando outro diretório deve-se substituí-los pelos atributos correspondentes. Ex.: AD - entryUUID > objectGUID e uid > sAMAccountName.

2.4. Crie o arquivo `/opt/shibboleth-idp/conf/attributes/custom/ImmutableID.properties` com o seguinte conteúdo:

```properties
# Microsoft Entra ImmutableID

id=ImmutableID
transcoder=SAML2StringTranscoder
displayName.en=Microsoft Entra ImmutableID
displayName.pt-br=Microsoft Entra ImmutableID
description.en=Microsoft Entra ImmutableID
description.pt-br=Microsoft Entra ImmutableID
saml2.name=urn:oid:1.2.840.113556.1.4.2
saml1.encodeType=false
```

2.5. Crie o arquivo `/opt/shibboleth-idp/conf/attributes/custom/UserId.properties` com o seguinte conteúdo:

```properties
# Microsoft Entra User ID

id=UserId
transcoder=SAML2ScopedStringTranscoder
displayName.en=Microsoft Entra User ID
displayName.pt-br=Microsoft Entra User ID
description.en=Microsoft Entra User ID
description.pt-br=Microsoft Entra User ID
saml2.name=urn:oid:0.9.2342.19200300.100.1.1
saml1.encodeType=false
```

2.6. Para configurar o provedor de metadados, altere o arquivo `/opt/shibboleth-idp/conf/metadata-providers.xml` e adicione a configuração abaixo:

```xml
<MetadataProvider id="Office365" xsi:type="FilesystemMetadataProvider" metadataFile="%{idp.home}/metadata/microsoft-md.xml"/>
```

2.7. A seguir baixe o arquivo de metadados da Microsoft e armazene-o no local apropriado e remova a linha `<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>`.

```bash
wget https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml -O /opt/shibboleth-idp/metadata/microsoft-md.xml
```

   
8. Por fim, altere o arquivo `/opt/shibboleth-idp/conf/attribute-filter.xml` incluindo a política de liberação de atributos para o Microsoft Entra.

```xml
<AttributeFilterPolicy id="PolicyForMicrosoftEntra">
   <PolicyRequirementRule xsi:type="Requester" value="urn:federation:MicrosoftOnline" />
   
   <AttributeRule attributeID="UserId">
      <PermitValueRule xsi:type="ANY"/>
   </AttributeRule>
   
   <AttributeRule attributeID="ImmutableID">
      <PermitValueRule xsi:type="ANY"/>
   </AttributeRule>

</AttributeFilterPolicy>
```

## 3. Configuração no Microsoft Entra

O Microsoft Entra (antigamente chamada de Azure AD) é a ferramenta destinada ao gerenciamento de usuários e controle de acesso no contexte de nuvem da Microsoft.

> **ATENÇÃO**
>
> É necessário possuir um console PowerShell capaz de se conectar ao Microsoft Entra bem como as credenciais de administração.
> 
> A configuração demandará as seguintes informações:
> - Domino da Insituição. Ex.: instituicao.edu.br
> - Endereço do IDP. Ex.: https://idp.instituicao.edu.br
> - Certificado digital usado pelo Shibbboleth IDP disponível em `/opt/shibboleth-idp/credentials/idp.crt`. Apenas o conteúdo, sem o delimitadores de inicio e fim. Ex.: MIIDpzCCAo8CAgPo...

3.1. Conecte-se no Microsoft Entra.

```powershell
Connect-MsolService
```

3.2. Faça a definição das variáveis necessárias para a autenticação federada. 

> **ATENÇÃO**
>
> Fique atendo as substituições necessárias.

```powershell
$dom = "Substituir pelo Domino da Insituição"
$idpHost="Substituir pelo Endereço do IDP"
$fedBrandName="IDP Instituicao"
$url = "$idpHost/idp/profile/SAML2/POST/SSO"
$ecpUrl = "$idpHost/idp/profile/SAML2/SOAP/ECP"
$uri = "$idpHost/idp/shibboleth"
$logoutUrl = "$idpHost/idp/profile/SAML2/POST/SLO"
$certData = "Substituir pelo Certificado digital"
```

3.3. Execute a configuração da autenticação federada.

```powershell
Set-MsolDomainAuthentication -DomainName $dom -federationBrandName $FedBrandName -Authentication Federated  -PassiveLogOnUri $url -SigningCertificate $certData -IssuerUri $uri -ActiveLogOnUri $ecpUrl -LogOffUri $logoutUrl -PreferredAuthenticationProtocol SAMLP
```

## 4. Dicas

4.1. Testar a liberação de atributos

```bash
/opt/shibboleth-idp/bin/aacli.sh -n <NOME-USUARIO> -r urn:federation:MicrosoftOnline --saml2
```

4.2. Exibir configurações da autenticação federada.

```powershell
Get-MsolDomainFederationSettings -DomainName $dom
```

4.3. Retornar para autenticação gerenciada

```powershell
Set-MsolDomainAuthentication -DomainName $dom -Authentication Managed
```

4.4. Criar usuário

```
New-MsolUser `
  -UserPrincipalName usuario@instituicao.edu.br `
  -ImmutableId SubstituirPeloValorDoNameID `
  -DisplayName "Nome Sobrenome" `
  -FirstName Nome `
  -LastName Sobrenome `
  -AlternateEmailAddresses "email-alternativo@provedor.com.br" `
  -UsageLocation "BR"
```

O valor a ser utilizado como ImmutableId é obtido a partir do NameID. Para obter esse valor execute o comando descrito em 4.1.