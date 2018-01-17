############
Configurando APACHE2 para SSL A+
Aprovado para PCI-DSS
Colaboradores: Robson Ferreira Lopes, Kleber de Paiva e Alexandre.

Para esse projeto foram usados:
Debian Versão 9.0
Apache Versão 2.24.25
Openssl 1.1.0f
Certificados LetEncripty

Habilitado para TLS1.0, TLS1.1, TLS1.2
Serviço HSTS Habilitado
Proteções contra XSS, SSI, Listagem de Diretórios, TRACE, Cookie e outras.

Dominio de Teste www.securitylabs.gru.br

Resumo dos Procedimentos
1. Modulos que devem ser habilitados:
rewrite
headers
ssl

2. Modulos que devem ser desabilitados: (Talvez precise forçar)
deflate

3. Os arquivos de configuração versão 1.0
apache2.conf, security.conf

4. O arquivo do VirtualHostt versão 1.0 
securitylabs.conf

Melhorias
- Comentar o arquivo e retirar linhas desnecessárias
- Implementar o ModSecurity


Referencias:
https://kb.sucuri.net/warnings/hardening/headers-x-content-type
https://servidordebian.org/pt/stretch/intranet/ssl_cert/start
https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=apache-2.4.25&openssl=1.0.1f&hsts=yes&profile=intermediate
https://geekflare.com/apache-web-server-hardening-security/#412-Set-cookie-with-HttpOnly-and-Secure-flag
https://scottlinux.com/2012/09/13/disable-http-compression-in-apache/
https://wiki.mozilla.org/Security/Server_Side_TLS
https://geekflare.com/ssl-test-certificate

