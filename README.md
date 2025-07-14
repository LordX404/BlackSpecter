Exploração Real de Vulnerabilidades 
Script para realizar testes reais de exploração em aplicações web, incluindo:

SQL Injection

Upload de webshell PHP

Captura de banner HTTP via socket

Busca de arquivos de configuração expostos

Exploração básica de deserialização com payload binário

Requisitos
Python 3.6 ou superior

Módulos Python:

pip install requests

Como usar:
python BlackSpecter.py <target_url> [opções]
Parâmetros
<target_url>: URL base do alvo (ex: http://site-vulneravel.com)

Opções (padrões):
scss

--sqlipath       Caminho vulnerável para SQL Injection (default: /vuln.php)
--sqliparam      Parâmetro vulnerável para SQL Injection (default: id)
--uploadpath     Caminho para upload de arquivos (default: /upload.php)
--uploadparam    Parâmetro para arquivo no upload (default: file)
--bannerport     Porta para captura de banner HTTP (default: 80)
--deserpath      Caminho para endpoint de deserialização (default: /deserialize)
--deserpayload   Payload em base64 para deserialização (default: None)
Exemplo de uso

python BlackSpecter.py http://site-vulneravel.com --sqlipath /vuln.php --sqliparam id --uploadpath /upload.php --uploadparam file --bannerport 80 --deserpath /deserialize --deserpayload <payload_base64>
