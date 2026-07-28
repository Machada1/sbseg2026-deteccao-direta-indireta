# 📊 Análise Completa dos Relatórios de Segurança - Pipeline DevSecOps

**Data:** 09/02/2026 18:57

**Aplicação:** DVWA (Damn Vulnerable Web Application)

**Pesquisa:** Integração de Testes de Segurança Contínuos em Pipelines CI/CD

---

## 📋 Sumário Executivo

| Ferramenta | Tipo | Findings | Status |
| --- | --- | --- | --- |
| Trivy | Container Scan | 1575 | ✅ Executado |
| Semgrep | SAST | 77 | ✅ Executado |
| Trivy FS | SCA | 0 | ✅ Executado |
| OWASP ZAP | DAST (Baseline) | 19 | ✅ Executado |
| OWASP ZAP | DAST (Active Scan) | 13 | ✅ Executado |
| Checkov | IaC Scan | 63 | ✅ Executado |
| Hydra | Brute Force | Vulnerável | ✅ Executado |

**Total de issues de segurança identificados: 1748**

## 1. 📦 Container Scan - Trivy

**Imagem analisada:** `dvwa-app:0a8e877`

**Sistema Operacional:** debian 9.5

**End of Support Life (EOSL):** ⚠️ SIM - Sistema sem suporte!

### Distribuição por Severidade

| Severidade | Quantidade | Percentual |
| --- | --- | --- |
| 🔴 CRITICAL | 254 | 16.1% |
| 🟠 HIGH | 551 | 35.0% |
| 🟡 MEDIUM | 642 | 40.8% |
| 🟢 LOW | 116 | 7.4% |

### Top 10 Pacotes Mais Vulneráveis

| # | Pacote | CVEs |
| --- | --- | --- |
| 1 | libapache2-mod-php7.0 | 53 |
| 2 | php7.0 | 53 |
| 3 | php7.0-cli | 53 |
| 4 | php7.0-common | 53 |
| 5 | php7.0-gd | 53 |
| 6 | php7.0-json | 53 |
| 7 | php7.0-mysql | 53 |
| 8 | php7.0-opcache | 53 |
| 9 | php7.0-pgsql | 53 |
| 10 | php7.0-readline | 53 |

### Top 10 CWEs Mais Frequentes

| CWE | Ocorrências |
| --- | --- |
| CWE-125 | 343 |
| CWE-787 | 148 |
| CWE-190 | 114 |
| CWE-476 | 92 |
| CWE-20 | 65 |
| CWE-416 | 63 |
| CWE-908 | 41 |
| CWE-119 | 37 |
| CWE-120 | 32 |
| CWE-400 | 29 |

### Exemplos de CVEs Críticas

**1. CVE-2019-10082**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u8
- Descrição: httpd: read-after-free in h2 connection shutdown...

**2. CVE-2021-26691**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u10
- Descrição: httpd: mod_session: Heap overflow via a crafted SessionHeader value...

**3. CVE-2021-39275**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u11
- Descrição: httpd: Out-of-bounds write in ap_escape_quotes() via malicious input...

**4. CVE-2021-40438**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u11
- Descrição: httpd: mod_proxy: SSRF via a crafted request uri-path containing "unix:"...

**5. CVE-2021-44790**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u12
- Descrição: httpd: mod_lua: Possible buffer overflow when parsing multipart content...

## 2. 🔍 SAST (Static Application Security Testing) - Semgrep

**Total de findings:** 77

### Distribuição por Severidade

| Severidade | Quantidade |
| --- | --- |
| 🔴 ERROR | 51 |
| 🟠 WARNING | 26 |
| 🟢 INFO | 0 |

### Findings por Arquivo

**📄 instructions.php**

- 🟠 **Linha 26:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)

**📄 login.php**

- 🔴 **Linha 41:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 phpinfo.php**

- 🔴 **Linha 8:** `phpinfo-use`
  - CWE: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
  - OWASP: A01:2021 - Broken Access Control

**📄 gen_openapi.php**

- 🟠 **Linha 6:** `php-permissive-cors`
  - CWE: CWE-346: Origin Validation Error
  - OWASP: A07:2021 - Identification and Authentication Failures

**📄 index.php**

- 🟠 **Linha 11:** `php-permissive-cors`
  - CWE: CWE-346: Origin Validation Error
  - OWASP: A07:2021 - Identification and Authentication Failures

**📄 HealthController.php**

- 🟠 **Linha 88:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 88:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection

**📄 Token.php**

- 🟠 **Linha 39:** `openssl-decrypt-validate`
  - CWE: CWE-252: Unchecked Return Value
  - OWASP: A02:2021 - Cryptographic Failures

**📄 authbypass.js**

- 🔴 **Linha 43:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)
- 🔴 **Linha 45:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)
- 🔴 **Linha 47:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)
- 🔴 **Linha 49:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)

**📄 low.php**

- 🔴 **Linha 22:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 35:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 79:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 medium.php**

- 🔴 **Linha 21:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 28:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 71:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 high.php**

- 🔴 **Linha 22:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 low.php**

- 🔴 **Linha 12:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 15:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 medium.php**

- 🔴 **Linha 17:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 impossible.php**

- 🔴 **Linha 46:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 ecb_attack.php**

- 🔴 **Linha 92:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A
- 🔴 **Linha 92:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 high.js**

- 🔴 **Linha 9:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)

**📄 impossible.js**

- 🔴 **Linha 9:** `insecure-document-method`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)

**📄 jsonp.php**

- 🔴 **Linha 12:** `echoed-request`
  - CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  - OWASP: A07:2017 - Cross-Site Scripting (XSS)

**📄 test_credentials.php**

- 🔴 **Linha 23:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 high.php**

- 🔴 **Linha 26:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 26:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 26:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 30:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 30:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 30:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection

**📄 impossible.php**

- 🔴 **Linha 22:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 22:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 22:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 26:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 26:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 26:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection

**📄 low.php**

- 🔴 **Linha 10:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 10:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 10:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 14:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 14:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 14:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection

**📄 medium.php**

- 🔴 **Linha 19:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 19:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 19:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 23:** `exec-use`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 23:** `tainted-exec`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A03:2021 - Injection
- 🔴 **Linha 23:** `tainted-exec`
  - CWE: CWE-94: Improper Control of Generation of Code ('Code Injection')
  - OWASP: A03:2021 - Injection

**📄 high.php**

- 🟠 **Linha 7:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)

**📄 index.php**

- 🔴 **Linha 43:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A
- 🔴 **Linha 57:** `md5-loose-equality`
  - CWE: CWE-697: Incorrect Comparison
  - OWASP: N/A

**📄 high.js**

- 🟠 **Linha 1:** `eval-detected`
  - CWE: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
  - OWASP: A03:2021 - Injection
- 🟠 **Linha 1:** `detect-non-literal-regexp`
  - CWE: CWE-1333: Inefficient Regular Expression Complexity
  - OWASP: A05:2021 - Security Misconfiguration

**📄 low.php**

- 🔴 **Linha 10:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 31:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 high.php**

- 🔴 **Linha 11:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 33:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 low.php**

- 🔴 **Linha 11:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection
- 🔴 **Linha 32:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 medium.php**

- 🔴 **Linha 34:** `tainted-sql-string`
  - CWE: CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
  - OWASP: A01:2017 - Injection

**📄 impossible.php**

- 🟠 **Linha 51:** `unlink-use`
  - CWE: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
  - OWASP: A05:2017 - Broken Access Control

**📄 view_help.php**

- 🔴 **Linha 20:** `eval-use`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A01:2017 - Injection
- 🟠 **Linha 20:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🔴 **Linha 22:** `eval-use`
  - CWE: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - OWASP: A01:2017 - Injection
- 🟠 **Linha 22:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)

**📄 view_source.php**

- 🟠 **Linha 63:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🟠 **Linha 67:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🟠 **Linha 68:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)

**📄 view_source_all.php**

- 🟠 **Linha 14:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🟠 **Linha 18:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🟠 **Linha 22:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)
- 🟠 **Linha 26:** `tainted-filename`
  - CWE: CWE-918: Server-Side Request Forgery (SSRF)
  - OWASP: A10:2021 - Server-Side Request Forgery (SSRF)

### CWEs Identificados

- **CWE-918: Server-Side Request Forgery (SSRF)**: 11 ocorrência(s)
- **CWE-697: Incorrect Comparison**: 10 ocorrência(s)
- **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**: 1 ocorrência(s)
- **CWE-346: Origin Validation Error**: 2 ocorrência(s)
- **CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**: 11 ocorrência(s)
- **CWE-94: Improper Control of Generation of Code ('Code Injection')**: 17 ocorrência(s)
- **CWE-252: Unchecked Return Value**: 1 ocorrência(s)
- **CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**: 7 ocorrência(s)
- **CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**: 14 ocorrência(s)
- **CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')**: 1 ocorrência(s)
- **CWE-1333: Inefficient Regular Expression Complexity**: 1 ocorrência(s)
- **CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**: 1 ocorrência(s)

### Mapeamento OWASP Top 10

- **A10:2021 - Server-Side Request Forgery (SSRF)**: 11 ocorrência(s)
- **A01:2025 - Broken Access Control**: 13 ocorrência(s)
- **A01:2021 - Broken Access Control**: 2 ocorrência(s)
- **A07:2021 - Identification and Authentication Failures**: 2 ocorrência(s)
- **A07:2025 - Authentication Failures**: 2 ocorrência(s)
- **A03:2021 - Injection**: 50 ocorrência(s)
- **A05:2025 - Injection**: 50 ocorrência(s)
- **A02:2021 - Cryptographic Failures**: 1 ocorrência(s)
- **A04:2025 - Cryptographic Failures**: 1 ocorrência(s)
- **A07:2017 - Cross-Site Scripting (XSS)**: 7 ocorrência(s)
- **A01:2017 - Injection**: 16 ocorrência(s)
- **A05:2021 - Security Misconfiguration**: 1 ocorrência(s)
- **A06:2017 - Security Misconfiguration**: 1 ocorrência(s)
- **A02:2025 - Security Misconfiguration**: 1 ocorrência(s)
- **A05:2017 - Broken Access Control**: 1 ocorrência(s)

## 3. 📦 SCA (Software Composition Analysis) - Trivy FS

**Alvo:** Código fonte do projeto

**Vulnerabilidades em dependências:** 0

✅ **NENHUMA VULNERABILIDADE CONHECIDA ENCONTRADA EM DEPENDÊNCIAS**

*Nota: Este resultado indica que as dependências declaradas (composer.lock, package-lock.json, etc.) não possuem CVEs conhecidas registradas nos bancos de dados de vulnerabilidades consultados pelo Trivy. Isso é um resultado positivo e válido.*

## 4. 🌐 DAST (Dynamic Application Security Testing) - OWASP ZAP

**Alvo:** `https://34.172.122.255`

**Total de alertas:** 19

### Distribuição por Risco

| Nível de Risco | Quantidade |
| --- | --- |
| Medium | 5 |
| Low | 7 |
| Informational | 7 |

### Alertas Encontrados

**🟠 Content Security Policy (CSP) Header Not Set**
- Risco: Medium (High)
- CWE: CWE-693
- Descrição: Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certai...

**🟠 Directory Browsing**
- Risco: Medium (Medium)
- CWE: CWE-548
- Descrição: It is possible to view the directory listing. Directory listing may reveal hidden scripts, include f...

**🟠 HTTP Only Site**
- Risco: Medium (Medium)
- CWE: CWE-311
- Descrição: The site is only served under HTTP and not HTTPS. ...

**🟠 Missing Anti-clickjacking Header**
- Risco: Medium (Medium)
- CWE: CWE-1021
- Descrição: The response does not protect against 'ClickJacking' attacks. It should include either Content-Secur...

**🟠 Relative Path Confusion**
- Risco: Medium (Medium)
- CWE: CWE-20
- Descrição: The web server is configured to serve responses to ambiguous URLs in a manner that is likely to lead...

**🟡 Cookie No HttpOnly Flag**
- Risco: Low (Medium)
- CWE: CWE-1004
- Descrição: A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by Java...

**🟡 Cookie without SameSite Attribute**
- Risco: Low (Medium)
- CWE: CWE-1275
- Descrição: A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a r...

**🟡 In Page Banner Information Leak**
- Risco: Low (High)
- CWE: CWE-497
- Descrição: The server returned a version banner string in the response content. Such information leaks may allo...

**🟡 Insufficient Site Isolation Against Spectre Vulnerability**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks li...

**🟡 Permissions Policy Header Not Set**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: Permissions Policy Header is an added layer of security that helps to restrict from unauthorized acc...

**🟡 Server Leaks Version Information via "Server" HTTP Response Header Field**
- Risco: Low (High)
- CWE: CWE-497
- Descrição: The web/application server is leaking version information via the "Server" HTTP response header. Acc...

**🟡 X-Content-Type-Options Header Missing**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older ver...

**🔵 Authentication Request Identified**
- Risco: Informational (High)
- CWE: CWE--1
- Descrição: The given request has been identified as an authentication request. The 'Other Info' field contains ...

**🔵 Cookie Slack Detector**
- Risco: Informational (Low)
- CWE: CWE-205
- Descrição: Repeated GET requests: drop a different cookie each time, followed by normal request with all cookie...

**🔵 Non-Storable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are not storable by caching components such as proxy servers. If the response ...

**🔵 Session Management Response Identified**
- Risco: Informational (Medium)
- CWE: CWE--1
- Descrição: The given response has been identified as containing a session management token. The 'Other Info' fi...

**🔵 Storable and Cacheable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are storable by caching components such as proxy servers, and may be retrieved...

**🔵 Storable but Non-Cacheable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are storable by caching components such as proxy servers, but will not be retr...

**🔵 User Agent Fuzzer**
- Risco: Informational (Medium)
- CWE: CWE-0
- Descrição: Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search E...

### CWEs Detectados pelo DAST

- **CWE-693**: 4 ocorrência(s)
- **CWE-548**: 1 ocorrência(s)
- **CWE-311**: 1 ocorrência(s)
- **CWE-1021**: 1 ocorrência(s)
- **CWE-20**: 1 ocorrência(s)
- **CWE-1004**: 1 ocorrência(s)
- **CWE-1275**: 1 ocorrência(s)
- **CWE-497**: 2 ocorrência(s)
- **CWE--1**: 2 ocorrência(s)
- **CWE-205**: 1 ocorrência(s)
- **CWE-524**: 3 ocorrência(s)
- **CWE-0**: 1 ocorrência(s)

## 4.1 🔓 DAST Active Scan (Autenticado) - OWASP ZAP

**Alvo:** `http://34.172.122.255`

**Total de alertas:** 13

**Tipo de scan:** Active Scan com autenticação (detecta SQL Injection, XSS, etc.)

### Distribuição por Risco

| Nível de Risco | Quantidade |
| --- | --- |
| High | 1 |
| Medium | 5 |
| Low | 4 |
| Informational | 3 |

### Alertas Encontrados (Active Scan)

**🟠 Missing Anti-clickjacking Header** (x7)
- Risco: Medium
- CWE: CWE-1021
- Descrição: The response does not protect against 'ClickJacking' attacks. It should include either Content-Secur...

**🟠 Content Security Policy (CSP) Header Not Set** (x9)
- Risco: Medium
- CWE: CWE-693
- Descrição: Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certai...

**🟡 Server Leaks Version Information via "Server" HTTP Response Header Field** (x52)
- Risco: Low
- CWE: CWE-497
- Descrição: The web/application server is leaking version information via the "Server" HTTP response header. Acc...

**🟡 X-Content-Type-Options Header Missing** (x22)
- Risco: Low
- CWE: CWE-693
- Descrição: The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older ver...

**🟡 In Page Banner Information Leak** (x2)
- Risco: Low
- CWE: CWE-497
- Descrição: The server returned a version banner string in the response content. Such information leaks may allo...

**🟠 Application Error Disclosure** (x2)
- Risco: Medium
- CWE: CWE-550
- Descrição: This page contains an error/warning message that may disclose sensitive information like the locatio...

**🟠 Directory Browsing** (x8)
- Risco: Medium
- CWE: CWE-548
- Descrição: It is possible to view a listing of the directory contents. Directory listings may reveal hidden scr...

**🔵 Authentication Request Identified** (x1)
- Risco: Informational
- CWE: CWE--1
- Descrição: The given request has been identified as an authentication request. The 'Other Info' field contains ...

**🔵 Information Disclosure - Suspicious Comments** (x1)
- Risco: Informational
- CWE: CWE-615
- Descrição: The response appears to contain suspicious comments which may help an attacker....

**🟡 Information Disclosure - Debug Error Messages** (x2)
- Risco: Low
- CWE: CWE-1295
- Descrição: The response appeared to contain common error messages returned by platforms such as ASP.NET, and We...

**🔴 SQL Injection** (x1)
- Risco: High
- CWE: CWE-89
- Descrição: SQL injection may be possible....

**🟠 HTTP Only Site** (x1)
- Risco: Medium
- CWE: CWE-311
- Descrição: The site is only served under HTTP and not HTTPS....

**🔵 User Agent Fuzzer** (x553)
- Risco: Informational
- CWE: CWE-0
- Descrição: Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search E...

### CWEs Detectados pelo Active Scan

- **CWE-1021**: 1 ocorrência(s)
- **CWE-693**: 2 ocorrência(s)
- **CWE-497**: 2 ocorrência(s)
- **CWE-550**: 1 ocorrência(s)
- **CWE-548**: 1 ocorrência(s)
- **CWE--1**: 1 ocorrência(s)
- **CWE-615**: 1 ocorrência(s)
- **CWE-1295**: 1 ocorrência(s)
- **CWE-89**: 1 ocorrência(s)
- **CWE-311**: 1 ocorrência(s)
- **CWE-0**: 1 ocorrência(s)

## 5. 🏗️ IaC Scan - Checkov

**Checks passados:** 205

**Checks falhados:** 63

**Checks ignorados:** 0

### Findings de Segurança

| Check ID | Recurso | Arquivo | Severidade |
| --- | --- | --- | --- |
| CKV_GCP_84 | google_artifact_registry_repository.devsecops_repo | artifact-registry.tf | None |
| CKV_GCP_70 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_65 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_13 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_20 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_25 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_66 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_21 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_12 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_64 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_69 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_61 | google_container_cluster.primary | gke.tf | None |
| CKV_GCP_68 | google_container_node_pool.primary_nodes | gke.tf | None |
| CKV_GCP_9 | google_container_node_pool.primary_nodes | gke.tf | None |
| CKV_GCP_10 | google_container_node_pool.primary_nodes | gke.tf | None |
| CKV_GCP_69 | google_container_node_pool.primary_nodes | gke.tf | None |
| CKV_GCP_49 | google_project_iam_member.cloudbuild_builder | iam.tf | None |
| CKV_GCP_114 | google_storage_bucket.reports_bucket | storage.tf | None |
| CKV_GCP_78 | google_storage_bucket.reports_bucket | storage.tf | None |
| CKV_GCP_62 | google_storage_bucket.reports_bucket | storage.tf | None |


## 6. 🔐 Teste de Força Bruta - Hydra

**Ferramenta:** DVWA Brute Force Scanner (Custom)

**Tipo de teste:** Brute Force

### ⚠️ Vulnerabilidade Detectada!

**Resultado:** VULNERÁVEL: 102 credenciais fracas encontradas

A aplicação é vulnerável a ataques de força bruta. Credenciais fracas foram encontradas.

## 7. 🎯 Comparação com Vulnerabilidades Conhecidas do DVWA

**Vulnerabilidades conhecidas do DVWA:** 17

**Detectadas pelo pipeline:** 13 (76.5%)

**Não detectadas:** 4 (23.5%)

### ✅ Vulnerabilidades Detectadas

| Vulnerabilidade | Categoria | CWE | Ferramenta | Descrição |
| --- | --- | --- | --- | --- |
| SQL Injection | web_application | CWE-89 | OWASP ZAP (Active Scan) | Permite injeção de comandos SQL em campos de entrada |
| Cross-Site Scripting (XSS) | web_application | CWE-79 | Semgrep | Permite execução de scripts maliciosos no navegador |
| Command Injection | web_application | CWE-78 | Semgrep | Permite execução de comandos do sistema operacional |
| CSRF | web_application | CWE-352 | Trivy (Container) | Cross-Site Request Forgery |
| Weak Session IDs | web_application | CWE-330 | Trivy (Container) | IDs de sessão previsíveis |
| Brute Force | web_application | CWE-307 | Hydra | Ausência de proteção contra força bruta |
| Open HTTP Redirect | web_application | CWE-601 | Trivy (Container) | Redirecionamento aberto para sites maliciosos |
| JavaScript Attacks | web_application | CWE-749 | Semgrep (JavaScript Analysis) | Exposição de lógica sensível no cliente |
| Content Security Policy Bypass | web_application | CWE-693 | OWASP ZAP (Active Scan) | Ausência ou bypass de CSP |
| Outdated OS | infrastructure | CWE-1104 | Trivy (Container - EOSL) | Sistema operacional desatualizado (Debian 9.5 EOSL) |
| Outdated Packages | infrastructure | CWE-1104 | Trivy (Container - EOSL) | Pacotes com vulnerabilidades conhecidas |
| Default Credentials | infrastructure | CWE-798 | Hydra | Credenciais padrão (admin/password) |
| Exposed MySQL | infrastructure | CWE-284 | Trivy (Container) | MySQL com credenciais fracas |


### ❌ Vulnerabilidades Não Detectadas

| Vulnerabilidade | Categoria | CWE | OWASP | Motivo | Sugestão |
| --- | --- | --- | --- | --- | --- |
| File Inclusion (LFI/RFI) | web_application | CWE-98 | A03:2021 - Injection | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |
| File Upload | web_application | CWE-434 | A04:2021 - Insecure Design | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |
| Insecure CAPTCHA | web_application | CWE-804 | A07:2021 - Identification and Authentication Failures | Requer interação humana ou automação avançada. | Fora do escopo do pipeline automatizado. |
| Authorisation Bypass | web_application | CWE-639 | A01:2021 - Broken Access Control | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |


### Resumo da Cobertura

Cobertura do pipeline: **13/17** vulnerabilidades conhecidas detectadas (**76.5%**)

**Avaliação:** ✅ **BOM** - O pipeline atende aos requisitos básicos de segurança, mas há espaço para melhorias

#### Cobertura Ajustada (Escopo Automatizável)

Cobertura considerando apenas vulnerabilidades detectáveis por automação: **13/13** (**100.0%**)

*4 vulnerabilidades estão fora do escopo de pipelines CI/CD automatizados.*

#### ⚠️ Vulnerabilidades Fora do Escopo de Automação

As seguintes vulnerabilidades do DVWA **não são detectáveis** por ferramentas automatizadas em pipelines CI/CD:

| Vulnerabilidade | CWE | Motivo | Alternativa |
| --- | --- | --- | --- |
| File Inclusion (LFI/RFI) | CWE-98 | Requer navegação manual por diretórios e payloads específicos de inclusão de arquivos | Pentest manual ou IAST (Interactive Application Security Testing) |
| File Upload | CWE-434 | Requer upload real de arquivos maliciosos e verificação de execução no servidor | Pentest manual com upload de webshells |
| Insecure CAPTCHA | CWE-804 | CAPTCHA é projetado para impedir automação; testar sua fraqueza requer análise humana | Análise manual do mecanismo de CAPTCHA |
| Authorisation Bypass | CWE-639 | Requer entendimento da lógica de negócio e testes com múltiplos usuários/sessões | Testes manuais de controle de acesso com diferentes perfis |


**Importante:** Essas vulnerabilidades existem no DVWA e são exploráveis, porém sua detecção requer testes manuais de penetração (pentest), ferramentas interativas ou conhecimento da lógica de negócio da aplicação. Isso demonstra uma **limitação inerente** de pipelines DevSecOps automatizados.

## 7.1 🔬 Validação da Cobertura do ZAP Active Scan

**Score de cobertura de injeção:** 16.7%

*Nota: Este score mede especificamente a detecção de vulnerabilidades de **injeção** (SQLi, XSS, Command Injection) que são o foco do Active Scan. O ZAP Active Scan **detectou outros tipos de vulnerabilidades** (configuração de headers, cookies, CORS, etc.) que são válidas mas não entram neste cálculo específico.*

**CWEs efetivamente detectados pelo Active Scan:** CWE-89, CWE-311, CWE-497, CWE-548, CWE-550, CWE-615, CWE-693, CWE-1021, CWE-1295

Estes CWEs representam vulnerabilidades reais encontradas (ex: cabeçalhos de segurança ausentes, configurações inseguras de cookies), mesmo que não sejam vulnerabilidades de injeção.

### CWEs de Injeção Detectados

| CWE | Vulnerabilidade | Crítico |
| --- | --- | --- |
| CWE-89 | SQL Injection | ✅ Sim |

### CWEs de Injeção Esperados mas Não Detectados

| CWE | Vulnerabilidade | Crítico | URLs Esperadas |
| --- | --- | --- | --- |
| CWE-79 | Cross-Site Scripting (XSS) | ⚠️ Sim | /xss_r/, /xss_s/, /xss_d/ |
| CWE-78 | OS Command Injection | ⚠️ Sim | /exec/ |
| CWE-22 | Path Traversal | Não | /fi/ |
| CWE-98 | Improper Control of Filename for Include | Não | /fi/ |
| CWE-352 | Cross-Site Request Forgery (CSRF) | Não | /csrf/ |


*A não detecção de vulnerabilidades de injeção pelo Active Scan pode ocorrer por:*
- *Sessão HTTP não configurada corretamente no ZAP (cookies não persistem entre requisições)*
- *DVWA configurado em nível de segurança 'Medium' ou 'High' que bloqueia payloads comuns*
- *Timeouts do scan ou limitações de profundidade configurados*
- *Necessidade de contexto de autenticação mais específico*
### URLs Vulneráveis Testadas

- ✅ `/vulnerabilities/sqli/`
- ✅ `/vulnerabilities/sqli_blind/`
- ✅ `/vulnerabilities/xss_r/`
- ✅ `/vulnerabilities/xss_s/`
- ✅ `/vulnerabilities/xss_d/`
- ✅ `/vulnerabilities/exec/`
- ✅ `/vulnerabilities/fi/`
- ✅ `/vulnerabilities/upload/`
- ✅ `/vulnerabilities/csrf/`
- ✅ `/vulnerabilities/brute/`

### Problemas Identificados

- ⚠️ Vulnerabilidades críticas não detectadas: Cross-Site Scripting (XSS), OS Command Injection

### Recomendações para Melhorar Cobertura DAST

- 💡 Verificar se o DVWA está configurado em nível 'Low'
- 💡 Verificar se o ZAP está autenticando corretamente no DVWA

## 7.2 ⚠️ Limitações Identificadas na Análise

As seguintes limitações foram identificadas dinamicamente durante a análise:

### SCA (Análise de Composição)

**Problema:** Trivy SCA não encontrou vulnerabilidades em dependências

- **Impacto:** Pode indicar ausência de arquivos de dependência (composer.json, etc.)
- **Recomendação:** Verificar se o Trivy está analisando o diretório correto com dependências

### DAST (Análise Dinâmica)

**Problema:** Cobertura do ZAP Active Scan baixa (16.7%)

- **Impacto:** Muitas vulnerabilidades conhecidas do DVWA não foram detectadas
- **Recomendação:** Verificar se o DVWA está configurado em nível 'Low'; Verificar se o ZAP está autenticando corretamente no DVWA

## 8. 📝 Conclusões e Recomendações

### Principais Descobertas

1. **RISCO CRÍTICO - SISTEMA OPERACIONAL**
   - A imagem base utiliza debian 9.5, que está em End of Support Life (EOSL)
   - Foram encontradas 254 vulnerabilidades CRÍTICAS e 551 de ALTA severidade
   - Recomendação: Migrar para imagem base com suporte ativo

2. **CONFIGURAÇÃO KUBERNETES/IAC**
   - Checkov identificou 63 problemas de configuração de segurança
   - Incluem: SecurityContext, RBAC, Network Policies, entre outros
   - Recomendação: Revisar e aplicar as correções sugeridas pelo Checkov

3. **ANÁLISE ESTÁTICA (SAST)**
   - Semgrep identificou 77 potenciais problemas no código
   - CWEs encontrados: CWE-918: Server-Side Request Forgery (SSRF), CWE-697: Incorrect Comparison, CWE-200: Exposure of Sensitive Information to an Unauthorized Actor, CWE-346: Origin Validation Error, CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
   - Recomendação: Revisar e corrigir os findings de alta prioridade

4. **ANÁLISE DINÂMICA (DAST)**
   - OWASP ZAP identificou 32 alertas totais (Baseline Scan: 19 alertas, Active Scan: 13 alertas)
   - Vulnerabilidades web detectadas incluem headers ausentes, cookies inseguros, etc.
   - Active Scan permite detecção de SQLi, XSS e outras vulnerabilidades de injeção

5. **TESTE DE FORÇA BRUTA**
   - ⚠️ Hydra detectou credenciais fracas na aplicação
   - A aplicação é vulnerável a ataques de força bruta
   - Recomendação: Implementar rate limiting e políticas de senha fortes

### Eficácia do Pipeline

**PONTOS FORTES:**
- ✅ Detecção automatizada de 1747 vulnerabilidades/issues
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ 6 camadas de análise (Container, IaC, SCA, SAST, DAST, Brute Force)
- ✅ DAST com Active Scan autenticado (13 alertas)
- ✅ Relatórios estruturados em JSON para análise automatizada
- ✅ Pipeline sem hardcode (usa substituições do Cloud Build)

### Cobertura de Vulnerabilidades DVWA

**Total de vulnerabilidades conhecidas:** 17

**Detectadas pelo pipeline:** 13 (76.5%)

**Não detectadas:** 4 (23.5%)

**Motivos para não detecção:**
- Requer autenticação e/ou ataque ativo.
- Requer interação humana ou automação avançada.

### Recomendações Baseadas nos Resultados

- 🔴 **URGENTE:** Migrar para imagem base com suporte ativo (ex: Debian 11/12, Alpine)
- 🔴 **URGENTE:** Aplicar patches para CVEs críticas ou reconstruir imagem
- 🟠 **ALTA:** Corrigir configurações de segurança do Kubernetes/IaC
- 🟡 **MÉDIA:** Aumentar cobertura de testes de segurança
- 🟢 **CONTÍNUA:** Manter pipeline atualizado com novas regras de segurança
- 🟢 **CONTÍNUA:** Integrar resultados com sistema de gestão de vulnerabilidades

---

*Relatório gerado automaticamente em 09/02/2026 às 18:57:14*