# Detecção Direta versus Indireta em Pipelines DevSecOps: Análise de Ruído Taxonômico e Calibração de Portões de Segurança Progressivos

Este repositório contém o pacote de artefatos do artigo **"Detecção Direta versus Indireta em Pipelines DevSecOps: Análise de Ruído Taxonômico e Calibração de Portões de Segurança Progressivos"**, aceito no XXVI Simpósio Brasileiro de Cibersegurança (SBSeg 2026).

**Resumo do artigo:** A agregação de achados em pipelines DevSecOps multicamada apoia-se em taxonomias comuns como CWE e CVSS, que ocultam uma assimetria operacional: uma mesma categoria de fraqueza pode ser reportada tanto como falha aplicacional identificada diretamente no código-fonte, quanto como CVE detectada em componentes da stack cujo CWE coincide com essa categoria. Tratar ambas como equivalentes inflaciona métricas de cobertura e contribui para a fadiga de alertas. Este trabalho formaliza a distinção entre detecções diretas e indiretas e caracteriza sua prevalência em um pipeline de seis camadas executado contra uma aplicação web alvo controlada (DVWA). A partir dessa caracterização, deriva-se um modelo de portões de segurança progressivos que incorpora tal distinção, avaliado por simulação de três políticas.

**Objetivo do artefato:** permitir a reprodução completa das três principais reivindicações do artigo (Tabelas 3, 4 e 5) a partir dos relatórios JSON brutos coletados pelo pipeline, do script de normalização/classificação e do script de simulação de políticas. Toda a análise é **determinística** e opera sobre dados pré-coletados: não é necessário provisionar infraestrutura em nuvem nem executar a aplicação vulnerável.

# Estrutura do readme.md

Este README está organizado nas seguintes seções:

- **Selos Considerados**: selos solicitados ao Comitê Técnico de Artefatos.
- **Informações básicas**: ambiente de execução, requisitos de hardware e software.
- **Dependências**: linguagens, bibliotecas e dados necessários.
- **Preocupações com segurança**: riscos (ou ausência deles) para os avaliadores.
- **Instalação**: passo a passo para obter e preparar o artefato.
- **Teste mínimo**: execução rápida para validar a instalação.
- **Experimentos**: reprodução das três reivindicações principais do artigo, uma subseção por reivindicação.
- **LICENSE**: licença do artefato.

O repositório está organizado da seguinte forma:

```
├── README.md              # este arquivo
├── LICENSE
├── data/
│   └── raw/               # relatórios JSON originais consumidos pelo script
│       ├── reports-0a8e877_trivy-report.json          # Container Scan (1.575 CVEs)
│       ├── reports-0a8e877_semgrep-report.json        # SAST
│       ├── reports-0a8e877_trivy-sca-report.json      # SCA
│       ├── reports-0a8e877_checkov-terraform.json     # IaC Scan (Terraform)
│       ├── reports-0a8e877_checkov-k8s.json           # IaC Scan (Kubernetes)
│       ├── reports-0a8e877_zap-report.json            # DAST Baseline
│       ├── reports-0a8e877_zap-auth-active-report.json # DAST Active autenticado
│       └── reports-0a8e877_hydra-bruteforce.json      # módulo de teste de credenciais*
├── src/
│   └── analise_artigo.py  # script único: normalização, matriz DVWA,
│                          # classificação direto/indireto e simulação P1/P2/P3
├── scripts/
│   ├── run_all.sh         # executa a análise e compara com a saída esperada
│   ├── claim1_conjunto.sh # Reivindicação 1 (Tabela 3)
│   ├── claim2_cobertura.sh # Reivindicação 2 (Tabela 4)
│   └── claim3_politicas.sh # Reivindicação 3 (Tabela 5)
├── expected/
│   └── numeros_secao6.json # saída de referência (todos os números da Seção 6)
├── output/                # gerado na execução (comparado com expected/)
├── docs/                  # documentação complementar (opcional)
└── collection/            # proveniência da coleta (opcional, não executado
                           # pelos revisores): módulo de brute force, Terraform
```

\* O nome `hydra-bruteforce` é legado da fase exploratória; o arquivo contém a saída do módulo Python próprio de teste de credenciais descrito na Seção 5.2 do artigo.

# Selos Considerados

Os selos considerados são: **Artefatos Disponíveis (SeloD)**, **Artefatos Funcionais (SeloF)**, **Artefatos Sustentáveis (SeloS)** e **Experimentos Reprodutíveis (SeloR)**.

# Informações básicas

O artefato consiste em scripts Python que processam relatórios JSON pré-coletados. A execução não requer acesso à internet não requer infraestrutura em nuvem e não executa a aplicação vulnerável.

**Requisitos de hardware:**

- CPU: qualquer processador x86_64 ou ARM64 moderno (1 núcleo é suficiente)
- RAM: 1 GB livre
- Disco: 200 MB livres (repositório + dependências)

**Requisitos de software:**

- Sistema operacional: Linux (testado em Ubuntu 24.04 LTS), macOS ou Windows com WSL2
- Python 3.9 ou superior (o script usa anotações de tipo com genéricos nativos, ex. `list[str]`)
- `bash` para os scripts auxiliares
- Nenhuma biblioteca externa é necessária (ver Dependências)

**Tempo esperado de execução:** cada reivindicação executa em menos de 1 minuto; a suíte completa (`run_all.sh`) executa em menos de 5 minutos em hardware modesto.

**Contexto de coleta dos dados (não requerido para reprodução):** os relatórios JSON em `data/raw/` foram gerados por um pipeline de 15 etapas orquestrado pelo Google Cloud Build, executando Semgrep (SAST), Trivy FS (SCA), Trivy Container (Container Scan), Checkov (IaC Scan), OWASP ZAP em fases Baseline e Active (DAST) e um módulo Python de teste de credenciais, contra a aplicação-alvo Damn Vulnerable Web Application (DVWA, imagem `vulnerables/web-dvwa`) em nível de segurança baixo, hospedada em cluster GKE provisionado por Terraform. A reprodução das reivindicações do artigo **não** requer a reexecução desse pipeline, pois a análise é determinística sobre os relatórios coletados.

# Dependências

**Linguagem:** Python 3.9+

**Bibliotecas:** o script utiliza **exclusivamente a biblioteca padrão do Python** (`json`, `pathlib`, `collections`, `dataclasses`, `typing`). Nenhuma dependência externa precisa ser instalada; não há `requirements.txt`.

**Benchmark/dados:** os dados de entrada são os relatórios JSON incluídos em `data/raw/`, gerados contra a DVWA conforme descrito na Seção 5 do artigo. A matriz de referência (dicionário `DVWA`, 17 vulnerabilidades: 13 automatizáveis e 4 fora do escopo de automação) está embutida em `src/analise_artigo.py`, com CWE, camada de detecção e critérios de correspondência por entrada, e é o ground truth da classificação. Nenhum recurso de terceiros ou credencial é necessário.

# Preocupações com segurança

**A execução deste artefato não oferece risco aos avaliadores.** Os scripts:

- **não** executam a aplicação vulnerável (DVWA) nem qualquer componente dela;
- **não** realizam varreduras de segurança, testes de intrusão ou tráfego de rede exploratório;
- **não** requerem privilégios elevados;
- operam exclusivamente em leitura sobre os relatórios JSON pré-coletados incluídos no repositório, produzindo saídas textuais/tabulares.

Os relatórios em `data/raw/` contêm identificadores públicos de vulnerabilidades (CVEs, CWEs) referentes a uma aplicação deliberadamente vulnerável de uso educacional amplamente conhecido; não contêm segredos, credenciais reais ou dados pessoais.

# Instalação

```bash
# 1. Clonar o repositório
git clone https://github.com/Machada1/[NOME-DO-REPO].git
cd [NOME-DO-REPO]

# 2. Verificar a versão do Python (>= 3.9)
python3 --version
```

Não há etapa de instalação de dependências: o clone do repositório é suficiente para a execução.

# Teste mínimo

O teste mínimo executa a análise completa (a execução integral leva menos de 1 minuto) e confere o número central do conjunto de avaliação:

```bash
python3 src/analise_artigo.py
python3 -c "import json; d=json.load(open('output/numeros_secao6.json')); \
print('Total bruto:', d['bruto']['total_bruto']); \
print('Conjunto de avaliação:', d['simulacao']['total_p_simulacao'])"
```

**Saída esperada:** `Total bruto: 1750` e `Conjunto de avaliação: 226`. O relatório completo é impresso no terminal e o arquivo `output/numeros_secao6.json` é gerado com todos os números da Seção 6 do artigo, para comparação com `expected/numeros_secao6.json`.

**Tempo esperado:** inferior a 1 minuto. **Recursos:** < 1 GB RAM.

# Experimentos

As três reivindicações principais do artigo correspondem às Tabelas 3, 4 e 5. Uma única execução do script produz `output/numeros_secao6.json` com todos os números; os scripts de reivindicação extraem e comparam a seção correspondente contra `expected/numeros_secao6.json`. A análise é determinística: a saída gerada deve ser idêntica à esperada. Para executar tudo em sequência:

```bash
./scripts/run_all.sh
```

## Reivindicação #1: Composição do conjunto de avaliação (Tabela 3)

**Afirmação do artigo:** o pipeline emitiu 1.750 ocorrências brutas; após a aplicação da granularidade mista (decomposição do Trivy Container em 3 agregados sintéticos + 48 achados individuais com CWE coincidente com vulnerabilidade aplicacional da matriz), o conjunto de avaliação resulta em **226 achados**.

**Execução:**

```bash
./scripts/claim1_conjunto.sh
```

**Resultado esperado:** seções `bruto` e `simulacao` do JSON gerado idênticas às de `expected/numeros_secao6.json`, correspondendo à composição da Tabela 3:

| Origem | Tipo | Qtd. |
|---|---|---|
| Semgrep | individual | 77 |
| Checkov | individual | 63 |
| OWASP ZAP (Baseline) | individual | 19 |
| OWASP ZAP (Active) | individual | 14 |
| Brute Force | individual | 2 |
| Trivy Container (CWE coincidente APP) | individual | 48 |
| Trivy Container (Outdated OS) | agregado | 1 |
| Trivy Container (Outdated Packages) | agregado | 1 |
| Trivy Container (demais CVEs do SO) | agregado | 1 |
| **Total** | | **226** |

**Tempo esperado:** < 1 min. **Recursos:** < 1 GB RAM / < 100 MB disco.

## Reivindicação #2: Cobertura DVWA e classificação direto/indireto (Tabela 4)

**Afirmação do artigo:** o pipeline alcança cobertura total das 13 vulnerabilidades automatizáveis da DVWA (13/13), porém com distribuição assimétrica: 10 são detectadas diretamente e 3 (CSRF, Weak Session IDs e Open HTTP Redirect) apenas indiretamente, via CVEs do Container Scan com CWE coincidente. Dos 226 achados elegíveis, 58 (25,7%) são diretos, 48 (21,2%) indiretos e 120 (53,1%) sem correspondência na matriz.

**Execução:**

```bash
./scripts/claim2_cobertura.sh
```

**Resultado esperado:** seções `cobertura` e `volume_classe` do JSON gerado idênticas às esperadas, correspondendo à matriz de cobertura das 13 vulnerabilidades com contagens de achados diretos e indiretos por vulnerabilidade e status final (`direta` / `apenas indireta`), reproduzindo a Tabela 4 do artigo, incluindo: SQL Injection (15 dir. / 8 ind.), XSS (7/15), CSRF (0/1, apenas indireta), Weak Session IDs (0/2, apenas indireta), Open HTTP Redirect (0/8, apenas indireta), e as duas vulnerabilidades de infraestrutura (Outdated OS e Outdated Packages, 1 achado direto agregado cada). Ao final, a decomposição do conjunto: 58 diretos / 48 indiretos / 120 sem matriz.

**Tempo esperado:** < 1 min. **Recursos:** < 1 GB RAM / < 100 MB disco.

## Reivindicação #3: Simulação comparativa das políticas de portão (Tabela 5)

**Afirmação do artigo:** sobre os 226 achados, a política P1 (CVSS ≥ 9,0, uniforme) dispara 5 bloqueios; P2 (CVSS ≥ 7,0, uniforme) dispara 80; P3 (CVSS ≥ 7,0, indiretos não bloqueantes) dispara 56. A diferença entre P2 e P3 (24 bloqueios, redução de 30%) corresponde exatamente aos achados indiretos bloqueados por P2. A cobertura bloqueante é 3/13 (P1), 11/13 (P2) e 8/13 (P3); a cobertura sinalizada permanece 13/13 em todas.

**Execução:**

```bash
./scripts/claim3_politicas.sh
```

**Resultado esperado:** seção `politicas` do JSON gerado idêntica à esperada, correspondendo à Tabela 5:

| Política | Bloqueios | % bloq. | Diretos | Indiretos | Sem matriz |
|---|---|---|---|---|---|
| P1 | 5 | 2,2% | 2 | 2 | 1 |
| P2 | 80 | 35,4% | 29 | 24 | 27 |
| P3 | 56 | 24,8% | 29 | 0 | 27 |

Adicionalmente, a distribuição por estágio impressa no terminal: P1 concentra os 5 bloqueios no Build Gate; P2 dispara 51 no Commit, 27 no Build e 2 no Deploy; P3 mantém 51 no Commit e 2 no Deploy, reduzindo o Build de 27 para 3.

**Tempo esperado:** < 1 min. **Recursos:** < 1 GB RAM / < 100 MB disco.

# LICENSE

Este artefato é distribuído sob a licença **MIT** (ver arquivo `LICENSE`).

> **[AJUSTAR]** Confirmar a licença desejada com os coautores. MIT é a escolha mais simples e amigável à avaliação; se os dados ou algum componente exigirem outra licença, declarar aqui.
