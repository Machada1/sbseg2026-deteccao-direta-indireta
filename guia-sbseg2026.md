# Guia SBSeg 2026: artefato + camera-ready

Prazos: artefato **05/08** (hotcrp), revisão r1 **07 a 20/08**, rebuttal **21/08**, decisão **22 a 27/08**. Camera-ready: deadline a confirmar com os chairs.

Decisão de estrutura: **repositório novo**, não fork. Fork carrega o histórico do TCC (incluindo o tfstate) e o rótulo "forked from" permanente. O artefato tem ~12 arquivos; repo limpo é mais simples e mais forte pro SeloS.

---

## Fase 1: Repositório do artefato

**1.1** Criar repo público novo. Sugestão de nome: `sbseg2026-deteccao-direta-indireta` (ou variação curta). Descrição: "Pacote de artefatos do artigo 'Detecção Direta versus Indireta em Pipelines DevSecOps' (SBSeg 2026)".

**1.2** Montar a estrutura:

```
mkdir -p data/raw src scripts expected output docs collection
```

**1.3** Copiar os arquivos, nesta correspondência:

| De (TCC-DevSecOps ou local) | Para |
|---|---|
| `analise_artigo_v3_1_.py` (após patches da Fase 2) | `src/analise_artigo.py` |
| `Instrumentos/Reports/reports-0a8e877_trivy-report.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_semgrep-report.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_trivy-sca-report.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_checkov-terraform.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_checkov-k8s.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_zap-report.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_zap-auth-active-report.json` | `data/raw/` |
| `Instrumentos/Reports/reports-0a8e877_hydra-bruteforce.json` | `data/raw/` |
| README.md gerado (ajustar nome do repo e licença) | raiz |
| `relatorio-vulnerabilidades.md` (opcional) | `docs/` |
| `dvwa-bruteforce.py`, `hydra.Dockerfile`, `infra/` (opcional) | `collection/` |

Conferir se os nomes em `Instrumentos/Reports/` batem exatamente com os acima (são os nomes que o script espera). Se houver divergência de prefixo, renomear o arquivo, não o código.

**NÃO copiar em hipótese alguma:** `terraform.tfstate`, relatórios HTML do ZAP, qualquer material do TCC (fichamentos, memorial, .tex, guia de defesa).

**1.4** `.gitignore` na raiz:

```
output/
__pycache__/
*.pyc
```

**1.5** `LICENSE`: MIT, após confirmação com Fábio e Caroline (é o último [AJUSTAR] do README).

---

## Fase 2: Código (src/analise_artigo.py)

**Patch 1, obrigatório: caminhos relativos.** Substituir as linhas 37-38:

```python
# ANTES
DATA = Path("/home/claude/artigo-sbseg/data")
OUT = Path("/home/claude/artigo-sbseg/analise/saida")

# DEPOIS
BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "raw"
OUT = BASE / "output"
OUT.mkdir(parents=True, exist_ok=True)
```

O `mkdir` é necessário porque o script grava `OUT / "numeros_secao6.json"` sem criar o diretório, e `output/` está no .gitignore.

**Patch 2, recomendado: exportar estágio e cobertura bloqueante.** O artigo afirma a distribuição por estágio (P2: 51/27/2; P3: 51/3/2) e a cobertura bloqueante (3, 11 e 8 de 13), mas hoje esses números só saem no stdout. Substituir os dois blocos finais de impressão do `main()`:

```python
    print("\n--- Bloqueios por estagio ---")
    print(f"{'Pol':<5s} {'Commit':>8s} {'Build':>8s} {'Deploy':>8s}")
    pol_stages = {}
    for p in ("P1", "P2", "P3"):
        c = Counter()
        for f in findings:
            if apply_policy(p, f):
                c[f.stage_hint] += 1
        pol_stages[p] = {"commit": c["commit"], "build": c["build"],
                         "deploy": c["deploy"]}
        print(f"{p:<5s} {c['commit']:>8d} {c['build']:>8d} {c['deploy']:>8d}")

    print("\n--- Cobertura bloqueante por politica ---")
    cob_bloq = {}
    for p in ("P1", "P2", "P3"):
        hit = set()
        for name, spec in DVWA.items():
            if spec.get("out_of_scope"):
                continue
            for f in findings:
                cls = classify(f, name, spec)
                if cls is None:
                    continue
                if apply_policy(p, f):
                    hit.add(name)
                    break
        cob_bloq[p] = len(hit)
        print(f"  {p}: {len(hit)}/{len(cov_rows)}")
```

E acrescentar as duas chaves no `out_data`, junto de `"politicas": pol_results`:

```python
        "politicas_por_estagio": pol_stages,
        "cobertura_bloqueante": cob_bloq,
```

**2.3** Regenerar a saída esperada **com o código já corrigido**, dentro do repo novo:

```bash
python3 src/analise_artigo.py
cp output/numeros_secao6.json expected/numeros_secao6.json
```

Isso garante que o expected vem da mesma versão de código que o revisor vai executar (com as duas seções novas do Patch 2). Antes de copiar, conferir no terminal: total bruto 1750, conjunto 226, estágios P2 51/27/2 e P3 51/3/2, cobertura bloqueante 3, 11 e 8.

---

## Fase 3: Scripts de reivindicação

`scripts/claim1_conjunto.sh` (Tabela 3):

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f output/numeros_secao6.json ] || python3 src/analise_artigo.py
python3 - << 'EOF'
import json, sys
got = json.load(open("output/numeros_secao6.json"))
exp = json.load(open("expected/numeros_secao6.json"))
for sec in ("bruto", "simulacao"):
    if got[sec] != exp[sec]:
        sys.exit(f"[FALHA] secao '{sec}' diverge do esperado")
    print(f"[OK] secao '{sec}' identica ao esperado")
print("Reivindicacao 1 (Tabela 3) reproduzida:",
      got["simulacao"]["total_p_simulacao"], "achados no conjunto de avaliacao")
EOF
```

`scripts/claim2_cobertura.sh` (Tabela 4): mesmo esqueleto, trocando o laço por

```python
for sec in ("cobertura", "volume_classe"):
```

e a mensagem final por

```python
c = got["cobertura"]
print(f"Reivindicacao 2 (Tabela 4) reproduzida: "
      f"{c['dir']} diretas, {c['ind']} apenas indiretas, {c['nao']} nao detectadas")
```

`scripts/claim3_politicas.sh` (Tabela 5): mesmo esqueleto, com

```python
for sec in ("politicas", "politicas_por_estagio", "cobertura_bloqueante"):
```

e mensagem final

```python
p = got["politicas"]
print(f"Reivindicacao 3 (Tabela 5) reproduzida: "
      f"P1={p['P1']['blocks']}, P2={p['P2']['blocks']}, P3={p['P3']['blocks']} bloqueios")
```

`scripts/run_all.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rm -f output/numeros_secao6.json
python3 src/analise_artigo.py
bash scripts/claim1_conjunto.sh
bash scripts/claim2_cobertura.sh
bash scripts/claim3_politicas.sh
echo "Todas as reivindicacoes reproduzidas com sucesso."
```

Finalizar com `chmod +x scripts/*.sh`.

---

## Fase 4: Validação em ambiente limpo

Exigência prática do CTA: instalar e executar numa máquina virtual nova seguindo **somente** o README.

```bash
vagrant init ubuntu/noble64   # ou box equivalente já usada no lab
vagrant up && vagrant ssh
# dentro da VM:
git clone https://github.com/Machada1/[NOME-DO-REPO].git
cd [NOME-DO-REPO]
python3 --version              # >= 3.9
./scripts/run_all.sh
```

Se qualquer passo exigir algo que não está no README, o README está incompleto: corrigir o README, não o processo. Depois, `vagrant destroy` e repetir uma segunda vez do zero pra confirmar.

Checklist final antes de submeter:

- [ ] `run_all.sh` termina com sucesso na VM limpa, duas vezes
- [ ] README sem nenhum [AJUSTAR] restante
- [ ] LICENSE presente e confirmada com coautores
- [ ] Nenhum tfstate, chave, token ou credencial no repo (rodar `git log --stat` e revisar; opcionalmente `gitleaks detect`)
- [ ] URL do repo definitiva (renomear depois quebra o camera-ready)

---

## Fase 5: Submissão no CTA (até 05/08)

1. Registrar em https://hotcrp.c3sl.ufpr.br/ com: contato dos autores, link do repo, selos solicitados (**os quatro**: D, F, S, R).
2. Apêndice: **não necessário**, o artefato não requer nuvem, chaves ou recursos privados. Declarar isso no registro se houver campo.
3. De 07 a 20/08: verificar o hotcrp **diariamente** (e a caixa de spam). Perguntas de revisores chegam pela plataforma e respostas rápidas contam.
4. 21/08: rebuttal, janela de um dia. Reservar a noite anterior pra rascunhar com os orientadores qualquer resposta pendente.

---

## Fase 6: Camera-ready do artigo

**6.1 Confirmar o deadline** com os chairs ou no JEMS (não veio no e-mail de aceite).

**6.2 Desanonimizar** (obrigatório):

- Bloco `\author` e `\address`: nomes completos e e-mails reais dos três autores.
- Contribuição (iv): trocar `\footnote{URL omitida para revisão anônima.}` pela URL real do repo do artefato.
- Seção 5.3, footnote 2: idem.
- Conclusão, frase "está disponível em repositório anônimo": trocar por "está disponível publicamente em [URL]".

**6.3 Aplicar os 4 blocos** de `snippets-camera-ready.tex`:

| Bloco | Onde entra |
|---|---|
| (1) Parágrafo da classificação estrutural | Seção 4.1, após "...tratá-las diferentemente na decisão de bloqueio." |
| (2) Figura TikZ direto vs indireto | Seção 4.1, após o parágrafo do bloco 1 |
| (3) Listing da matriz | Seção 5.3, após o parágrafo da função central |
| (4) Frase-ponte APP/INFRA | Seção 5.1, após "...13 vulnerabilidades como web_application e 4 como infrastructure." |

Preâmbulo: acrescentar `\usepackage{tikz}` e `\usetikzlibrary{positioning}`.

**6.4 Tabela 5 nas margens:** aplicar `{\small ...}` no tabular e encurtar a primeira coluna pra P1/P2/P3, movendo as definições pra legenda (texto pronto no snippet do turno anterior). Revisar as demais tabelas compiladas contra a margem.

**6.5 Cortes de repetição** (compensam o espaço das adições):

- Seção 2.3: remover a frase final "Este trabalho argumenta que uma dimensão adicional..." (repete a introdução).
- Conclusão, 1º parágrafo: reescrever de redefinição pra síntese ("Este trabalho formalizou e avaliou..." direto aos números, sem reexplicar a assimetria).

**6.6 Legendas autoexplicativas** em todas as figuras e tabelas: cada legenda deve permitir entender o elemento sem ler o corpo do texto. As dos snippets já seguem esse padrão; revisar as Tabelas 1 a 4.

**6.7 Compilar e conferir o limite de páginas** da trilha. Se estourar: encurtar primeiro o parágrafo da circularidade (validade externa), depois reduzir o listing a duas entradas. A figura não sai.

**6.8 Revisão final dos orientadores** antes de submeter.

---

## Fase 7: Higiene do TCC-DevSecOps

1. Remover os leftovers da apresentação (já combinado com orientadores).
2. **tfstate:** se o repo é ou será público, remover do histórico, não só do HEAD:

```bash
pip install git-filter-repo
git clone --mirror git@github.com:Machada1/TCC-DevSecOps.git
cd TCC-DevSecOps.git
git filter-repo --invert-paths --path Instrumentos/Reports/terraform.tfstate
git push --force --mirror
```

(Requer desarquivar temporariamente pra aceitar o push.) Mesmo com o projeto GCP encerrado, tfstate público é má prática e revisor de segurança repara. Aproveitar e rodar `gitleaks detect` no histórico pra caçar chaves de service account esquecidas.

3. Rearquivar depois, se quiser. O README do artefato referencia o TCC como origem do experimento.

---

## Cronograma sugerido

| Até | Entrega |
|---|---|
| 24/07 | Repo criado, patches aplicados, expected regenerado |
| 27/07 | Scripts de reivindicação prontos, primeira validação em VM limpa |
| 01/08 | Revisão dos coautores no README e no repo, segunda validação em VM |
| 03/08 | Registro no hotcrp (buffer de 2 dias sobre o prazo) |
| 07 a 20/08 | Monitoramento diário do hotcrp |
| 21/08 | Rebuttal |
| Em paralelo | Camera-ready: 6.2 a 6.7 podem começar já; só a URL depende da Fase 1 |
