#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f output/numeros_secao6.json ] || python3 src/analise_artigo.py
python3 - <<'EOF'
import json, sys
with open("output/numeros_secao6.json", encoding="utf-8") as fh:
    got = json.load(fh)
with open("expected/numeros_secao6.json", encoding="utf-8") as fh:
    exp = json.load(fh)
for sec in ("cobertura", "volume_classe"):
    if got[sec] != exp[sec]:
        sys.exit(f"[FALHA] secao '{sec}' diverge do esperado")
    print(f"[OK] secao '{sec}' identica ao esperado")
c = got["cobertura"]
print(f"Reivindicacao 2 (Tabela 4) reproduzida: "
      f"{c['dir']} diretas, {c['ind']} apenas indiretas, {c['nao']} nao detectadas")
EOF
