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
for sec in ("politicas", "politicas_por_estagio", "cobertura_bloqueante"):
    if got[sec] != exp[sec]:
        sys.exit(f"[FALHA] secao '{sec}' diverge do esperado")
    print(f"[OK] secao '{sec}' identica ao esperado")
p = got["politicas"]
print(f"Reivindicacao 3 (Tabela 5) reproduzida: "
      f"P1={p['P1']['blocks']}, P2={p['P2']['blocks']}, P3={p['P3']['blocks']} bloqueios")
EOF
