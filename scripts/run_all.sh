#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rm -f output/numeros_secao6.json
python3 src/analise_artigo.py
bash scripts/claim1_conjunto.sh
bash scripts/claim2_cobertura.sh
bash scripts/claim3_politicas.sh
echo "Todas as reivindicacoes reproduzidas com sucesso."
