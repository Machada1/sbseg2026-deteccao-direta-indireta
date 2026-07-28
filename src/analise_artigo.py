"""
analise_artigo_v3.py
---------------------
Implementação final da classificação direto/indireto.

REGRA UNICA (em uma frase):
  Para cada par (finding f, vulnerabilidade DVWA v):
  - Se f é evidência agregada de uma condição estrutural da imagem
    que define v (EOSL para Outdated OS, corrigíveis para Outdated
    Packages), o par é direto.
  - Se f vem de SAST/DAST/Brute Force/IaC e seu artefato-alvo
    coincide com a camada de v, o par é direto.
  - Se o CWE de f coincide com o CWE de v mas as camadas diferem,
    o par é indireto.
  - Caso contrário, f não é detecção de v.

GRANULARIDADE:
  - SAST, DAST, IaC, Brute Force: cada finding individual entra na
    simulação.
  - Trivy Container:
      (a) findings que casam por CWE com vulns APP da matriz DVWA
          entram individualmente (são as detecções indiretas
          relevantes);
      (b) os demais findings (que não casam com DVWA) são agregados
          em UM finding sintético "Outdated OS" e UM finding
          sintético "Outdated Packages";
      (c) o conjunto de CVEs sem qualquer match também recebe um
          agregado sintético "Demais CVEs do SO" -- indica risco
          da stack independente da matriz.
"""
import json
from pathlib import Path
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "raw"
OUT = BASE / "output"
OUT.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------
# MODELO DE DADOS
# ---------------------------------------------------------------------
@dataclass
class Finding:
    tool: str
    layer: str           # APP ou INFRA
    stage_hint: str      # commit, build, deploy
    cwes: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    severity_label: Optional[str] = None
    identifier: Optional[str] = None
    target: Optional[str] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------
# MATRIZ DVWA
# ---------------------------------------------------------------------
DVWA = {
    # APP - granularidade fina via CWE
    "SQL Injection":              {"cwe": "CWE-89",   "layer": "APP"},
    "Cross-Site Scripting (XSS)": {"cwe": "CWE-79",   "layer": "APP"},
    "Command Injection":          {"cwe": "CWE-78",   "layer": "APP"},
    "CSRF":                       {"cwe": "CWE-352",  "layer": "APP"},
    "Weak Session IDs":           {"cwe": "CWE-330",  "layer": "APP"},
    "Brute Force":                {"cwe": "CWE-307",  "layer": "APP"},
    "Open HTTP Redirect":         {"cwe": "CWE-601",  "layer": "APP"},
    "JavaScript Attacks":         {"cwe": "CWE-749",  "layer": "APP"},
    "Content Security Policy Bypass": {"cwe": "CWE-693", "layer": "APP"},
    "Default Credentials":        {"cwe": "CWE-798",  "layer": "APP"},
    "Exposed MySQL":              {"cwe": "CWE-284",  "layer": "APP"},
    # INFRA - granularidade agregada
    "Outdated OS":                {"cwe": "CWE-1104", "layer": "INFRA",
                                   "match_via": "agregado_eosl"},
    "Outdated Packages":          {"cwe": "CWE-1104", "layer": "INFRA",
                                   "match_via": "agregado_fixable"},
    # Fora do escopo
    "File Inclusion (LFI/RFI)":   {"cwe": "CWE-98",   "layer": "APP", "out_of_scope": True},
    "File Upload":                {"cwe": "CWE-434",  "layer": "APP", "out_of_scope": True},
    "Insecure CAPTCHA":           {"cwe": "CWE-804",  "layer": "APP", "out_of_scope": True},
    "Authorisation Bypass":       {"cwe": "CWE-639",  "layer": "APP", "out_of_scope": True},
}

# CWEs de APP, para classificar findings INFRA do Trivy como indiretos
APP_CWES = {spec["cwe"] for name, spec in DVWA.items()
            if spec.get("layer") == "APP" and not spec.get("out_of_scope")}


# ---------------------------------------------------------------------
# LOADERS
# ---------------------------------------------------------------------
def load_json(name: str):
    with open(DATA / name, encoding="utf-8") as f:
        return json.load(f)


def _trivy_cvss(v: dict) -> Optional[float]:
    cvss_data = v.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa"):
        if src in cvss_data:
            v3 = cvss_data[src].get("V3Score")
            if v3 is not None:
                return float(v3)
    for vd in cvss_data.values():
        v3 = vd.get("V3Score")
        if v3 is not None:
            return float(v3)
    return None


def load_raw_trivy_container() -> list[dict]:
    """Retorna TODAS as CVEs do Trivy Container como dicts brutos.
    A agregação acontece na função build_findings()."""
    d = load_json("reports-0a8e877_trivy-report.json")
    out = []
    for r in d.get("Results", []):
        target = r.get("Target", "")
        is_eosl_context = "debian 9.5" in target.lower()
        for v in r.get("Vulnerabilities", []) or []:
            out.append({
                "cve": v.get("VulnerabilityID"),
                "pkg": v.get("PkgName"),
                "cwes": list(v.get("CweIDs") or []),
                "cvss": _trivy_cvss(v),
                "severity": v.get("Severity"),
                "fixed_version": v.get("FixedVersion"),
                "status": v.get("Status"),
                "eosl_context": is_eosl_context,
            })
    return out


SEVERITY_PROXY = {
    "ERROR": 7.5, "WARNING": 5.0, "INFO": 3.0,
    "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "CRITICAL": 9.5,
}


def load_semgrep() -> list[Finding]:
    d = load_json("reports-0a8e877_semgrep-report.json")
    out = []
    for r in d.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        raw_cwes = meta.get("cwe") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwes = [c.split(":")[0].strip() for c in raw_cwes if isinstance(c, str)]
        sev = (extra.get("severity") or "INFO").upper()
        out.append(Finding(
            tool="Semgrep", layer="APP", stage_hint="commit",
            cwes=cwes,
            cvss=SEVERITY_PROXY.get(sev),
            severity_label=sev,
            identifier=r.get("check_id"),
            target=r.get("path"),
        ))
    return out


def load_trivy_sca() -> list[Finding]:
    d = load_json("reports-0a8e877_trivy-sca-report.json")
    out = []
    for r in d.get("Results", []):
        for v in r.get("Vulnerabilities", []) or []:
            out.append(Finding(
                tool="Trivy FS (SCA)", layer="APP", stage_hint="commit",
                cwes=list(v.get("CweIDs") or []),
                cvss=_trivy_cvss(v),
                severity_label=v.get("Severity"),
                identifier=v.get("VulnerabilityID"),
                target=v.get("PkgName"),
            ))
    return out


def load_checkov() -> list[Finding]:
    out = []
    for fname in [
        "reports-0a8e877_checkov-terraform.json",
        "reports-0a8e877_checkov-k8s.json",
    ]:
        d = load_json(fname)
        for c in d.get("results", {}).get("failed_checks", []):
            sev = (c.get("severity") or "MEDIUM")
            if sev is None:
                sev = "MEDIUM"
            out.append(Finding(
                tool="Checkov", layer="INFRA", stage_hint="build",
                cwes=[],
                cvss=SEVERITY_PROXY.get(sev.upper(), 5.0),
                severity_label=sev,
                identifier=c.get("check_id"),
                target=c.get("resource"),
            ))
    return out


ZAP_RISK_TO_CVSS = {3: 7.5, 2: 5.0, 1: 3.0, 0: 0.0}


def load_zap_baseline() -> list[Finding]:
    d = load_json("reports-0a8e877_zap-report.json")
    out = []
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            risk = a.get("riskcode")
            try:
                risk_int = int(risk) if risk is not None else None
            except (ValueError, TypeError):
                risk_int = None
            cvss = ZAP_RISK_TO_CVSS.get(risk_int) if risk_int is not None else None
            cwe = a.get("cweid")
            cwes = [f"CWE-{cwe}"] if cwe and cwe != "-1" else []
            out.append(Finding(
                tool="OWASP ZAP (Baseline)", layer="APP", stage_hint="deploy",
                cwes=cwes, cvss=cvss,
                severity_label=a.get("riskdesc"),
                identifier=str(a.get("pluginid") or a.get("alertRef")),
                target=a.get("name"),
            ))
    return out


def load_zap_active() -> list[Finding]:
    d = load_json("reports-0a8e877_zap-auth-active-report.json")
    out = []
    seen = {}
    for a in d.get("alerts", []):
        key = (a.get("pluginId"), a.get("name"))
        if key not in seen:
            seen[key] = a
    for (pid, name), a in seen.items():
        risk = a.get("risk")
        try:
            risk_int = int(risk) if risk is not None else None
        except (ValueError, TypeError):
            risk_int = None
        cvss = ZAP_RISK_TO_CVSS.get(risk_int) if risk_int is not None else None
        cwe = a.get("cweid")
        cwes = [f"CWE-{cwe}"] if cwe and cwe != "-1" else []
        out.append(Finding(
            tool="OWASP ZAP (Active)", layer="APP", stage_hint="deploy",
            cwes=cwes, cvss=cvss,
            severity_label=str(risk),
            identifier=str(pid),
            target=name,
        ))
    return out


def load_bruteforce() -> list[Finding]:
    d = load_json("reports-0a8e877_hydra-bruteforce.json")
    out = []
    if d.get("vulnerable"):
        n_success = len(d.get("successful_logins") or [])
        out.append(Finding(
            tool="Brute Force", layer="APP", stage_hint="deploy",
            cwes=["CWE-307"], cvss=7.5, severity_label="High",
            identifier="bf-rate-limit",
            target=f"{n_success} successful_logins",
        ))
        out.append(Finding(
            tool="Brute Force", layer="APP", stage_hint="deploy",
            cwes=["CWE-798"], cvss=7.5, severity_label="High",
            identifier="bf-default-creds",
            target="admin/password, admin/dvwa",
        ))
    return out


# ---------------------------------------------------------------------
# CONSTRUTOR DE FINDINGS COM GRANULARIDADE MISTA
# ---------------------------------------------------------------------
def build_findings():
    """Retorna a lista final de findings para a simulação, com a
    granularidade adequada conforme o modelo."""
    findings: list[Finding] = []

    # SAST/DAST/IaC/SCA/BF: granularidade fina
    findings += load_semgrep()
    findings += load_trivy_sca()
    findings += load_checkov()
    findings += load_zap_baseline()
    findings += load_zap_active()
    findings += load_bruteforce()

    # Trivy Container: granularidade mista
    raw_trivy = load_raw_trivy_container()

    # (a) CVEs do Trivy que casam por CWE com alguma vuln APP da DVWA
    #     -> entram individualmente como findings INFRA
    eosl_present = any(c["eosl_context"] for c in raw_trivy)
    fixable_present = any(c.get("fixed_version") for c in raw_trivy)
    has_app_cwe_match = []
    no_app_cwe_match = []

    for c in raw_trivy:
        if any(cwe in APP_CWES for cwe in c["cwes"]):
            has_app_cwe_match.append(c)
        else:
            no_app_cwe_match.append(c)

    for c in has_app_cwe_match:
        findings.append(Finding(
            tool="Trivy Container",
            layer="INFRA",
            stage_hint="build",
            cwes=c["cwes"],
            cvss=c["cvss"],
            severity_label=c["severity"],
            identifier=c["cve"],
            target=c["pkg"],
            extra={"granularity": "individual_app_match"},
        ))

    # (b) Findings agregados para Outdated OS e Outdated Packages
    if eosl_present:
        n_total = len(raw_trivy)
        max_cvss = max((c["cvss"] for c in raw_trivy if c["cvss"] is not None),
                       default=10.0)
        findings.append(Finding(
            tool="Trivy Container",
            layer="INFRA",
            stage_hint="build",
            cwes=["CWE-1104"],
            cvss=max_cvss,
            severity_label="CRITICAL",
            identifier="agg-outdated-os",
            target=f"Debian 9.5 EOSL ({n_total} CVEs underlying)",
            extra={"granularity": "aggregate_eosl"},
        ))
    if fixable_present:
        fixables = [c for c in raw_trivy if c.get("fixed_version")]
        max_cvss = max((c["cvss"] for c in fixables if c["cvss"] is not None),
                       default=10.0)
        findings.append(Finding(
            tool="Trivy Container",
            layer="INFRA",
            stage_hint="build",
            cwes=["CWE-1104"],
            cvss=max_cvss,
            severity_label="HIGH",
            identifier="agg-outdated-packages",
            target=f"{len(fixables)} packages with FixedVersion",
            extra={"granularity": "aggregate_fixable"},
        ))

    # (c) Demais CVEs do SO (sem match com DVWA) agregadas em 1 finding
    if no_app_cwe_match:
        max_cvss = max((c["cvss"] for c in no_app_cwe_match if c["cvss"] is not None),
                       default=10.0)
        findings.append(Finding(
            tool="Trivy Container",
            layer="INFRA",
            stage_hint="build",
            cwes=[],
            cvss=max_cvss,
            severity_label="HIGH",
            identifier="agg-other-os-cves",
            target=f"{len(no_app_cwe_match)} CVEs without DVWA CWE match",
            extra={"granularity": "aggregate_other"},
        ))

    return findings, raw_trivy


# ---------------------------------------------------------------------
# CLASSIFICAÇÃO
# ---------------------------------------------------------------------
def classify(finding: Finding, vuln_name: str, vuln_spec: dict) -> Optional[str]:
    """Retorna 'direta', 'indireta' ou None para o par (finding, vuln)."""
    if vuln_spec.get("out_of_scope"):
        return None

    granularity = finding.extra.get("granularity")
    cwe_v = vuln_spec["cwe"]
    layer_v = vuln_spec["layer"]

    # Caso 1: agregado EOSL é direto de Outdated OS
    if granularity == "aggregate_eosl" and vuln_name == "Outdated OS":
        return "direta"
    # Caso 2: agregado fixable é direto de Outdated Packages
    if granularity == "aggregate_fixable" and vuln_name == "Outdated Packages":
        return "direta"
    # Agregados não casam com nada mais
    if granularity in ("aggregate_eosl", "aggregate_fixable", "aggregate_other"):
        return None

    # Caso 3: SAST direto via critério específico
    if vuln_name == "JavaScript Attacks" and finding.tool == "Semgrep":
        if "/javascript/" in (finding.target or ""):
            return "direta"
    # Caso 4: ZAP direto via critério específico para CSP Bypass
    if vuln_name == "Content Security Policy Bypass":
        if finding.tool in ("OWASP ZAP (Baseline)", "OWASP ZAP (Active)"):
            tgt = (finding.target or "").lower()
            if "content security policy" in tgt or "csp" in tgt:
                return "direta"
    # Caso 5: Checkov direto para Exposed MySQL
    if vuln_name == "Exposed MySQL" and finding.tool == "Checkov":
        bad = ("CKV_K8S_29", "CKV_K8S_30", "CKV_K8S_31", "CKV_K8S_38",
               "CKV_GCP_21", "CKV_GCP_62")
        if (finding.identifier or "") in bad:
            return "direta"
    # Caso 6: Brute Force direto
    if vuln_name == "Brute Force" and finding.tool == "Brute Force":
        if "CWE-307" in finding.cwes:
            return "direta"
    if vuln_name == "Default Credentials" and finding.tool == "Brute Force":
        if "CWE-798" in finding.cwes:
            return "direta"

    # Caso 7: regra geral por CWE coincidente
    if cwe_v in finding.cwes:
        if finding.layer == layer_v:
            return "direta"
        else:
            return "indireta"

    return None


def finding_class_overall(finding: Finding) -> str:
    """'direta' se f é direto de pelo menos uma vuln no escopo;
    'indireta' se é apenas indireto de alguma; 'n_a' se não casa."""
    has_direct = False
    has_indirect = False
    for name, spec in DVWA.items():
        cls = classify(finding, name, spec)
        if cls == "direta":
            has_direct = True
        elif cls == "indireta":
            has_indirect = True
    if has_direct:
        return "direta"
    if has_indirect:
        return "indireta"
    return "n_a"


# ---------------------------------------------------------------------
# RELATÓRIO
# ---------------------------------------------------------------------
def section(t: str):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def main():
    findings, raw_trivy = build_findings()

    section("CARACTERIZACAO INICIAL DO PIPELINE")
    print(f"Achados brutos do pipeline:")
    print(f"  Trivy Container (CVEs individuais): {len(raw_trivy)}")
    semgrep_n = sum(1 for f in findings if f.tool == "Semgrep")
    sca_n = sum(1 for f in findings if f.tool == "Trivy FS (SCA)")
    checkov_n = sum(1 for f in findings if f.tool == "Checkov")
    zb_n = sum(1 for f in findings if f.tool == "OWASP ZAP (Baseline)")
    za_n = sum(1 for f in findings if f.tool == "OWASP ZAP (Active)")
    bf_n = sum(1 for f in findings if f.tool == "Brute Force")
    print(f"  Semgrep:                            {semgrep_n}")
    print(f"  Trivy FS (SCA):                     {sca_n}")
    print(f"  Checkov:                            {checkov_n}")
    print(f"  OWASP ZAP Baseline:                 {zb_n}")
    print(f"  OWASP ZAP Active (tipos):           {za_n}")
    print(f"  Brute Force:                        {bf_n}")
    bruto_total = len(raw_trivy) + semgrep_n + sca_n + checkov_n + zb_n + za_n + bf_n
    print(f"  TOTAL BRUTO:                        {bruto_total}")

    section("VOLUME APOS GRANULARIDADE MISTA")
    print(f"  Semgrep:                            {semgrep_n}")
    print(f"  Trivy FS (SCA):                     {sca_n}")
    print(f"  Checkov:                            {checkov_n}")
    print(f"  OWASP ZAP Baseline:                 {zb_n}")
    print(f"  OWASP ZAP Active:                   {za_n}")
    print(f"  Brute Force:                        {bf_n}")
    n_indiv = sum(1 for f in findings if f.extra.get("granularity") == "individual_app_match")
    print(f"  Trivy Container individual (APP CWE match): {n_indiv}")
    print(f"  Trivy Container agregado EOSL:      1")
    print(f"  Trivy Container agregado fixable:   1")
    print(f"  Trivy Container agregado outras CVEs: 1")
    print(f"  TOTAL p/ SIMULACAO:                 {len(findings)}")

    section("DISTRIBUICAO CVSS - TRIVY CONTAINER (TODAS AS CVES BRUTAS)")
    bands = [
        ("9.0-10.0 Critical", 9.0, 10.01),
        ("7.0-8.9 High",       7.0, 9.0),
        ("4.0-6.9 Medium",     4.0, 7.0),
        ("0.1-3.9 Low",        0.1, 4.0),
    ]
    for label, lo, hi in bands:
        n = sum(1 for c in raw_trivy if c["cvss"] is not None and lo <= c["cvss"] < hi)
        pct = 100.0 * n / len(raw_trivy)
        print(f"  {label:<18s} n={n:>5d}  ({pct:5.1f}%)")
    n_no = sum(1 for c in raw_trivy if c["cvss"] is None)
    print(f"  {'Sem CVSS':<18s} n={n_no:>5d}  ({100*n_no/len(raw_trivy):5.1f}%)")
    vals = [c["cvss"] for c in raw_trivy if c["cvss"] is not None]
    print(f"  Media CVSS: {sum(vals)/len(vals):.2f}")

    section("TOP CWEs - TRIVY CONTAINER")
    cwe_ct = Counter()
    for c in raw_trivy:
        for w in c["cwes"]:
            cwe_ct[w] += 1
    for w, n in cwe_ct.most_common(10):
        marker = " *" if w in APP_CWES else ""
        print(f"  {w:<10s} {n:>5d}{marker}")
    print("  (* = CWE coincide com vuln APP da matriz DVWA)")

    section("COBERTURA DVWA")
    print(f"{'Vulnerabilidade':<34s} {'CWE':<10s} {'cam':<5s} "
          f"{'#dir':>5s} {'#ind':>5s} {'status'}")
    print("-" * 88)
    cov_rows = []
    for name, spec in DVWA.items():
        if spec.get("out_of_scope"):
            continue
        n_d = sum(1 for f in findings if classify(f, name, spec) == "direta")
        n_i = sum(1 for f in findings if classify(f, name, spec) == "indireta")
        if n_d > 0:
            status = "direta"
        elif n_i > 0:
            status = "apenas indireta"
        else:
            status = "NAO detectada"
        cov_rows.append({
            "name": name, "cwe": spec["cwe"], "layer": spec["layer"],
            "n_direta": n_d, "n_indireta": n_i, "status": status,
        })
        print(f"{name:<34s} {spec['cwe']:<10s} {spec['layer']:<5s} "
              f"{n_d:>5d} {n_i:>5d} {status}")
    n_dir = sum(1 for r in cov_rows if r["status"] == "direta")
    n_ind = sum(1 for r in cov_rows if r["status"] == "apenas indireta")
    n_nao = sum(1 for r in cov_rows if r["status"] == "NAO detectada")
    print(f"\n  Total no escopo: {len(cov_rows)}")
    print(f"  Detectadas (direta):           {n_dir}")
    print(f"  Detectadas (apenas indireta):  {n_ind}")
    print(f"  Nao detectadas:                {n_nao}")

    section("VOLUME DE FINDINGS POR CLASSE (granularidade mista)")
    cls_count = Counter(finding_class_overall(f) for f in findings)
    total = len(findings)
    for k in ("direta", "indireta", "n_a"):
        n = cls_count[k]
        print(f"  {k:<10s} {n:>5d}  ({100*n/total:5.1f}%)")
    print(f"  TOTAL      {total:>5d}")

    section("SIMULACAO DE POLITICAS")

    def apply_policy(p: str, f: Finding) -> bool:
        cvss = f.cvss if f.cvss is not None else 0.0
        cls = finding_class_overall(f)
        if p == "P1":
            return cvss >= 9.0
        if p == "P2":
            return cvss >= 7.0
        if p == "P3":
            if cls == "indireta":
                return False
            return cvss >= 7.0
        raise ValueError(p)

    print(f"\n{'Pol':<5s} {'Total':>7s} {'Bloq':>6s} {'%':>6s} "
          f"{'B-dir':>7s} {'B-ind':>7s} {'B-n/a':>7s}")
    print("-" * 55)
    pol_results = {}
    for p in ("P1", "P2", "P3"):
        blocks = [f for f in findings if apply_policy(p, f)]
        nd = sum(1 for f in blocks if finding_class_overall(f) == "direta")
        ni = sum(1 for f in blocks if finding_class_overall(f) == "indireta")
        nn = sum(1 for f in blocks if finding_class_overall(f) == "n_a")
        pol_results[p] = {"total": total, "blocks": len(blocks),
                          "dir": nd, "ind": ni, "na": nn}
        print(f"{p:<5s} {total:>7d} {len(blocks):>6d} "
              f"{100*len(blocks)/total:>5.1f}% {nd:>7d} {ni:>7d} {nn:>7d}")

    print("\n--- Bloqueios por estagio ---")
    print(f"{'Pol':<5s} {'Commit':>8s} {'Build':>8s} {'Deploy':>8s}")
    pol_stages = {}
    for p in ("P1", "P2", "P3"):
        c = Counter()
        for f in findings:
            if apply_policy(p, f):
                c[f.stage_hint] += 1
        pol_stages[p] = {"commit": c["commit"], "build": c["build"], "deploy": c["deploy"]}
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

    # Salva JSON com tudo
    out_data = {
        "bruto": {
            "trivy_container_individual": len(raw_trivy),
            "semgrep": semgrep_n, "trivy_sca": sca_n,
            "checkov": checkov_n, "zap_baseline": zb_n,
            "zap_active": za_n, "brute_force": bf_n,
            "total_bruto": bruto_total,
        },
        "simulacao": {
            "trivy_container_individual_app_match": n_indiv,
            "trivy_container_agregados": 3,
            "total_p_simulacao": len(findings),
        },
        "trivy_cvss": {
            "media": sum(vals)/len(vals),
            "bandas": {label: sum(1 for c in raw_trivy if c["cvss"] is not None and lo <= c["cvss"] < hi)
                       for label, lo, hi in bands},
            "sem_score": n_no,
        },
        "trivy_top_cwes": cwe_ct.most_common(10),
        "cobertura": {"rows": cov_rows,
                      "dir": n_dir, "ind": n_ind, "nao": n_nao},
        "volume_classe": dict(cls_count),
        "politicas": pol_results,
        "politicas_por_estagio": pol_stages,
        "cobertura_bloqueante": cob_bloq,
    }
    with open(OUT / "numeros_secao6.json", "w", encoding="utf-8") as fh:
        json.dump(out_data, fh, indent=2, ensure_ascii=False, default=str)
    print(f"\nDados salvos em {OUT / 'numeros_secao6.json'}")


if __name__ == "__main__":
    main()
