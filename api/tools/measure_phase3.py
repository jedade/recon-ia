# tools/measure_phase3.py
"""
Mesure avant/après de la phase 3 (fiabilité de l'analyse), HORS LIGNE.

Rejoue un jeu FIXE de résultats bruts de référence (tests/fixtures/phase3/
scan_*.json) et de sorties LLM brutes reconstituées (llm_*.json, défauts
réellement constatés : constat positif en CRITICAL, HSTS halluciné, CVE
inventée…) dans deux pipelines de post-traitement :

  avant : chaîne d'avant la phase 3 — nettoyage de format seul, sévérité du
          modèle conservée, RAG en une requête globale (6 extraits, sans
          filtre de collection), pas de B6 ni de KEV ;
  après : routes/analyze.py::_prepare_phase3 + _postprocess_report, tels
          qu'exécutés en production (sanitizer + B6, règles de sévérité,
          RAG par constat filtré par collection, références par finding).

Aucun appel réseau : le catalogue KEV vient de kev_catalog.json, le RAG
d'un mini-corpus (rag_corpus.json) interrogé par recouvrement lexical — les
chiffres RAG mesurent donc la MÉCANIQUE (requêtes, filtrage, rattachement),
pas la qualité des embeddings réels.

Usage (conteneur de test, réseau coupé) :
  MSYS_NO_PATHCONV=1 docker run --rm --network none -v "$PWD/api:/app" -w /app \
      recon-ia-api-test python tools/measure_phase3.py [--json]
"""
import copy
import json
import os
import re
import sys

# Environnement minimal (aucune base, aucun service) avant tout import applicatif.
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ADMIN_EMAIL", "measure")
os.environ.setdefault("ADMIN_PASSWORD", "measure")
os.environ.setdefault("KEV_ENABLED", "false")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "phase3")
CASES = [("example.com", "scan_example_com.json", "llm_example_com.json"),
         ("vuln-target.test", "scan_vuln_target.json", "llm_vuln_target.json")]


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def _tokens(text):
    return set(re.findall(r"[a-z0-9]{3,}", str(text).lower()))


class LexicalCorpus:
    """Recherche simulée : score = mots communs ; même interface que rag_retrieval._search."""

    def __init__(self, docs):
        self.docs = docs

    def embed(self, query):
        return sorted(_tokens(query))

    def search(self, vec, collections, k):
        q = set(vec)
        scored = []
        for i, d in enumerate(self.docs):
            if collections and d["collection"] not in collections:
                continue
            s = len(q & _tokens(d["content"] + " " + d["source"]))
            if s:
                scored.append((-s, i, d))
        scored.sort()
        return [{"source": d["source"], "content": d["content"], "collection": d["collection"]}
                for _, _, d in scored[:max(1, k)]]


def _kev_override():
    from utils.kev import _parse_catalog
    return _parse_catalog(_load("kev_catalog.json"))


def _summary(report):
    g = report.get("grounding_check") or {}
    c = report.get("coverage_check") or {}
    sev = report.get("findings_summary") or {}
    return {
        "findings":                 len(report.get("findings") or []),
        "critical_high":            sev.get("critical", 0) + sev.get("high", 0),
        "security_score":           report.get("security_score"),
        "risk_score":               report.get("risk_score"),
        "grounding_verified_pct":   g.get("verified_pct"),
        "coverage_pct":             c.get("coverage_pct"),
        "rag_snippets_used":        c.get("rag_snippets_used"),
        "rag_snippets_available":   c.get("rag_snippets_available"),
        "rag_queries":              c.get("rag_queries", 1 if c.get("rag_snippets_available") else 0),
        "findings_with_rag_refs":   c.get("findings_with_rag_references", 0),
        "unverified_cves_left":     _unverified_cves(report),
    }


def _unverified_cves(report):
    """CVE citées dans les findings mais absentes du scan (B6 : doit être 0 après)."""
    cves = set()
    for f in report.get("findings") or []:
        cves |= {c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", json.dumps(f), re.I)}
    return sorted(cves - report.get("_observed_cves", set()))


def run_before(scan, llm, corpus):
    """Chaîne d'avant la phase 3 (voir docstring du module)."""
    import routes.analyze as an
    from routes.recon import TOOLS_REGISTRY
    from utils.analysis_merger import compute_security_score
    from utils.coverage_check import compute_coverage_check
    from utils.finding_sanitizer import sanitize_findings
    from utils.grounding_check import compute_grounding_check
    from utils.severity_rules import observed_cves

    signals = an._extract_signals(scan)
    spf = ((signals.get("email") or {}).get("config") or {}).get("spf") or ""
    query = f"Sécurité web pour {signals.get('domain')} — technologies: ; TLS: ; SPF: {spf}"
    signals["rag_context"] = corpus.search(corpus.embed(query), None, 6)

    report = copy.deepcopy(llm)
    report["findings"] = sanitize_findings(report.get("findings") or [], TOOLS_REGISTRY, check_cves=False)
    for f in report["findings"]:      # sévérité du modèle conservée telle quelle
        f.pop("_llm_confidence", None)
    report.update(compute_security_score(report))
    report["grounding_check"] = compute_grounding_check(report, scan)
    report["coverage_check"] = compute_coverage_check(report, scan, signals)
    report["_observed_cves"] = set(observed_cves(scan))
    return report


def run_after(scan, llm, corpus):
    import routes.analyze as an
    from utils.rag_retrieval import TopicRetriever
    from utils.severity_rules import observed_cves

    signals = an._extract_signals(scan)
    retriever = TopicRetriever(embed_fn=corpus.embed, search_fn=corpus.search, has_collections=True)
    ctx = an._prepare_phase3(scan, signals, "Sécurité web", kev_override=_kev_override(), retriever=retriever)
    report = an._postprocess_report(copy.deepcopy(llm), signals, ctx, "fixture")
    report["_observed_cves"] = set(observed_cves(scan))
    return report


def main():
    corpus = LexicalCorpus(_load("rag_corpus.json")["documents"])
    results = []
    for name, scan_file, llm_file in CASES:
        scan, llm = _load(scan_file), _load(llm_file)
        before, after = run_before(scan, llm, corpus), run_after(scan, llm, corpus)
        results.append({"case": name, "before": _summary(before), "after": _summary(after),
                        "severity_check": {k: after["severity_check"].get(k) for k in (
                            "rule_applied", "positive_capped", "llm_capped", "llm_proposed", "unverified",
                            "contradicted_dropped", "contradicted_info", "duplicates_dropped",
                            "dropped_unverified_cve", "injected", "kev_cves")}})

    if "--json" in sys.argv:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return
    keys = list(results[0]["before"].keys())
    for r in results:
        print(f"\n=== {r['case']} ===")
        print(f"{'métrique':<26}{'avant':>18}{'après':>18}")
        for k in keys:
            print(f"{k:<26}{str(r['before'][k]):>18}{str(r['after'][k]):>18}")
        print("severity_check :", json.dumps(r["severity_check"], ensure_ascii=False))


if __name__ == "__main__":
    main()
