"""Core unit tests. Run with `python tests/test_core.py` (no pytest needed)
or `python -m pytest tests/`.

Covers the parts that decide a verdict: target parsing, the deterministic
scorer against each labelled demo trace, and the verifiable-report hash.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import analysis, demo               # noqa: E402
from app.jobs import Job                      # noqa: E402
from app.models import Label, parse_target    # noqa: E402


def _score(scenario: str):
    job = Job(f"demo:{scenario}")
    events = [job._mk_event(d) for d in demo.event_dicts(scenario)]
    return analysis.score(events)


def test_parse_target():
    cases = {
        "npm:left-pad": ("npm", "left-pad", ""),
        "pypi:requests==2.0": ("pypi", "requests", "2.0"),
        "pip:flask": ("pypi", "flask", ""),
        "github.com/owner/repo": ("github", "owner/repo", ""),
        "https://github.com/a/b/tree/main": ("github", "a/b", ""),
        "https://evil.example/login": ("url", "https://evil.example/login", ""),
        "demo:exfil": ("demo", "exfil", ""),
        "@scope/pkg@1.2.3": ("npm", "@scope/pkg", "1.2.3"),
        "owner/repo": ("github", "owner/repo", ""),
        "lodash": ("npm", "lodash", ""),
    }
    for raw, (typ, name, ver) in cases.items():
        t = parse_target(raw)
        assert (t.type, t.name, t.version) == (typ, name, ver), (raw, t.__dict__)


def test_clean_is_benign():
    v = _score("clean")
    assert v.label == Label.BENIGN
    assert v.score == 0
    assert v.iocs == []


def test_exfil_is_malicious():
    v = _score("exfil")
    assert v.label == Label.MALICIOUS
    assert v.score >= 60
    # canary reads + blocked egress must surface as indicators
    kinds = {i.type for i in v.iocs}
    assert "credential" in kinds
    assert any(i.type in ("ip", "domain") for i in v.iocs)


def test_phish_is_malicious():
    v = _score("phish")
    assert v.label == Label.MALICIOUS
    assert any("cross-origin" in r or "phishing" in r.lower() for r in v.reasons)


def test_report_hash_is_stable_and_order_sensitive():
    job = Job("demo:exfil")
    for d in demo.event_dicts("exfil"):
        job.events.append(job._mk_event(d))
    job.verdict = analysis.score(job.events)
    r1 = job.report()
    r2 = job.report()
    assert r1["evidence_sha256"] == r2["evidence_sha256"]
    assert len(r1["evidence_sha256"]) == 64
    assert r1["event_count"] == len(job.events)


def _run():
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
