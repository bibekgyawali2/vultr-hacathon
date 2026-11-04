"""Turn a stream of observed events into a defensible verdict.

Deterministic, evidence-first scoring: every point added to the risk score
traces to a concrete event, and every reason names what was seen. The agent
layer (agent.py) writes the prose headline on top of this; this module is the
ground truth the headline must not contradict.
"""
from __future__ import annotations

from .models import Event, IOC, Kind, Label, Verdict


def score(events: list[Event]) -> Verdict:
    v = Verdict()
    pts = 0
    seen_iocs: set[tuple[str, str]] = set()

    def add_ioc(t: str, value: str, note: str = ""):
        key = (t, value)
        if key not in seen_iocs and value and value != "?":
            seen_iocs.add(key)
            v.iocs.append(IOC(type=t, value=value, note=note))

    canary_hits = 0
    egress_blocked = 0
    egress_ok = 0
    sensitive_reads = 0
    cred_forms = 0
    cross_post = False
    static_hits = 0
    static_patterns: set[str] = set()

    for e in events:
        det = e.detail or {}
        if det.get("static_risk"):
            static_hits += 1
            for p in det.get("patterns", []):
                static_patterns.add(p)
            continue
        if e.kind == Kind.FILE and det.get("canary"):
            canary_hits += 1
            add_ioc("credential", e.target, "canary credential accessed")
        elif e.kind == Kind.FILE and e.op == "note" and "credential form" in e.target:
            cred_forms += 1
            if det.get("cross_origin"):
                cross_post = True
                add_ioc("url", det.get("posts_to", ""), "credential form posts cross-origin")
        elif e.kind == Kind.FILE and e.severity >= 1:
            sensitive_reads += 1
            add_ioc("path", e.target, "sensitive path touched")
        elif e.kind == Kind.BLOCKED and e.op == "connect":
            egress_blocked += 1
            host = e.target.rsplit(":", 1)[0]
            add_ioc("ip", host, "blocked outbound connection")
        elif e.kind == Kind.NETWORK and e.op in ("connect", "fetch"):
            egress_ok += 1
            host = e.target.rsplit(":", 1)[0]
            if det.get("redirected_to"):
                add_ioc("url", det["redirected_to"], "redirect target")
            elif det.get("external_script"):
                add_ioc("domain", host, "external script host")

    # Weighted, explainable scoring.
    if canary_hits:
        pts += 55
        v.reasons.append(
            f"Read {canary_hits} planted canary credential"
            f"{'s' if canary_hits > 1 else ''} — benign installers never do this.")
    if egress_blocked:
        pts += 30
        v.reasons.append(
            f"Attempted {egress_blocked} outbound connection"
            f"{'s' if egress_blocked > 1 else ''} that the sandbox blocked "
            f"(contained; nothing left the machine).")
    if cross_post:
        pts += 60
        v.reasons.append("Credential form posts to a different origin than the page is served from — the canonical phishing pattern.")
    elif cred_forms:
        pts += 15
        v.reasons.append(f"Page contains {cred_forms} password form"
                         f"{'s' if cred_forms > 1 else ''}.")
    if sensitive_reads:
        pts += min(15, 3 * sensitive_reads)
        v.reasons.append(f"Touched {sensitive_reads} sensitive path(s) outside the work directory.")
    if egress_ok and not cross_post:
        pts += min(10, 2 * egress_ok)
        v.reasons.append(f"Made {egress_ok} outbound request(s) during analysis.")
    if static_patterns:
        pts += min(15, 5 * len(static_patterns))
        pats = ", ".join(sorted(static_patterns)[:5])
        v.reasons.append(f"Agent found high-risk code pattern(s) in the source ({pats}).")

    v.score = max(0, min(100, pts))
    if v.score >= 60:
        v.label = Label.MALICIOUS
    elif v.score >= 20:
        v.label = Label.SUSPICIOUS
    else:
        v.label = Label.BENIGN

    if not v.reasons:
        v.reasons.append("No sensitive access, no egress attempts, no credential forms observed.")
    v.headline = {
        Label.MALICIOUS: "Malicious behaviour observed and contained.",
        Label.SUSPICIOUS: "Suspicious behaviour — review the evidence below.",
        Label.BENIGN: "No malicious behaviour observed in the sandbox.",
    }[v.label]
    return v
