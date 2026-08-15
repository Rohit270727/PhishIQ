"""
detectors/email_auth.py
SPF / DMARC validation (DNS-only, no API keys required).
DKIM here is a presence heuristic only — full signature verification
requires the raw .eml (headers + body) via dkimpy, not just message text.
"""
import re
import dns.resolver

_COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim"]
_MAX_SPF_REDIRECT_DEPTH = 4


def _resolve_spf_txt(domain: str, timeout: int) -> str | None:
    """Return the raw v=spf1 TXT record for a domain, or None."""
    answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def check_spf(domain: str, timeout: int = 3, _depth: int = 0, _chain: list | None = None) -> dict:
    chain = _chain if _chain is not None else []
    result = {"checked": True, "found": False, "record": None,
              "all_qualifier": None, "redirect_chain": chain, "risk_notes": []}

    if _depth > _MAX_SPF_REDIRECT_DEPTH:
        result["risk_notes"].append("SPF redirect chain too deep — treating as unresolved")
        return result

    try:
        txt = _resolve_spf_txt(domain, timeout)
        if txt is None:
            result["risk_notes"].append("No SPF record found — domain has no sender authorization policy")
            return result

        result["found"] = True
        result["record"] = txt
        chain.append(domain)

        m = re.search(r'([-~?+])all\b', txt)
        if m:
            result["all_qualifier"] = m.group(1) + "all"
            if m.group(1) == "+":
                result["risk_notes"].append(f"SPF (on {domain}) uses +all — allows any sender, high spoofing risk")
            elif m.group(1) == "?":
                result["risk_notes"].append(f"SPF (on {domain}) uses ?all (neutral) — provides no real protection")
            return result

        # No 'all' mechanism directly — check for a redirect modifier before
        # concluding the policy is incomplete.
        redirect_match = re.search(r'redirect=([^\s]+)', txt)
        if redirect_match:
            redirected_domain = redirect_match.group(1)
            sub_result = check_spf(redirected_domain, timeout, _depth + 1, chain)
            # Adopt the redirected policy's findings as the effective policy
            sub_result["record"] = txt  # keep the original domain's record visible too
            sub_result["risk_notes"] = [
                f"SPF policy delegated via redirect to {redirected_domain}"
            ] + sub_result["risk_notes"]
            sub_result["redirect_chain"] = chain
            return sub_result

        result["risk_notes"].append(f"SPF (on {domain}) has no 'all' mechanism and no redirect — incomplete policy")
        return result

    except dns.resolver.NXDOMAIN:
        result["risk_notes"].append(f"Domain {domain} does not exist (NXDOMAIN)")
        return result
    except dns.resolver.NoAnswer:
        result["risk_notes"].append("No SPF record found — domain has no sender authorization policy")
        return result
    except Exception as e:
        result["checked"] = False
        result["risk_notes"].append(f"SPF lookup failed: {e}")
        return result


def check_dmarc(domain: str, timeout: int = 3) -> dict:
    result = {"checked": True, "found": False, "record": None,
              "policy": None, "pct": 100, "risk_notes": []}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt.lower().startswith("v=dmarc1"):
                result["found"] = True
                result["record"] = txt
                p = re.search(r'p=(\w+)', txt)
                if p:
                    result["policy"] = p.group(1)
                    if result["policy"] == "none":
                        result["risk_notes"].append("DMARC policy is 'none' — monitoring only, no enforcement")
                pct = re.search(r'pct=(\d+)', txt)
                if pct:
                    result["pct"] = int(pct.group(1))
                    if result["pct"] < 100:
                        result["risk_notes"].append(f"DMARC enforced on only {result['pct']}% of mail")
                break
        if not result["found"]:
            result["risk_notes"].append("No DMARC record found — domain does not enforce sender authentication")
    except dns.resolver.NXDOMAIN:
        result["risk_notes"].append("No DMARC record found (NXDOMAIN on _dmarc subdomain)")
    except dns.resolver.NoAnswer:
        result["risk_notes"].append("No DMARC record found — domain does not enforce sender authentication")
    except Exception as e:
        result["checked"] = False
        result["risk_notes"].append(f"DMARC lookup failed: {e}")
    return result


def check_dkim_presence(domain: str, timeout: int = 3) -> dict:
    """Heuristic only: checks common selectors for a DKIM public-key record.
    A miss here is NOT proof DKIM is absent (selector could be nonstandard).
    A hit is NOT proof a given message was actually signed correctly."""
    result = {"checked": True, "found_selectors": [], "risk_notes": []}
    for sel in _COMMON_DKIM_SELECTORS:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=timeout)
            result["found_selectors"].append(sel)
        except Exception:
            continue
    if not result["found_selectors"]:
        result["risk_notes"].append(
            "No DKIM record found under common selectors (heuristic — not conclusive)"
        )
    return result


def check_email_auth(domain: str) -> dict:
    """Combined SPF+DMARC+DKIM-heuristic check with a rough risk contribution."""
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim_presence(domain)

    risk_score = 0
    if not spf["found"]:
        risk_score += 15
    elif spf.get("all_qualifier") == "+all":
        risk_score += 20
    elif spf.get("all_qualifier") is None:
        risk_score += 10  # genuinely incomplete (no all, no redirect resolved)
    if not dmarc["found"]:
        risk_score += 15
    elif dmarc.get("policy") == "none":
        risk_score += 8
    if not dkim["found_selectors"]:
        risk_score += 5  # low weight — heuristic only

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "email_auth_risk_score": min(risk_score, 40),
        "all_notes": spf["risk_notes"] + dmarc["risk_notes"] + dkim["risk_notes"],
    }
