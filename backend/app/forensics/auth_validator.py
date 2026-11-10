"""Protocol Authentication Validator (SPF, DKIM, DMARC RFC 7489 Alignment, and ARC).

Validates:
1. Real DKIM (DomainKeys Identified Mail) cryptographic signature verification using dkimpy
   against raw message bytes, canonicalization policies, body hash (bh=), RSA/Ed25519 signature (b=),
   handling multiple signatures, l= tag body length abuse, expired signatures (x=),
   revoked keys (empty p=), and historical unresolvable keys (KEY_UNAVAILABLE).
2. Real SPF (Sender Policy Framework) evaluation via pyspf (RFC 7208) using the true connecting IP
   from the first trusted hop, HELO identity, and MAIL FROM envelope sender, enforcing the
   10-lookup DNS mechanism limit, PermError, and TempError states.
3. Real DMARC (RFC 7489) evaluation querying _dmarc.<domain> and organizational domains via the
   Public Suffix List, computing strict and relaxed alignment only from cryptographically verified results.
4. Real ARC (Authenticated Received Chain - RFC 8617) verification and chain integrity parsing.
5. Upstream Discrepancy Detection: Decouples upstream MTA claims (Authentication-Results) from our
   own independently recomputed verdicts and flags discrepancies indicating header injection or MTA spoofing.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import dkim
import publicsuffix2
import spf
from pydantic import BaseModel, Field

logger = logging.getLogger("auth_validator")

# DNS timeout constant for hackathon air-gapped / offline resilience (1.5 seconds)
DNS_QUERY_TIMEOUT_SECONDS = 1.5


class DkimSignatureResult(BaseModel):
    """Detailed evaluation of an individual DKIM-Signature header."""
    domain: str = ""
    selector: str = ""
    algorithm: str = ""
    canonicalization: str = ""
    signed_headers: List[str] = Field(default_factory=list)
    body_hash_status: str = "NONE"      # MATCH, MISMATCH, NONE
    signature_status: str = "NONE"      # PASS, FAIL, INVALID, EXPIRED, KEY_REVOKED, KEY_UNAVAILABLE, NONE
    body_length: Optional[int] = None
    l_tag_abuse_detected: bool = False
    l_tag_explanation: Optional[str] = None
    expiration_timestamp: Optional[int] = None
    is_expired: bool = False
    dns_key_snapshot: Optional[str] = None
    details: str = ""


class ArcChainResult(BaseModel):
    """Evaluation of Authenticated Received Chain (RFC 8617)."""
    status: str = "NONE"                # PASS, FAIL, NONE
    chain_validation: Optional[str] = None  # pass, fail, none
    instances_count: int = 0
    details: List[Dict[str, Any]] = Field(default_factory=list)
    reason: Optional[str] = None


class AuthValidationResult(BaseModel):
    """Forensic evaluation of SPF, DKIM, DMARC, and ARC authentication."""
    # SPF Recomputed Verdict
    spf_status: str = "NONE"       # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, PERMERROR, TEMPERROR, UNVERIFIABLE
    spf_domain: Optional[str] = None
    spf_client_ip: Optional[str] = None
    spf_helo: Optional[str] = None
    spf_lookups_count: int = 0
    spf_explanation: Optional[str] = None

    # DKIM Recomputed Verdict
    dkim_status: str = "NONE"      # PASS, FAIL, NONE, INVALID, EXPIRED, KEY_REVOKED, KEY_UNAVAILABLE, BODY_HASH_MISMATCH
    dkim_selector: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_signatures: List[DkimSignatureResult] = Field(default_factory=list)

    # DMARC Recomputed Verdict (RFC 7489)
    dmarc_status: str = "NONE"     # PASS, FAIL, NONE, UNVERIFIABLE
    dmarc_policy: str = "none"     # reject, quarantine, none
    dmarc_alignment_spf: bool = False
    dmarc_alignment_dkim: bool = False
    dmarc_org_domain: Optional[str] = None

    # ARC Chain
    arc: ArcChainResult = Field(default_factory=ArcChainResult)

    # Claimed by Receiving MTA vs Recomputed
    claimed_by_mta: Dict[str, Any] = Field(default_factory=dict)
    recomputed_verdict: Dict[str, Any] = Field(default_factory=dict)
    has_discrepancy: bool = False
    discrepancies: List[str] = Field(default_factory=list)

    # Threat Scoring & Audit Trail
    auth_score: float = 0.0        # 0.0 (safe) to 100.0 (complete failure/impersonation)
    dns_resolved_live: bool = False
    dns_key_snapshots: List[Dict[str, Any]] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


def extract_organizational_domain(domain: str) -> str:
    """Extract base organizational domain using the Public Suffix List (e.g. sub.example.co.in -> example.co.in)."""
    if not domain:
        return ""
    clean = domain.lower().strip().rstrip(".")
    sld = publicsuffix2.get_sld(clean)
    if sld:
        return sld
    # Domain segmentation if publicsuffix lookup returns empty
    parts = clean.split(".")
    if len(parts) <= 2:
        return clean
    two_part_tlds = {"co.in", "gov.in", "ac.in", "edu.in", "res.in", "org.in", "co.uk", "org.uk", "gov.uk"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_alignment(from_domain: str, candidate_domain: str, strict: bool = False) -> bool:
    """Check RFC 7489 domain alignment between From: domain and SPF/DKIM domains."""
    if not from_domain or not candidate_domain:
        return False
    from_clean = from_domain.lower().strip().rstrip(".")
    cand_clean = candidate_domain.lower().strip().rstrip(".")

    if strict:
        return from_clean == cand_clean

    # Relaxed alignment: compare organizational domains via Public Suffix List
    return extract_organizational_domain(from_clean) == extract_organizational_domain(cand_clean)


def query_dns_txt_with_timeout(
    domain: str,
    timeout: float = DNS_QUERY_TIMEOUT_SECONDS,
    custom_records: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """Perform aggressive-timeout DNS TXT record lookup with zero-crash offline resilience.

    Supports custom local record fixtures for deterministic testing / air-gapped operation.
    """
    if not domain:
        return []

    clean_domain = domain.strip().rstrip(".").lower()

    # Check local test/fixture dictionary if provided
    if custom_records:
        for k, recs in custom_records.items():
            if k.strip().rstrip(".").lower() == clean_domain:
                return recs

    if "." not in clean_domain:
        return []

    try:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            txt_parts = [
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            ]
            records.append("".join(txt_parts))
        return records
    except Exception as exc:
        logger.debug("DNS TXT query for %s failed/timed out: %s", domain, exc)
        return []


def parse_received_spf_header(received_spf_str: str) -> Dict[str, str]:
    """Parse key authentication tokens from a Received-SPF header."""
    results: Dict[str, str] = {}
    if not received_spf_str:
        return results

    cleaned = received_spf_str.strip()
    match_status = re.match(r"^([a-zA-Z]+)", cleaned)
    if match_status:
        results["spf"] = match_status.group(1).upper()

    domain_match = re.search(r"envelope-from=([^\s;]+)", cleaned, re.IGNORECASE) or re.search(
        r"identity=([^\s;]+)", cleaned, re.IGNORECASE
    )
    if domain_match:
        val = domain_match.group(1).split("@")[-1].strip("<>;\"'")
        results["spf_domain"] = val

    client_ip_match = re.search(r"client-ip=([0-9a-fA-F.:]+)", cleaned, re.IGNORECASE)
    if client_ip_match:
        results["client_ip"] = client_ip_match.group(1)

    helo_match = re.search(r"helo=([^\s;]+)", cleaned, re.IGNORECASE)
    if helo_match:
        results["helo"] = helo_match.group(1).strip()

    return results


def parse_authentication_results(auth_results_str: str) -> Dict[str, str]:
    """Parse claimed authentication tokens from an upstream Authentication-Results header."""
    results: Dict[str, str] = {}
    if not auth_results_str:
        return results

    # Authentication Service Identifier
    serv_match = re.match(r"^([^\s;]+)", auth_results_str.strip())
    if serv_match:
        results["auth_serv_id"] = serv_match.group(1)

    # SPF match
    spf_match = re.search(r"\bspf=([a-zA-Z]+)", auth_results_str, re.IGNORECASE)
    if spf_match:
        results["spf"] = spf_match.group(1).upper()

    spf_domain_match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth_results_str, re.IGNORECASE)
    if spf_domain_match:
        results["spf_domain"] = spf_domain_match.group(1).split("@")[-1].strip("<>")

    # DKIM match
    dkim_match = re.search(r"\bdkim=([a-zA-Z]+)", auth_results_str, re.IGNORECASE)
    if dkim_match:
        results["dkim"] = dkim_match.group(1).upper()

    dkim_d_match = re.search(r"header\.d=([^\s;]+)", auth_results_str, re.IGNORECASE)
    if dkim_d_match:
        results["dkim_domain"] = dkim_d_match.group(1).strip()

    dkim_s_match = re.search(r"header\.s=([^\s;]+)", auth_results_str, re.IGNORECASE)
    if dkim_s_match:
        results["dkim_selector"] = dkim_s_match.group(1).strip()

    # DMARC match
    dmarc_match = re.search(r"\bdmarc=([a-zA-Z]+)", auth_results_str, re.IGNORECASE)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).upper()

    dmarc_p_match = re.search(r"\bp=([a-zA-Z]+)", auth_results_str, re.IGNORECASE)
    if dmarc_p_match:
        results["dmarc_policy"] = dmarc_p_match.group(1).lower()

    # ARC match
    arc_match = re.search(r"\barc=([a-zA-Z]+)", auth_results_str, re.IGNORECASE)
    if arc_match:
        results["arc"] = arc_match.group(1).upper()

    return results


def verify_dkim_signatures(
    raw_bytes: bytes,
    dnsfunc: Optional[Callable[..., Optional[bytes]]] = None,
    custom_records: Optional[Dict[str, List[str]]] = None,
    timeout: float = DNS_QUERY_TIMEOUT_SECONDS,
) -> tuple[str, Optional[str], Optional[str], List[DkimSignatureResult], List[Dict[str, Any]], bool]:
    """Cryptographically verify all DKIM signatures in raw email bytes using dkimpy.

    Returns:
        (consolidated_dkim_status, primary_selector, primary_domain, signature_results, dns_snapshots, dns_live)
    """
    signature_results: List[DkimSignatureResult] = []
    dns_snapshots: List[Dict[str, Any]] = []
    dns_live_flag = False

    if not raw_bytes:
        return "NONE", None, None, [], [], False

    # Check for DKIM-Signature header existence
    try:
        d = dkim.DKIM(raw_bytes, timeout=timeout)
    except Exception as exc:
        logger.debug("dkim.DKIM parse error: %s", exc)
        return "INVALID", None, None, [], [], False

    sig_headers = [h for h in d.headers if h[0].lower() == b"dkim-signature"]
    if not sig_headers:
        return "NONE", None, None, [], [], False

    def default_dnsfunc(name: bytes, timeout: float = timeout) -> Optional[bytes]:
        nonlocal dns_live_flag
        name_str = name.decode("utf-8", errors="replace").rstrip(".")

        # Custom local test records
        if custom_records:
            for k, recs in custom_records.items():
                if k.strip().rstrip(".").lower() == name_str.lower():
                    if recs:
                        return recs[0].encode("utf-8")
                    return None

        # Live DNS query
        recs = query_dns_txt_with_timeout(name_str, timeout=timeout)
        if recs:
            dns_live_flag = True
            return recs[0].encode("utf-8")
        return None

    active_dnsfunc = dnsfunc or default_dnsfunc

    current_unix_time = int(time.time())

    for idx, (hdr_name, hdr_val) in enumerate(sig_headers):
        sig_parsed = dkim.parse_tag_value(hdr_val)
        d_val = sig_parsed.get(b"d", b"").decode("utf-8", errors="replace").strip()
        s_val = sig_parsed.get(b"s", b"").decode("utf-8", errors="replace").strip()
        a_val = sig_parsed.get(b"a", b"").decode("utf-8", errors="replace").strip()
        c_val = sig_parsed.get(b"c", b"simple/simple").decode("utf-8", errors="replace").strip()
        h_val = sig_parsed.get(b"h", b"").decode("utf-8", errors="replace").split(":")
        signed_hdrs = [h.strip() for h in h_val if h.strip()]

        res_item = DkimSignatureResult(
            domain=d_val,
            selector=s_val,
            algorithm=a_val,
            canonicalization=c_val,
            signed_headers=signed_hdrs,
        )

        # 1. Check expiration tag x=
        if b"x" in sig_parsed:
            try:
                x_val = int(sig_parsed[b"x"])
                res_item.expiration_timestamp = x_val
                if current_unix_time > x_val:
                    res_item.is_expired = True
                    res_item.signature_status = "EXPIRED"
                    res_item.details = f"DKIM Signature expired at Unix timestamp {x_val} (current {current_unix_time})."
            except (ValueError, TypeError):
                pass

        # 2. Check l= tag abuse (RFC 6376 Section 8.2)
        if b"l" in sig_parsed:
            try:
                l_val = int(sig_parsed[b"l"])
                res_item.body_length = l_val
                try:
                    canon_policy = dkim.CanonicalizationPolicy.from_c_value(sig_parsed.get(b"c", b"simple/simple"))
                    canon_body = canon_policy.canonicalize_body(d.body)
                    actual_body_len = len(canon_body)
                    if actual_body_len > l_val:
                        res_item.l_tag_abuse_detected = True
                        res_item.l_tag_explanation = (
                            f"Length tag l={l_val} limits signed content; actual canonicalized body length is "
                            f"{actual_body_len} bytes. Malicious content may have been appended post-signature."
                        )
                except Exception as exc:
                    logger.debug("DKIM l= canonicalization check error: %s", exc)
            except (ValueError, TypeError):
                pass

        # 3. DNS Public Key Resolution
        fqdn_bytes = f"{s_val}._domainkey.{d_val}.".encode("utf-8")
        txt_res: Optional[bytes] = None
        try:
            txt_res = active_dnsfunc(fqdn_bytes)
        except Exception as exc:
            logger.debug("DNS lookup for DKIM key %s failed: %s", fqdn_bytes, exc)

        if not txt_res:
            if not res_item.signature_status or res_item.signature_status == "NONE":
                res_item.signature_status = "KEY_UNAVAILABLE"
                res_item.details = (
                    f"Public key record at {s_val}._domainkey.{d_val} could not be resolved in DNS. "
                    "For historical or air-gapped emails, status is KEY_UNAVAILABLE."
                )
            signature_results.append(res_item)
            continue

        raw_txt_str = txt_res.decode("utf-8", errors="replace")
        res_item.dns_key_snapshot = raw_txt_str
        dns_snapshots.append({
            "domain": d_val,
            "selector": s_val,
            "fqdn": f"{s_val}._domainkey.{d_val}",
            "txt_record": raw_txt_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # 4. Check Key Revocation (empty p= tag per RFC 6376 Section 6.1.2)
        p_match = re.search(r"\bp=([^;\s]*)", raw_txt_str, re.IGNORECASE)
        if p_match:
            p_val = p_match.group(1).strip()
            if not p_val:
                res_item.signature_status = "KEY_REVOKED"
                res_item.details = "Public key p= tag is empty; domain owner revoked this selector per RFC 6376."
                signature_results.append(res_item)
                continue
        else:
            res_item.signature_status = "KEY_REVOKED"
            res_item.details = "Public key record lacks p= public key data."
            signature_results.append(res_item)
            continue

        # If already expired, preserve expired status but still compute body hash check
        # 5. Cryptographic Verification via dkim.DKIM.verify
        try:
            # We wrap verification for this specific signature index
            sig_valid = d.verify(idx=idx, dnsfunc=active_dnsfunc)
            if sig_valid:
                res_item.body_hash_status = "MATCH"
                if not res_item.is_expired:
                    res_item.signature_status = "PASS"
                    res_item.details = f"Cryptographically verified RSA/Ed25519 signature for d={d_val} s={s_val}."
            else:
                if not res_item.is_expired:
                    res_item.signature_status = "FAIL"
                    res_item.details = f"DKIM cryptographic verification failed for d={d_val} s={s_val}."
        except dkim.ValidationError as ve:
            err_msg = str(ve).lower()
            if "body hash mismatch" in err_msg:
                res_item.body_hash_status = "MISMATCH"
                res_item.signature_status = "BODY_HASH_MISMATCH"
                res_item.details = f"DKIM body hash mismatch (body altered in transit): {ve}"
            else:
                if not res_item.is_expired:
                    res_item.signature_status = "FAIL"
                    res_item.details = f"DKIM Validation Error: {ve}"
        except (dkim.KeyFormatError, dkim.MessageFormatError) as me:
            res_item.signature_status = "INVALID"
            res_item.details = f"DKIM Format Error: {me}"
        except Exception as exc:
            if not res_item.is_expired:
                res_item.signature_status = "FAIL"
                res_item.details = f"DKIM Verification Exception: {exc}"

        signature_results.append(res_item)

    # Determine consolidated status
    primary_domain = signature_results[0].domain if signature_results else None
    primary_selector = signature_results[0].selector if signature_results else None

    # Priority ranking for consolidated DKIM status:
    # PASS if at least one signature verified PASS
    if any(s.signature_status == "PASS" for s in signature_results):
        consolidated_status = "PASS"
    elif any(s.signature_status == "BODY_HASH_MISMATCH" for s in signature_results):
        consolidated_status = "BODY_HASH_MISMATCH"
    elif any(s.signature_status == "EXPIRED" for s in signature_results):
        consolidated_status = "EXPIRED"
    elif any(s.signature_status == "KEY_REVOKED" for s in signature_results):
        consolidated_status = "KEY_REVOKED"
    elif any(s.signature_status == "KEY_UNAVAILABLE" for s in signature_results):
        consolidated_status = "KEY_UNAVAILABLE"
    elif any(s.signature_status in ("FAIL", "INVALID") for s in signature_results):
        consolidated_status = "FAIL"
    else:
        consolidated_status = "NONE"

    return (
        consolidated_status,
        primary_selector,
        primary_domain,
        signature_results,
        dns_snapshots,
        dns_live_flag,
    )


def verify_spf_pyspf(
    connecting_ip: Optional[str],
    envelope_sender: Optional[str],
    helo_name: Optional[str],
    timeout: float = DNS_QUERY_TIMEOUT_SECONDS,
    custom_records: Optional[Dict[str, List[str]]] = None,
) -> tuple[str, str, int, Optional[str], bool]:
    """Execute real SPF verification via pyspf (RFC 7208).

    Evaluates:
    - Connecting IP from the first trusted hop
    - Envelope MAIL FROM sender
    - Client HELO/EHLO identity
    - 10-lookup mechanism limit (RFC 7208 Section 4.6.4)
    - PermError and TempError states

    Returns:
        (spf_status, spf_domain, lookups_count, explanation, dns_live)
    """
    domain = envelope_sender.split("@")[-1].strip().lower() if envelope_sender and "@" in envelope_sender else ""
    if not domain and helo_name:
        domain = helo_name.strip().lower()

    if not connecting_ip:
        return "NONE", domain, 0, "No connecting IP identified from reliable MTA hops.", False

    # Check for private or non-routable IPs (skip check if custom_records fixture is provided)
    if not custom_records:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(connecting_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return "UNVERIFIABLE", domain, 0, f"Connecting IP {connecting_ip} is RFC 1918 private/local; cannot evaluate public SPF.", False
        except ValueError:
            return "PERMERROR", domain, 0, f"Malformed connecting IP address: {connecting_ip}", False

    sender_addr = envelope_sender or (f"postmaster@{domain}" if domain else "postmaster@unknown")
    client_helo = helo_name or domain or "unknown"

    # If custom DNS records are supplied for testing, intercept DNS queries in spf.query
    dns_live = False
    try:
        q = spf.query(i=connecting_ip, s=sender_addr, h=client_helo, timeout=timeout)

        if custom_records:
            for k, recs in custom_records.items():
                clean_k = k.strip().rstrip(".").lower()
                q.cache[(clean_k, "TXT")] = [[r.encode("utf-8")] for r in recs]

            original_dns_txt = q.dns_txt
            def patched_dns_txt(domainname: str, rr: str = "TXT", ignore_void: bool = False) -> List[bytes]:
                clean_name = domainname.strip().rstrip(".").lower()
                for k, recs in custom_records.items():
                    if k.strip().rstrip(".").lower() == clean_name:
                        return [r.encode("utf-8") for r in recs]
                return original_dns_txt(domainname, rr, ignore_void)
            q.dns_txt = patched_dns_txt  # type: ignore[assignment]

        res, code, explanation = q.check()
        lookups = getattr(q, "lookups", 0)

        # Check for RFC 7208 10-lookup limit
        if lookups > 10:
            return "PERMERROR", domain, lookups, f"RFC 7208 SPF 10-lookup limit exceeded ({lookups} lookups).", dns_live

        mapped_status = res.upper()
        if mapped_status == "TEMPERROR":
            explanation_str = f"SPF DNS resolution timed out or server unavailable: {explanation}"
        elif mapped_status == "PERMERROR":
            explanation_str = f"SPF Permanent Syntax or Evaluation Error: {explanation}"
        else:
            explanation_str = f"SPF {mapped_status}: {explanation}"

        if not custom_records and lookups > 0:
            dns_live = True

        return mapped_status, domain, lookups, explanation_str, dns_live

    except spf.TempError as te:
        return "TEMPERROR", domain, 0, f"SPF Temporary DNS Resolution Failure: {te}", False
    except spf.PermError as pe:
        return "PERMERROR", domain, 0, f"SPF Permanent Configuration Error: {pe}", False
    except Exception as exc:
        logger.debug("pyspf check error: %s", exc)
        return "UNVERIFIABLE", domain, 0, f"SPF evaluation aborted: {exc}", False


def verify_dmarc_rfc7489(
    from_domain: str,
    spf_status: str,
    spf_domain: Optional[str],
    dkim_signatures: List[DkimSignatureResult],
    timeout: float = DNS_QUERY_TIMEOUT_SECONDS,
    custom_records: Optional[Dict[str, List[str]]] = None,
) -> tuple[str, str, bool, bool, Optional[str], bool]:
    """Execute RFC 7489 DMARC policy check and strict/relaxed alignment evaluation.

    Computes:
    - SPF alignment (strict: exact match; relaxed: PSL organizational domain match)
    - DKIM alignment (strict: exact match; relaxed: PSL organizational domain match)
    - Only verifies alignment if the underlying protocol passed cryptographically!

    Returns:
        (dmarc_status, dmarc_policy, alignment_spf, alignment_dkim, org_domain, dns_live)
    """
    if not from_domain:
        return "NONE", "none", False, False, None, False

    org_domain = extract_organizational_domain(from_domain)
    dns_live = False

    # 1. Fetch DMARC TXT record at _dmarc.<from_domain>
    dmarc_query_domain = f"_dmarc.{from_domain}"
    recs = query_dns_txt_with_timeout(dmarc_query_domain, timeout=timeout, custom_records=custom_records)
    if not recs and org_domain and org_domain != from_domain:
        # Query organizational domain DMARC record
        dmarc_query_domain = f"_dmarc.{org_domain}"
        recs = query_dns_txt_with_timeout(dmarc_query_domain, timeout=timeout, custom_records=custom_records)

    dmarc_policy = "none"
    dmarc_record_found = False
    aspf_mode = "r"
    adkim_mode = "r"

    for r in recs:
        if "v=dmarc1" in r.lower():
            dmarc_record_found = True
            if not custom_records:
                dns_live = True
            p_match = re.search(r"\bp=([a-zA-Z]+)", r, re.IGNORECASE)
            if p_match:
                dmarc_policy = p_match.group(1).lower()

            aspf_match = re.search(r"\baspf=([rs])", r, re.IGNORECASE)
            if aspf_match:
                aspf_mode = aspf_match.group(1).lower()

            adkim_match = re.search(r"\badkim=([rs])", r, re.IGNORECASE)
            if adkim_match:
                adkim_mode = adkim_match.group(1).lower()
            break

    # 2. Evaluate SPF alignment (SPF must have PASSED)
    align_spf = False
    if spf_status == "PASS" and spf_domain:
        is_strict = (aspf_mode == "s")
        align_spf = check_alignment(from_domain, spf_domain, strict=is_strict)

    # 3. Evaluate DKIM alignment (At least one DKIM signature must have PASSED)
    align_dkim = False
    is_strict_dkim = (adkim_mode == "s")
    for sig in dkim_signatures:
        if sig.signature_status == "PASS" and sig.domain:
            if check_alignment(from_domain, sig.domain, strict=is_strict_dkim):
                align_dkim = True
                break

    # 4. Synthesize DMARC Status
    if not dmarc_record_found:
        dmarc_status = "NONE"
    else:
        if align_spf or align_dkim:
            dmarc_status = "PASS"
        else:
            dmarc_status = "FAIL"

    return dmarc_status, dmarc_policy, align_spf, align_dkim, org_domain, dns_live


def verify_arc_chain(
    raw_bytes: bytes,
    dnsfunc: Optional[Callable[[bytes, float], Optional[bytes]]] = None,
    timeout: float = DNS_QUERY_TIMEOUT_SECONDS,
) -> ArcChainResult:
    """Verify Authenticated Received Chain (RFC 8617) using dkimpy."""
    if not raw_bytes or b"ARC-Seal" not in raw_bytes:
        return ArcChainResult(status="NONE", chain_validation="none", instances_count=0)

    try:
        arc_obj = dkim.ARC(raw_bytes)
        max_instance, arc_headers_w_instance = arc_obj.sorted_arc_headers()
        if max_instance == 0:
            return ArcChainResult(status="NONE", chain_validation="none", instances_count=0)

        cv_res, details_list, reason_msg = dkim.arc_verify(raw_bytes, dnsfunc=dnsfunc)
        cv_str = cv_res.decode("utf-8", errors="replace") if isinstance(cv_res, bytes) else str(cv_res)

        formatted_details = []
        for item in details_list:
            if isinstance(item, dict):
                formatted_details.append({
                    "instance": item.get("instance"),
                    "cv": item.get("cv", b"").decode("utf-8", errors="replace") if isinstance(item.get("cv"), bytes) else str(item.get("cv")),
                    "ams_valid": item.get("ams-valid"),
                    "as_valid": item.get("as-valid"),
                })

        status_mapped = "PASS" if cv_str.lower() == "pass" else ("FAIL" if cv_str.lower() == "fail" else "NONE")

        return ArcChainResult(
            status=status_mapped,
            chain_validation=cv_str.lower(),
            instances_count=max_instance,
            details=formatted_details,
            reason=str(reason_msg),
        )
    except Exception as exc:
        logger.debug("ARC verification exception: %s", exc)
        return ArcChainResult(
            status="FAIL",
            chain_validation="fail",
            instances_count=0,
            reason=f"ARC verification error: {exc}",
        )


def validate_protocol_authentication(
    from_email: Optional[str],
    return_path: Optional[str],
    headers_dict: Dict[str, list],
    auth_results_header: Optional[str] = None,
    raw_bytes: Optional[bytes] = None,
    connecting_ip: Optional[str] = None,
    helo_name: Optional[str] = None,
    dnsfunc: Optional[Callable[[bytes, float], Optional[bytes]]] = None,
    custom_dns_records: Optional[Dict[str, List[str]]] = None,
) -> AuthValidationResult:
    """Perform comprehensive forensic SPF, DKIM, DMARC, and ARC protocol validation.

    Independently recomputes all verdicts using raw byte cryptography and live/fixture DNS lookups.
    Compares recomputed verdicts with upstream MTA claims and flags discrepancies.
    """
    from_domain = from_email.split("@")[-1].strip().lower() if from_email and "@" in from_email else ""
    return_domain = return_path.split("@")[-1].strip().lower() if return_path and "@" in return_path else ""

    # 1. Parse Claimed Upstream MTA Headers (Authentication-Results & Received-SPF)
    claimed_auth_results: Dict[str, str] = {}
    if auth_results_header:
        claimed_auth_results = parse_authentication_results(auth_results_header)
    elif "Authentication-Results" in headers_dict:
        claimed_auth_results = parse_authentication_results(str(headers_dict["Authentication-Results"][0]))

    claimed_received_spf: Dict[str, str] = {}
    if "Received-SPF" in headers_dict:
        claimed_received_spf = parse_received_spf_header(str(headers_dict["Received-SPF"][0]))

    claimed_by_mta = {
        "claimed_spf": claimed_auth_results.get("spf") or claimed_received_spf.get("spf") or "NONE",
        "claimed_dkim": claimed_auth_results.get("dkim") or "NONE",
        "claimed_dmarc": claimed_auth_results.get("dmarc") or "NONE",
        "claimed_arc": claimed_auth_results.get("arc") or "NONE",
        "claimed_client_ip": claimed_received_spf.get("client_ip"),
        "auth_serv_id": claimed_auth_results.get("auth_serv_id"),
    }

    # Derive connecting IP if not passed explicitly: check Received-SPF or first hop
    effective_ip = connecting_ip or claimed_received_spf.get("client_ip")
    effective_helo = helo_name or claimed_received_spf.get("helo") or from_domain

    # 2. Cryptographic DKIM Verification via dkimpy
    effective_bytes = raw_bytes or b""
    if not effective_bytes and headers_dict:
        # Reconstruct minimal RFC 822 byte payload if raw bytes were omitted
        lines = []
        for k, vals in headers_dict.items():
            for v in vals:
                lines.append(f"{k}: {v}".encode("utf-8"))
        lines.append(b"")
        lines.append(b"")
        effective_bytes = b"\r\n".join(lines)

    dkim_status, dkim_selector, dkim_domain, dkim_signatures, dns_snapshots, dkim_dns_live = verify_dkim_signatures(
        raw_bytes=effective_bytes,
        dnsfunc=dnsfunc,
        custom_records=custom_dns_records,
        timeout=DNS_QUERY_TIMEOUT_SECONDS,
    )

    # 3. Real SPF Evaluation via pyspf
    spf_status, spf_eval_domain, spf_lookups, spf_explanation, spf_dns_live = verify_spf_pyspf(
        connecting_ip=effective_ip,
        envelope_sender=return_path or from_email,
        helo_name=effective_helo,
        timeout=DNS_QUERY_TIMEOUT_SECONDS,
        custom_records=custom_dns_records,
    )

    spf_domain = spf_eval_domain or return_domain or from_domain

    # 4. RFC 7489 DMARC Evaluation & Alignment
    dmarc_status, dmarc_policy, align_spf, align_dkim, org_domain, dmarc_dns_live = verify_dmarc_rfc7489(
        from_domain=from_domain,
        spf_status=spf_status,
        spf_domain=spf_domain,
        dkim_signatures=dkim_signatures,
        timeout=DNS_QUERY_TIMEOUT_SECONDS,
        custom_records=custom_dns_records,
    )

    # 5. Real ARC Evaluation
    arc_result = verify_arc_chain(
        raw_bytes=effective_bytes,
        dnsfunc=dnsfunc,
        timeout=DNS_QUERY_TIMEOUT_SECONDS,
    )

    # 6. Discrepancy Detection: Compare Claimed Upstream MTA vs Recomputed
    discrepancies: List[str] = []
    has_discrepancy = False

    # Check SPF Discrepancy
    c_spf = str(claimed_by_mta.get("claimed_spf") or "NONE").upper()
    if c_spf in ("PASS", "FAIL", "SOFTFAIL") and spf_status not in ("NONE", "UNVERIFIABLE", "TEMPERROR"):
        if c_spf == "PASS" and spf_status in ("FAIL", "SOFTFAIL", "PERMERROR"):
            discrepancies.append(
                f"SPF Discrepancy: Upstream MTA claimed SPF '{c_spf}', but recomputed verification failed as '{spf_status}'."
            )
            has_discrepancy = True
        elif c_spf in ("FAIL", "SOFTFAIL") and spf_status == "PASS":
            discrepancies.append(
                f"SPF Discrepancy: Upstream MTA claimed SPF '{c_spf}', but recomputed verification evaluated as 'PASS'."
            )
            has_discrepancy = True

    # Check DKIM Discrepancy
    c_dkim = str(claimed_by_mta.get("claimed_dkim") or "NONE").upper()
    if c_dkim in ("PASS", "FAIL") and dkim_status not in ("NONE", "KEY_UNAVAILABLE"):
        if c_dkim == "PASS" and dkim_status in ("FAIL", "INVALID", "BODY_HASH_MISMATCH", "EXPIRED", "KEY_REVOKED"):
            discrepancies.append(
                f"DKIM Discrepancy: Upstream MTA claimed DKIM '{c_dkim}', but recomputed cryptographic verification yielded '{dkim_status}'."
            )
            has_discrepancy = True
        elif c_dkim == "FAIL" and dkim_status == "PASS":
            discrepancies.append(
                f"DKIM Discrepancy: Upstream MTA claimed DKIM '{c_dkim}', but recomputed cryptographic signature verified as 'PASS'."
            )
            has_discrepancy = True

    # Check DMARC Discrepancy
    c_dmarc = str(claimed_by_mta.get("claimed_dmarc") or "NONE").upper()
    if c_dmarc in ("PASS", "FAIL") and dmarc_status not in ("NONE", "UNVERIFIABLE"):
        if c_dmarc == "PASS" and dmarc_status == "FAIL":
            discrepancies.append(
                "DMARC Discrepancy: Upstream MTA claimed DMARC 'PASS', but recomputed alignment failed."
            )
            has_discrepancy = True

    # Check for Length Tag Abuse
    for sig in dkim_signatures:
        if sig.l_tag_abuse_detected:
            discrepancies.append(f"DKIM Header Warning: {sig.l_tag_explanation}")
            has_discrepancy = True

    # 7. Forensic Threat Score Calculation (0.0 = Safe, 100.0 = Extreme Risk)
    auth_score = 0.0
    details: Dict[str, Any] = {}

    # SPF Penalty
    if spf_status == "FAIL":
        auth_score += 40.0
        details["spf"] = f"SPF Hard Fail for connecting IP {effective_ip} on domain {spf_domain}"
    elif spf_status == "SOFTFAIL":
        auth_score += 25.0
        details["spf"] = f"SPF Softfail for connecting IP {effective_ip} on domain {spf_domain}"
    elif spf_status == "PERMERROR":
        auth_score += 30.0
        details["spf"] = f"SPF PermError: {spf_explanation}"
    elif spf_status == "NONE":
        auth_score += 15.0
        details["spf"] = "No SPF record published"

    # DKIM Penalty
    if dkim_status in ("FAIL", "INVALID", "BODY_HASH_MISMATCH"):
        auth_score += 40.0
        details["dkim"] = f"DKIM cryptographic verification failed ({dkim_status}) for domain {dkim_domain}"
    elif dkim_status == "EXPIRED":
        auth_score += 25.0
        details["dkim"] = "DKIM cryptographic signature has expired (x= tag)"
    elif dkim_status == "KEY_REVOKED":
        auth_score += 35.0
        details["dkim"] = "DKIM public key has been revoked by domain owner"
    elif dkim_status == "KEY_UNAVAILABLE":
        auth_score += 10.0
        details["dkim"] = "DKIM public key is currently unavailable in DNS (historical or offline)"
    elif dkim_status == "NONE":
        auth_score += 20.0
        details["dkim"] = "Email does not contain a DKIM cryptographic signature"

    # DMARC Penalty
    if dmarc_status == "FAIL":
        auth_score += 30.0
        details["dmarc"] = (
            f"DMARC validation failed (SPF aligned={align_spf}, DKIM aligned={align_dkim}, policy={dmarc_policy})"
        )

    # Discrepancy / Forgery Penalty
    if has_discrepancy:
        auth_score += 35.0
        details["discrepancy"] = "Critical: Upstream Authentication-Results contradict recomputed cryptographic ground truth (potential MTA forgery/spoofing)."

    # Cap score at 100.0
    auth_score = min(100.0, auth_score)

    overall_dns_live = dkim_dns_live or spf_dns_live or dmarc_dns_live
    details["dns_mode"] = "LIVE_DNS_TXT" if overall_dns_live else "OFFLINE_RESILIENT_OR_FIXTURE"

    recomputed_verdict = {
        "spf": spf_status,
        "spf_lookups": spf_lookups,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "alignment_spf": align_spf,
        "alignment_dkim": align_dkim,
        "arc": arc_result.status,
    }

    return AuthValidationResult(
        spf_status=spf_status,
        spf_domain=spf_domain,
        spf_client_ip=effective_ip,
        spf_helo=effective_helo,
        spf_lookups_count=spf_lookups,
        spf_explanation=spf_explanation,
        dkim_status=dkim_status,
        dkim_selector=dkim_selector,
        dkim_domain=dkim_domain,
        dkim_signatures=dkim_signatures,
        dmarc_status=dmarc_status,
        dmarc_policy=dmarc_policy,
        dmarc_alignment_spf=align_spf,
        dmarc_alignment_dkim=align_dkim,
        dmarc_org_domain=org_domain,
        arc=arc_result,
        claimed_by_mta=claimed_by_mta,
        recomputed_verdict=recomputed_verdict,
        has_discrepancy=has_discrepancy,
        discrepancies=discrepancies,
        auth_score=auth_score,
        dns_resolved_live=overall_dns_live,
        dns_key_snapshots=dns_snapshots,
        details=details,
    )
