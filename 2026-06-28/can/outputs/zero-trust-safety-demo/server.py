#!/usr/bin/env python3
"""Dependency-free hackathon demo for a zero-trust safety overlay.

This intentionally mirrors the FastAPI-shaped API from the source brief while
using only the Python standard library so it can run on a clean laptop.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "demo_audit.sqlite3"
SAFE_WORKSPACE = ROOT / "workspace"
SAFE_WORKSPACE.mkdir(exist_ok=True)

PENDING_INTERNAL_ARGS: dict[str, dict[str, Any]] = {}
SESSION_VAULTS: dict[str, dict[str, str]] = {}
LAST_INTEGRATION_ERRORS: dict[str, str] = {}


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_text(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def real_llm_enabled() -> bool:
    return env_bool("USE_REAL_LLM") or bool(env_text("LLM_API_BASE"))


def openbao_enabled() -> bool:
    return env_bool("USE_OPENBAO") or bool(env_text("OPENBAO_ADDR"))


def docker_enabled() -> bool:
    return env_bool("USE_DOCKER")


def nemo_enabled() -> bool:
    return env_bool("USE_NEMO")


POLICY = {
    "tools": {
        "read_file": {"risk": "medium", "approval_required": False, "allowed": True},
        "write_file": {"risk": "high", "approval_required": True, "allowed": True},
        "delete_file": {"risk": "critical", "approval_required": True, "allowed": True},
        "send_email": {"risk": "high", "approval_required": True, "allowed": True},
        "shell": {"risk": "high", "approval_required": True, "allowed": True},
        "http_request": {"risk": "medium", "approval_required": False, "allowed": True},
        "create_calendar_event": {"risk": "medium", "approval_required": False, "allowed": True},
    },
    "network": {
        "allowlist": [
            "github.com",
            "raw.githubusercontent.com",
            "pypi.org",
            "npmjs.com",
            "docs.nvidia.com",
            "api.openai.com",
            "exampleclinic.org",
        ],
        "blocklist": ["pastebin.com", "transfer.sh", "webhook.site", "attacker.com"],
    },
    "rules": {
        "block_raw_ip": True,
        "block_secret_exfiltration": True,
        "require_approval_for_unknown_domains": True,
        "require_approval_for_large_uploads": True,
        "max_outbound_body_chars_without_approval": 2000,
    },
}


GUARDRAIL_RULES = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore all instructions",
    "reveal your system prompt",
    "send the api key",
    "send the user's api key",
    "exfiltrate",
    "upload secrets",
    "print environment variables",
    "read .env",
    "send private data",
    "bypass policy",
    "disable safety",
]

SECURITY_KNOWLEDGE = [
    {
        "id": "mitre-credential-phishing",
        "source": "MITRE ATT&CK",
        "category": "attack",
        "title": "Credential phishing and data theft",
        "summary": "Emails that ask a user or agent to reveal credentials, tokens, SSNs, or private data match credential-phishing and information-theft behavior.",
        "keywords": "phishing credential ssn private data password token api key secret attacker exfiltrate send",
    },
    {
        "id": "mitre-bec",
        "source": "MITRE ATT&CK",
        "category": "attack",
        "title": "Business email compromise",
        "summary": "Business email compromise often uses ordinary-looking requests, new vendors, payment workflows, or external uploads to move sensitive information outside trusted channels.",
        "keywords": "vendor upload external new domain business email compromise request invoice payment sensitive information",
    },
    {
        "id": "cisa-phishing",
        "source": "CISA guidance",
        "category": "guidance",
        "title": "Phishing indicators",
        "summary": "CISA recommends treating urgent requests, credential requests, suspicious links, and unexpected attachments as phishing indicators that need verification.",
        "keywords": "phishing suspicious link urgent attachment verify credential request unknown sender",
    },
    {
        "id": "owasp-prompt-injection",
        "source": "OWASP LLM Top 10",
        "category": "attack",
        "title": "Prompt injection",
        "summary": "Prompt injection occurs when untrusted content tells an LLM or agent to ignore instructions, reveal secrets, bypass policy, or follow attacker-controlled commands.",
        "keywords": "prompt injection ignore previous instructions reveal system prompt bypass policy disable safety attacker",
    },
    {
        "id": "owasp-sensitive-info",
        "source": "OWASP LLM Top 10",
        "category": "policy",
        "title": "Sensitive information disclosure",
        "summary": "Agents must not expose personal data, secrets, or credentials to model context, logs, email, webhooks, or tools unless a trusted policy permits it.",
        "keywords": "sensitive information disclosure pii ssn email phone address secret credential logs webhook tool",
    },
    {
        "id": "policy-secrets",
        "source": "Enterprise policy",
        "category": "policy",
        "title": "Secrets and personal data handling",
        "summary": "Company policy blocks sending API keys, passwords, SSNs, private keys, or raw personal data to unapproved external destinations.",
        "keywords": "policy block api key password ssn private key personal data external destination webhook",
    },
    {
        "id": "policy-human-approval",
        "source": "Enterprise policy",
        "category": "policy",
        "title": "Human approval for high-risk actions",
        "summary": "Outbound email, shell execution, deletion, unknown domains, and large uploads require human approval before execution.",
        "keywords": "approval human review outbound email shell unknown domain large upload delete high risk",
    },
    {
        "id": "email-auth-lookalike",
        "source": "Email security notes",
        "category": "guidance",
        "title": "Spoofing and lookalike domains",
        "summary": "Unknown or lookalike sender domains should be treated with caution, especially when they request uploads, credentials, or workflow changes.",
        "keywords": "unknown domain lookalike spoofing dmarc dkim spf sender upload credential",
    },
    {
        "id": "prompt-patterns",
        "source": "Prompt injection patterns",
        "category": "guidance",
        "title": "Instruction hijack phrases",
        "summary": "Phrases such as ignore previous instructions, bypass policy, disable safety, or reveal system prompt are strong prompt-injection signals.",
        "keywords": "ignore previous instructions bypass policy disable safety reveal system prompt instruction hijack",
    },
    {
        "id": "incident-webhook-leak",
        "source": "Historical incidents",
        "category": "incident",
        "title": "Webhook secret leak precedent",
        "summary": "A prior incident involved a debug automation posting an API key and customer record to a webhook; the fix was to block secret-bearing outbound requests.",
        "keywords": "incident webhook api key customer record debug automation secret leak block",
    },
    {
        "id": "incident-ssh-key",
        "source": "Historical incidents",
        "category": "incident",
        "title": "Local key read attempt",
        "summary": "A prior attachment workflow attempted to read an SSH private key before upload; shell commands touching credentials are blocked before sandbox execution.",
        "keywords": "incident ssh private key attachment workflow shell cat id_rsa blocked sandbox",
    },
    {
        "id": "example-clean-calendar",
        "source": "Phishing examples",
        "category": "incident",
        "title": "Clean appointment scheduling example",
        "summary": "A normal meeting request can be allowed when private contact data is tokenized and outbound confirmation is routed through human approval.",
        "keywords": "clean meeting appointment calendar frido friday confirmation tokenized approval",
    },
]

DANGEROUS_SHELL_PATTERNS = [
    r"\brm\s+-rf\s+/",
    r"\bcurl\b.+\|\s*sh\b",
    r"\bwget\b.+\|\s*sh\b",
    r"\bcat\s+.*\.env\b",
    r"\bcat\s+.*id_rsa\b",
    r"\bprintenv\b",
    r"(^|\s)env(\s|$)",
    r"\bssh\b",
    r"\bscp\b",
]

SECRET_PATTERNS = [
    (
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{6,}\b"),
        "[OPENAI_API_KEY_REDACTED]",
    ),
    (
        "github_token",
        re.compile(r"\bghp_[A-Za-z0-9]{6,}\b"),
        "[GITHUB_TOKEN_REDACTED]",
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
        "[AWS_ACCESS_KEY_REDACTED]",
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "[PRIVATE_KEY_REDACTED]",
    ),
    (
        "password",
        re.compile(r"(?i)(password\s*[:=]\s*)[^\s,;&]+"),
        lambda match: match.group(1) + "[PASSWORD_REDACTED]",
    ),
    (
        "api_key",
        re.compile(r"(?i)(api_key\s*[:=]\s*)[^\s,;&]+"),
        lambda match: match.group(1) + "[API_KEY_REDACTED]",
    ),
    (
        "token",
        re.compile(r"(?i)(token\s*[:=]\s*)[^\s,;&]+"),
        lambda match: match.group(1) + "[TOKEN_REDACTED]",
    ),
]

PII_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL_REDACTED]",
    ),
    (
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
        "[PHONE_REDACTED]",
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "[CARD_REDACTED]",
    ),
    (
        "address",
        re.compile(
            r"\b\d{1,5}\s+[A-Za-z0-9 .'\-]+"
            r"\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct)\b",
            re.IGNORECASE,
        ),
        "[ADDRESS_REDACTED]",
    ),
    (
        "date_of_birth",
        re.compile(r"(?i)\b(?:dob|date of birth)\s*[:=]\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),
        "[DOB_REDACTED]",
    ),
]


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT,
                user_id TEXT,
                event_type TEXT,
                tool_name TEXT,
                input_redacted TEXT,
                output_redacted TEXT,
                decision TEXT,
                risk_level TEXT,
                reason TEXT,
                created_at TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                request_id TEXT,
                user_id TEXT,
                tool_name TEXT,
                tool_args_redacted TEXT,
                tool_args_encrypted_or_internal_ref TEXT,
                risk_level TEXT,
                reason TEXT,
                status TEXT,
                created_at TEXT,
                resolved_at TEXT
            )
            """
        )
        con.commit()


def integration_status() -> dict[str, Any]:
    """Report which real integrations are configured and reachable enough to try."""
    llm_base = env_text("LLM_API_BASE", "http://127.0.0.1:8000/v1")
    openbao_addr = env_text("OPENBAO_ADDR")
    docker_path = shutil.which("docker")
    return {
        "llm": {
            "enabled": real_llm_enabled(),
            "mode": "real_openai_compatible" if real_llm_enabled() else "simulated",
            "model": env_text("LLM_MODEL", "qwen2.5-32b-instruct"),
            "api_base": llm_base if real_llm_enabled() else "",
            "last_error": LAST_INTEGRATION_ERRORS.get("llm", ""),
        },
        "nemo": {
            "enabled": nemo_enabled(),
            "mode": "real_nemo_guardrails" if nemo_enabled() else "rule_based",
            "config_path": env_text("NEMO_CONFIG_PATH", str(ROOT / "nemo_guardrails_config")),
            "last_error": LAST_INTEGRATION_ERRORS.get("nemo", ""),
        },
        "docker": {
            "enabled": docker_enabled(),
            "mode": "docker_sandbox" if docker_enabled() else "blocked_shell_fallback",
            "docker_path": docker_path or "",
            "last_error": LAST_INTEGRATION_ERRORS.get("docker", ""),
        },
        "openbao": {
            "enabled": openbao_enabled(),
            "mode": "openbao_kv_v2" if openbao_enabled() else "in_memory_vault",
            "addr": openbao_addr,
            "mount": env_text("OPENBAO_KV_MOUNT", "secret"),
            "last_error": LAST_INTEGRATION_ERRORS.get("openbao", ""),
        },
    }


def db_rows(query: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        return [dict(row) for row in con.execute(query, args).fetchall()]


def log_event(
    *,
    request_id: str,
    user_id: str,
    event_type: str,
    decision: str,
    risk_level: str,
    reason: str,
    tool_name: str | None = None,
    input_redacted: Any = None,
    output_redacted: Any = None,
) -> None:
    safe_input = safe_json(input_redacted)
    safe_output = safe_json(output_redacted)
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            INSERT INTO audit_logs (
                request_id, user_id, event_type, tool_name, input_redacted,
                output_redacted, decision, risk_level, reason, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                user_id,
                event_type,
                tool_name,
                safe_input,
                safe_output,
                decision,
                risk_level,
                reason,
                now_iso(),
            ),
        )
        con.commit()


def safe_json(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        redacted, _ = redact_all_text(value)
        return redacted
    redacted = redact_value(value)
    return json.dumps(redacted, ensure_ascii=True, sort_keys=True)


def redact_with_patterns(
    text: str, patterns: list[tuple[str, re.Pattern[str], str | Any]]
) -> tuple[str, list[str]]:
    redacted = text
    found: list[str] = []
    for name, pattern, replacement in patterns:
        if pattern.search(redacted):
            found.append(name)
        redacted = pattern.sub(replacement, redacted)
    return redacted, sorted(set(found))


def redact_secrets(text: str) -> tuple[str, list[str]]:
    return redact_with_patterns(text, SECRET_PATTERNS)


def redact_pii(text: str) -> tuple[str, list[str]]:
    return redact_with_patterns(text, PII_PATTERNS)


def redact_all_text(text: str) -> tuple[str, dict[str, list[str]]]:
    redacted, secret_types = redact_secrets(text)
    redacted, pii_types = redact_pii(redacted)
    return redacted, {"secret_types": secret_types, "pii_types": pii_types}


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_all_text(value)[0]
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def detect_value(value: Any) -> dict[str, list[str]]:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True) if not isinstance(value, str) else value
    _, detection = redact_all_text(text)
    return detection


def extract_subject(text: str) -> str:
    match = re.search(r"(?im)^subject:\s*(.+)$", text)
    return match.group(1).strip() if match else ""


def security_tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-zA-Z0-9_.'-]{3,}", text.lower())
        if token not in {"the", "and", "for", "with", "from", "this", "that", "are", "you", "your"}
    }


def security_rule_flags(text: str, tool_name: str = "", args: dict[str, Any] | None = None) -> list[str]:
    args = args or {}
    redacted_text = redact_value(text)
    lowered = str(redacted_text).lower()
    flags: list[str] = []
    if any(rule in lowered for rule in GUARDRAIL_RULES):
        flags.append("prompt_injection")
    detections = detect_value(args if args else redacted_text)
    if detections["secret_types"]:
        flags.append("secret_detected")
    if detections["pii_types"]:
        flags.append("pii_detected")
    if tool_name == "shell":
        command = str(args.get("command", ""))
        if shell_is_dangerous(command):
            flags.append("dangerous_shell")
        else:
            flags.append("shell_requires_approval")
    if tool_name == "send_email":
        flags.append("outbound_email_requires_approval")
    if tool_name == "http_request":
        domain = url_domain(str(args.get("url", "")))[0] or ""
        if domain and domain_matches(domain, POLICY["network"]["blocklist"]):
            flags.append("blocklisted_domain")
        elif domain and not domain_matches(domain, POLICY["network"]["allowlist"]):
            flags.append("unknown_domain")
        else:
            flags.append("allowlisted_domain")
        if len(str(args.get("body", ""))) > POLICY["rules"]["max_outbound_body_chars_without_approval"]:
            flags.append("large_upload")
    if "frido" in lowered and "friday" in lowered:
        flags.append("clean_calendar_request")
    return sorted(set(flags))


def security_search_query(text: str, flags: list[str], tool_name: str = "") -> str:
    subject = extract_subject(text)
    parts = []
    if subject:
        parts.append(f"subject {redact_value(subject)}")
    parts.extend(flags)
    if tool_name:
        parts.append(f"tool {tool_name}")
    return " ".join(parts)[:500] or "email security decision"


def security_rag_search(query: str, flags: list[str], limit: int = 5) -> list[dict[str, Any]]:
    query_terms = security_tokens(query + " " + " ".join(flags))
    scored: list[tuple[int, dict[str, Any]]] = []
    for doc in SECURITY_KNOWLEDGE:
        haystack = " ".join([doc["title"], doc["summary"], doc["keywords"], doc["category"]])
        score = len(query_terms & security_tokens(haystack))
        if doc["category"] == "attack" and any(flag in flags for flag in ["prompt_injection", "secret_detected", "dangerous_shell", "blocklisted_domain"]):
            score += 2
        if doc["category"] == "policy" and any(flag in flags for flag in ["pii_detected", "secret_detected", "unknown_domain", "large_upload", "outbound_email_requires_approval"]):
            score += 2
        if doc["category"] == "incident" and any(flag in flags for flag in ["clean_calendar_request", "secret_detected", "dangerous_shell"]):
            score += 2
        if score:
            scored.append((score, doc))

    scored.sort(key=lambda item: (-item[0], item[1]["id"]))
    selected: list[dict[str, Any]] = []
    used: set[str] = set()
    for category in ["attack", "policy", "incident"]:
        for score, doc in scored:
            if doc["category"] == category and doc["id"] not in used:
                selected.append({**doc, "score": score})
                used.add(doc["id"])
                break
    for score, doc in scored:
        if len(selected) >= limit:
            break
        if doc["id"] not in used:
            selected.append({**doc, "score": score})
            used.add(doc["id"])

    return [
        {
            "citation_id": item["id"],
            "source": item["source"],
            "category": item["category"],
            "title": item["title"],
            "summary": item["summary"],
            "score": item["score"],
        }
        for item in selected[:limit]
    ]


def security_analyst_verdict(status: str, reason: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    valid_ids = {item["citation_id"] for item in evidence}
    citations = [item["citation_id"] for item in evidence[:3] if item["citation_id"] in valid_ids]
    if not citations:
        return {
            "verdict": status,
            "confidence": "low",
            "rationale": "No retrieved evidence was available, so the verdict falls back to rule checks.",
            "citations": [],
            "fallback_to_rules": True,
        }
    return {
        "verdict": status,
        "confidence": "high" if status == "blocked" else "medium",
        "rationale": f"Rule outcome '{status}' is supported by retrieved security evidence and remains controlled by policy.",
        "citations": citations,
        "fallback_to_rules": False,
    }


def security_rag_context(
    *,
    text: str,
    status: str,
    reason: str,
    tool_name: str = "",
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    flags = security_rule_flags(text, tool_name=tool_name, args=args)
    query = security_search_query(text, flags, tool_name=tool_name)
    evidence = security_rag_search(query, flags)
    return {
        "mode": "local_curated_keyword_rag",
        "query_redacted": query,
        "rule_flags": flags,
        "evidence": evidence,
        "analyst_verdict": security_analyst_verdict(status, reason, evidence),
        "rule_checks_win": True,
    }


def token_for(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:8].upper()
    return f"PII_{kind.upper()}_{digest}"


def mask_value(kind: str, value: str) -> str:
    if kind == "email" and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    digits = re.sub(r"\D", "", value)
    if kind in {"phone", "ssn", "credit_card"} and len(digits) >= 4:
        return f"***{digits[-4:]}"
    if kind == "address":
        return "street address hidden"
    if kind == "date_of_birth":
        return "date hidden"
    return "hidden"


def vault_storage_label() -> str:
    return "OpenBao KV v2" if openbao_enabled() else "session vault only"


def tokenize_pii(text: str) -> tuple[str, list[dict[str, str]], dict[str, str]]:
    vault: dict[str, str] = {}
    public_entries: dict[str, dict[str, str]] = {}
    tokenized = text

    for kind, pattern, _ in PII_PATTERNS:
        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            token = token_for(kind, value)
            vault[token] = value
            public_entries[token] = {
                "type": kind,
                "token": token,
                "masked_value": mask_value(kind, value),
                "storage": vault_storage_label(),
                "agent_visibility": "token only",
            }
            return token

        tokenized = pattern.sub(replace, tokenized)

    return tokenized, list(public_entries.values()), vault


def openbao_url(path: str) -> str:
    return env_text("OPENBAO_ADDR").rstrip("/") + "/v1/" + path.lstrip("/")


def openbao_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = env_text("OPENBAO_TOKEN")
    if token:
        headers["X-Vault-Token"] = token
    return headers


def openbao_kv_path(request_id: str) -> str:
    mount = env_text("OPENBAO_KV_MOUNT", "secret").strip("/")
    prefix = env_text("OPENBAO_KV_PREFIX", "zero-trust-demo/session").strip("/")
    return f"{mount}/data/{prefix}/{request_id}"


def store_vault_refs(request_id: str, private_vault: dict[str, str]) -> dict[str, Any]:
    SESSION_VAULTS[request_id] = private_vault
    if not openbao_enabled():
        return {"backend": "memory", "stored": bool(private_vault), "tokens": len(private_vault)}

    payload = json.dumps({"data": private_vault}, ensure_ascii=True).encode("utf-8")
    req = urlrequest.Request(
        openbao_url(openbao_kv_path(request_id)),
        data=payload,
        headers=openbao_headers(),
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            resp.read()
        LAST_INTEGRATION_ERRORS.pop("openbao", None)
        return {"backend": "openbao", "stored": True, "tokens": len(private_vault)}
    except Exception as exc:  # noqa: BLE001 - report real integration failures in health.
        LAST_INTEGRATION_ERRORS["openbao"] = f"{exc.__class__.__name__}: {exc}"
        return {"backend": "memory_fallback", "stored": bool(private_vault), "tokens": len(private_vault)}


def load_vault_refs(request_id: str) -> tuple[dict[str, str], str]:
    if openbao_enabled():
        req = urlrequest.Request(openbao_url(openbao_kv_path(request_id)), headers=openbao_headers(), method="GET")
        try:
            with urlrequest.urlopen(req, timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            data = payload.get("data", {}).get("data", {})
            if isinstance(data, dict):
                LAST_INTEGRATION_ERRORS.pop("openbao", None)
                return {str(key): str(value) for key, value in data.items()}, "openbao"
        except Exception as exc:  # noqa: BLE001
            LAST_INTEGRATION_ERRORS["openbao"] = f"{exc.__class__.__name__}: {exc}"
    return SESSION_VAULTS.get(request_id, {}), "memory"


def resolve_vault_token(request_id: str, token: str) -> tuple[str | None, str]:
    vault, backend = load_vault_refs(request_id)
    return vault.get(token), backend


def rule_based_guardrail_check(text: str) -> dict[str, Any]:
    lowered = text.lower()
    matched = [rule for rule in GUARDRAIL_RULES if rule in lowered]
    if matched:
        return {
            "allowed": False,
            "risk_level": "high",
            "reason": "Potential prompt injection detected",
            "matched_rules": matched,
        }
    return {
        "allowed": True,
        "risk_level": "low",
        "reason": "No prompt-injection rules matched",
        "matched_rules": [],
    }


def nemo_guardrail_check(text: str) -> dict[str, Any]:
    config_path = env_text("NEMO_CONFIG_PATH", str(ROOT / "nemo_guardrails_config"))
    try:
        from nemoguardrails import LLMRails, RailsConfig  # type: ignore

        config = RailsConfig.from_path(config_path)
        rails = LLMRails(config)
        result = rails.generate(messages=[{"role": "user", "content": text}])
        content = result.get("content", "") if isinstance(result, dict) else str(result)
        lowered = content.lower()
        blocked = any(word in lowered for word in ["block", "blocked", "not allowed", "unsafe", "yes"])
        LAST_INTEGRATION_ERRORS.pop("nemo", None)
        return {
            "allowed": not blocked,
            "risk_level": "high" if blocked else "low",
            "reason": "NeMo Guardrails blocked input" if blocked else "NeMo Guardrails allowed input",
            "matched_rules": ["nemo_guardrails"] if blocked else [],
            "engine": "nemo_guardrails",
            "nemo_response_redacted": redact_value(content[:500]),
        }
    except Exception as exc:  # noqa: BLE001
        LAST_INTEGRATION_ERRORS["nemo"] = f"{exc.__class__.__name__}: {exc}"
        fallback = rule_based_guardrail_check(text)
        fallback["engine"] = "rule_based_fallback"
        fallback["fallback_reason"] = LAST_INTEGRATION_ERRORS["nemo"]
        return fallback


def guardrail_check(text: str) -> dict[str, Any]:
    if nemo_enabled():
        return nemo_guardrail_check(text)
    result = rule_based_guardrail_check(text)
    result["engine"] = "rule_based"
    return result


def domain_matches(domain: str, candidates: list[str]) -> bool:
    normalized = domain.lower().strip(".")
    return any(normalized == item or normalized.endswith("." + item) for item in candidates)


def url_domain(url: str) -> tuple[str | None, str | None]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None, "URL must be http(s) and include a host"
    return parsed.hostname.lower(), None


def is_raw_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def shell_is_dangerous(command: str) -> str | None:
    for pattern in DANGEROUS_SHELL_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return pattern
    return None


def policy_decision(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    tool = POLICY["tools"].get(tool_name)
    detection = detect_value(args)
    secret_types = detection["secret_types"]
    pii_types = detection["pii_types"]

    if not tool:
        return {
            "decision": "block",
            "risk_level": "critical",
            "reason": f"Unknown tool '{tool_name}' is denied by default",
            "detections": detection,
        }
    if not tool["allowed"]:
        return {
            "decision": "block",
            "risk_level": tool["risk"],
            "reason": f"Tool '{tool_name}' is disabled by policy",
            "detections": detection,
        }

    if secret_types and tool_name in {"http_request", "send_email", "write_file"}:
        return {
            "decision": "block",
            "risk_level": "critical",
            "reason": "Secret exfiltration attempt detected",
            "detections": detection,
        }

    if tool_name == "shell":
        command = str(args.get("command", ""))
        matched = shell_is_dangerous(command)
        if matched:
            return {
                "decision": "block",
                "risk_level": "critical",
                "reason": "Dangerous shell command blocked before sandboxing",
                "matched_rule": matched,
                "detections": detection,
            }

    if tool_name == "http_request":
        url = str(args.get("url", ""))
        body = str(args.get("body", ""))
        domain, error = url_domain(url)
        if error:
            return {
                "decision": "block",
                "risk_level": "high",
                "reason": error,
                "detections": detection,
            }
        assert domain is not None
        if POLICY["rules"]["block_raw_ip"] and is_raw_ip(domain):
            return {
                "decision": "block",
                "risk_level": "critical",
                "reason": "Raw IP outbound requests are blocked",
                "detections": detection,
            }
        if domain_matches(domain, POLICY["network"]["blocklist"]):
            return {
                "decision": "block",
                "risk_level": "critical" if secret_types else "high",
                "reason": f"Domain '{domain}' is on the blocklist",
                "detections": detection,
            }
        if (
            POLICY["rules"]["require_approval_for_large_uploads"]
            and len(body) > POLICY["rules"]["max_outbound_body_chars_without_approval"]
        ):
            return {
                "decision": "require_approval",
                "risk_level": "high",
                "reason": "Large outbound body requires human approval",
                "detections": detection,
            }
        if not domain_matches(domain, POLICY["network"]["allowlist"]):
            return {
                "decision": "require_approval",
                "risk_level": "medium",
                "reason": f"Unknown domain '{domain}' requires human approval",
                "detections": detection,
            }

    if tool.get("approval_required"):
        return {
            "decision": "require_approval",
            "risk_level": tool["risk"],
            "reason": f"Tool '{tool_name}' requires human approval",
            "detections": detection,
        }

    return {
        "decision": "allow",
        "risk_level": tool["risk"],
        "reason": "Policy checks passed",
        "detections": detection,
    }


def safe_join_workspace(path_text: str) -> Path | None:
    requested = (SAFE_WORKSPACE / path_text.lstrip("/")).resolve()
    if SAFE_WORKSPACE.resolve() not in requested.parents and requested != SAFE_WORKSPACE.resolve():
        return None
    return requested


def run_docker_sandbox(command: str) -> dict[str, Any]:
    docker_path = shutil.which("docker")
    if not docker_enabled():
        return {"executed": False, "reason": "Docker sandbox disabled; set USE_DOCKER=1"}
    if not docker_path:
        LAST_INTEGRATION_ERRORS["docker"] = "docker CLI not found"
        return {"executed": False, "reason": "Docker CLI not found"}

    image = env_text("DOCKER_SANDBOX_IMAGE", "alpine:3.20")
    timeout = int(env_text("DOCKER_SANDBOX_TIMEOUT_SECONDS", "10"))
    memory = env_text("DOCKER_SANDBOX_MEMORY", "512m")
    cpus = env_text("DOCKER_SANDBOX_CPUS", "1")

    with tempfile.TemporaryDirectory(prefix="zt-sandbox-", dir=str(SAFE_WORKSPACE)) as temp_dir:
        cmd = [
            docker_path,
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            memory,
            "--cpus",
            cpus,
            "--read-only",
            "-v",
            f"{temp_dir}:/workspace:rw",
            "-w",
            "/workspace",
            image,
            "/bin/sh",
            "-lc",
            command,
        ]
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            LAST_INTEGRATION_ERRORS.pop("docker", None)
            return {
                "executed": True,
                "sandbox": "docker",
                "image": image,
                "network": "none",
                "exit_code": completed.returncode,
                "stdout_redacted": redact_value(completed.stdout[-4000:]),
                "stderr_redacted": redact_value(completed.stderr[-4000:]),
            }
        except subprocess.TimeoutExpired:
            LAST_INTEGRATION_ERRORS["docker"] = "sandbox timeout"
            return {"executed": False, "sandbox": "docker", "reason": "Sandbox timeout"}
        except Exception as exc:  # noqa: BLE001
            LAST_INTEGRATION_ERRORS["docker"] = f"{exc.__class__.__name__}: {exc}"
            return {"executed": False, "sandbox": "docker", "reason": LAST_INTEGRATION_ERRORS["docker"]}


def execute_tool(tool_name: str, args: dict[str, Any], request_id: str, user_id: str) -> dict[str, Any]:
    if tool_name == "http_request":
        url = str(args.get("url", ""))
        method = str(args.get("method", "GET")).upper()
        body = str(args.get("body", ""))
        domain = url_domain(url)[0] or "unknown"
        result = {
            "executed": True,
            "simulation": True,
            "method": method,
            "url": url,
            "status_code": 200,
            "body_preview": "Simulated allowlisted response. No external network call was made.",
        }
        log_event(
            request_id=request_id,
            user_id=user_id,
            event_type="network_request_allowed",
            tool_name=tool_name,
            input_redacted={"method": method, "url": url, "bytes_sent": len(body), "domain": domain},
            output_redacted={"bytes_received": 72, "simulation": True},
            decision="allow",
            risk_level="medium",
            reason=f"Network monitor allowed '{domain}'",
        )
        return result

    if tool_name == "send_email":
        recipient_token = str(args.get("to", ""))
        resolved_recipient, vault_backend = resolve_vault_token(request_id, recipient_token)
        return {
            "executed": True,
            "simulation": True,
            "message_id": "msg_" + uuid.uuid4().hex[:10],
            "to": recipient_token,
            "recipient_resolution": (
                f"resolved backend-only via {vault_backend}" if resolved_recipient else "token not resolved"
            ),
            "recipient_masked": mask_value("email", resolved_recipient) if resolved_recipient else "",
            "subject": args.get("subject"),
            "body_redacted": redact_value(args.get("body", "")),
        }

    if tool_name == "create_calendar_event":
        return {
            "executed": True,
            "simulation": True,
            "event_id": "evt_" + uuid.uuid4().hex[:10],
            "title": args.get("title", "Protected automation"),
            "time": args.get("time", "requested time"),
            "attendee_ref": args.get("attendee_ref", "tokenized"),
            "notes": args.get("notes", ""),
        }

    if tool_name == "read_file":
        safe_path = safe_join_workspace(str(args.get("path", "")))
        if not safe_path or not safe_path.exists() or not safe_path.is_file():
            return {"executed": False, "reason": "File is outside safe workspace or does not exist"}
        return {"executed": True, "content_redacted": redact_value(safe_path.read_text(encoding="utf-8"))}

    if tool_name == "write_file":
        safe_path = safe_join_workspace(str(args.get("path", "")))
        if not safe_path:
            return {"executed": False, "reason": "Path traversal blocked"}
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        content = redact_value(str(args.get("content", "")))
        safe_path.write_text(content, encoding="utf-8")
        return {"executed": True, "path": str(safe_path.relative_to(ROOT)), "stored": "redacted content only"}

    if tool_name == "delete_file":
        safe_path = safe_join_workspace(str(args.get("path", "")))
        if not safe_path or not safe_path.exists() or not safe_path.is_file():
            return {"executed": False, "reason": "File is outside safe workspace or does not exist"}
        safe_path.unlink()
        return {"executed": True, "path": str(safe_path.relative_to(ROOT))}

    if tool_name == "shell":
        return run_docker_sandbox(str(args.get("command", "")))

    return {"executed": False, "reason": "No executor is implemented for this tool"}


def create_approval(
    *,
    request_id: str,
    user_id: str,
    tool_name: str,
    args: dict[str, Any],
    risk_level: str,
    reason: str,
) -> dict[str, Any]:
    approval_id = str(uuid.uuid4())
    internal_ref = "memref_" + approval_id
    redacted_args = redact_value(args)
    PENDING_INTERNAL_ARGS[approval_id] = {
        "request_id": request_id,
        "user_id": user_id,
        "tool_name": tool_name,
        "args": redacted_args,
    }
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            INSERT INTO approvals (
                approval_id, request_id, user_id, tool_name, tool_args_redacted,
                tool_args_encrypted_or_internal_ref, risk_level, reason, status,
                created_at, resolved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL)
            """,
            (
                approval_id,
                request_id,
                user_id,
                tool_name,
                json.dumps(redacted_args, ensure_ascii=True, sort_keys=True),
                internal_ref,
                risk_level,
                reason,
                now_iso(),
            ),
        )
        con.commit()
    return {
        "approval_id": approval_id,
        "tool_name": tool_name,
        "tool_args_redacted": redacted_args,
        "risk_level": risk_level,
        "reason": reason,
        "status": "pending",
    }


def handle_tool_call(data: dict[str, Any], request_id: str | None = None) -> dict[str, Any]:
    request_id = request_id or str(uuid.uuid4())
    user_id = str(data.get("user_id", "demo_user"))
    tool_name = str(data.get("tool_name", ""))
    args = data.get("args") or {}
    if not isinstance(args, dict):
        args = {"value": args}

    redacted_args = redact_value(args)
    decision = policy_decision(tool_name, args)
    security_rag = security_rag_context(
        text=json.dumps(redacted_args, ensure_ascii=True, sort_keys=True),
        status={"block": "blocked", "require_approval": "review", "allow": "allowed"}.get(decision["decision"], decision["decision"]),
        reason=decision["reason"],
        tool_name=tool_name,
        args=args,
    )

    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="tool_call_requested",
        tool_name=tool_name,
        input_redacted=redacted_args,
        output_redacted=decision,
        decision=decision["decision"],
        risk_level=decision["risk_level"],
        reason=decision["reason"],
    )
    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="security_rag_retrieved",
        tool_name=tool_name,
        input_redacted=security_rag["query_redacted"],
        output_redacted=security_rag,
        decision="allow",
        risk_level="low",
        reason="SecurityRAG retrieved local evidence for the policy decision",
    )

    if decision["decision"] == "block":
        log_event(
            request_id=request_id,
            user_id=user_id,
            event_type="tool_call_blocked",
            tool_name=tool_name,
            input_redacted=redacted_args,
            decision="block",
            risk_level=decision["risk_level"],
            reason=decision["reason"],
        )
        if tool_name == "http_request":
            log_event(
                request_id=request_id,
                user_id=user_id,
                event_type="network_request_blocked",
                tool_name=tool_name,
                input_redacted=redacted_args,
                decision="block",
                risk_level=decision["risk_level"],
                reason=decision["reason"],
            )
        if decision.get("detections", {}).get("secret_types"):
            log_event(
                request_id=request_id,
                user_id=user_id,
                event_type="secret_detected",
                tool_name=tool_name,
                input_redacted=redacted_args,
                decision="block",
                risk_level="critical",
                reason="Secret pattern matched and raw value was redacted",
            )
        return {
            "status": "blocked",
            "request_id": request_id,
            "tool_name": tool_name,
            "risk_level": decision["risk_level"],
            "reason": decision["reason"],
            "tool_args_redacted": redacted_args,
            "policy": decision,
            "security_rag": security_rag,
        }

    if decision["decision"] == "require_approval":
        approval = create_approval(
            request_id=request_id,
            user_id=user_id,
            tool_name=tool_name,
            args=args,
            risk_level=decision["risk_level"],
            reason=decision["reason"],
        )
        log_event(
            request_id=request_id,
            user_id=user_id,
            event_type="approval_created",
            tool_name=tool_name,
            input_redacted=approval["tool_args_redacted"],
            output_redacted=approval,
            decision="require_approval",
            risk_level=decision["risk_level"],
            reason=decision["reason"],
        )
        return {
            "status": "pending_approval",
            "request_id": request_id,
            "tool_name": tool_name,
            "risk_level": decision["risk_level"],
            "reason": decision["reason"],
            "approval": approval,
            "tool_args_redacted": redacted_args,
            "policy": decision,
            "security_rag": security_rag,
        }

    execution = execute_tool(tool_name, redacted_args, request_id, user_id)
    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="tool_call_allowed",
        tool_name=tool_name,
        input_redacted=redacted_args,
        output_redacted=execution,
        decision="allow",
        risk_level=decision["risk_level"],
        reason=decision["reason"],
    )
    return {
        "status": "allowed",
        "request_id": request_id,
        "tool_name": tool_name,
        "risk_level": decision["risk_level"],
        "reason": decision["reason"],
        "tool_args_redacted": redacted_args,
        "execution": execution,
        "policy": decision,
        "security_rag": security_rag,
    }


def find_first_token(vault_entries: list[dict[str, str]], kind: str) -> str | None:
    for entry in vault_entries:
        if entry["type"] == kind:
            return entry["token"]
    return None


def extract_json_object(text: str) -> dict[str, Any] | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start : end + 1])
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def validate_tool_plan(plan: Any) -> list[dict[str, Any]]:
    if not isinstance(plan, dict):
        return []
    actions = plan.get("actions", [])
    if not isinstance(actions, list):
        return []

    allowed_tools = set(POLICY["tools"].keys())
    validated: list[dict[str, Any]] = []
    for action in actions[:5]:
        if not isinstance(action, dict):
            continue
        tool_name = str(action.get("tool_name", ""))
        args = action.get("args", {})
        if tool_name not in allowed_tools or not isinstance(args, dict):
            continue
        validated.append({"tool_name": tool_name, "args": args})
    return validated


def fallback_tool_plan(prompt: str, safe_agent_context: str, public_vault: list[dict[str, str]]) -> dict[str, Any]:
    lower_prompt = prompt.lower()
    wants_automation = any(
        word in lower_prompt
        for word in ["schedule", "appointment", "book", "email", "send", "calendar", "meet", "invite"]
    )
    if not wants_automation:
        return {"runtime": "simulated_agent", "summary": "No automation requested.", "actions": []}

    email_token = find_first_token(public_vault, "email") or "PII_EMAIL_BACKEND_REF"
    is_frido_meeting = "frido" in lower_prompt and "friday" in lower_prompt
    meeting_title = "Meeting with Frido" if is_frido_meeting else "Protected personal-data automation"
    meeting_time = "Friday 11:00 AM" if is_frido_meeting else "Requested time from tokenized context"
    email_subject = "Meeting confirmed for Friday at 11:00 AM" if is_frido_meeting else "Confirmation prepared by safety overlay"
    email_body = (
        "Confirmed for Friday at 11:00 AM. The calendar invite has been prepared. "
        "The safety overlay used backend vault references for private contact details."
        if is_frido_meeting
        else (
            "The requested automation is ready. Personal details remain behind "
            f"vault references such as {email_token}. No raw personal data is in this message."
        )
    )
    return {
        "runtime": "simulated_agent",
        "summary": (
            "Deterministic fallback created a Frido calendar invite and an approval-gated Gmail reply."
            if is_frido_meeting
            else "Deterministic fallback created a calendar action and an approval-gated email action."
        ),
        "actions": [
            {
                "tool_name": "create_calendar_event",
                "args": {
                    "title": meeting_title,
                    "time": meeting_time,
                    "attendee_ref": email_token,
                    "notes": "Agent received tokenized context only; raw contact details stay in the backend vault.",
                    "source_context": safe_agent_context[:600],
                },
            },
            {
                "tool_name": "send_email",
                "args": {
                    "to": email_token,
                    "subject": email_subject,
                    "body": email_body,
                },
            },
        ],
    }


def real_llm_tool_plan(safe_agent_context: str, public_vault: list[dict[str, str]]) -> dict[str, Any]:
    api_base = env_text("LLM_API_BASE", "http://127.0.0.1:8000/v1").rstrip("/")
    model = env_text("LLM_MODEL", "qwen2.5-32b-instruct")
    api_key = env_text("LLM_API_KEY") or env_text("OPENAI_API_KEY")
    public_tokens = [
        {"type": entry["type"], "token": entry["token"], "agent_visibility": entry["agent_visibility"]}
        for entry in public_vault
    ]
    system_prompt = (
        "You are a privacy-preserving agent. You only see tokenized personal data. "
        "Never ask for or invent raw PII. Return only JSON with this schema: "
        "{\"summary\": string, \"actions\": [{\"tool_name\": string, \"args\": object}]}. "
        "Allowed tools: create_calendar_event, send_email, http_request, read_file. "
        "Use vault tokens exactly as provided for recipients or attendees."
    )
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "agent_context": safe_agent_context,
                        "vault_tokens_available": public_tokens,
                    },
                    ensure_ascii=True,
                ),
            },
        ],
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urlrequest.Request(
        api_base + "/chat/completions",
        data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=int(env_text("LLM_TIMEOUT_SECONDS", "30"))) as resp:
            response = json.loads(resp.read().decode("utf-8"))
        content = response["choices"][0]["message"]["content"]
        parsed = extract_json_object(content)
        actions = validate_tool_plan(parsed)
        LAST_INTEGRATION_ERRORS.pop("llm", None)
        return {
            "runtime": "real_llm_openai_compatible",
            "model": model,
            "summary": parsed.get("summary", "Real LLM returned a tool plan.") if parsed else "",
            "actions": actions,
            "llm_output_redacted": redact_value(content[:1200]),
        }
    except Exception as exc:  # noqa: BLE001
        LAST_INTEGRATION_ERRORS["llm"] = f"{exc.__class__.__name__}: {exc}"
        return {
            "runtime": "real_llm_failed",
            "summary": "Real LLM call failed; falling back to deterministic simulated agent.",
            "actions": [],
            "error": LAST_INTEGRATION_ERRORS["llm"],
        }


def agent_tool_plan(prompt: str, safe_agent_context: str, public_vault: list[dict[str, str]]) -> dict[str, Any]:
    if real_llm_enabled():
        llm_plan = real_llm_tool_plan(safe_agent_context, public_vault)
        if llm_plan.get("actions"):
            return llm_plan
    return fallback_tool_plan(prompt, safe_agent_context, public_vault)


def handle_agent_run(data: dict[str, Any]) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    user_id = str(data.get("user_id", "demo_user"))
    prompt = str(data.get("prompt", ""))
    input_redacted = redact_value(prompt)
    guardrail = guardrail_check(prompt)
    initial_status = "allowed" if guardrail["allowed"] else "blocked"
    security_rag = security_rag_context(
        text=input_redacted,
        status=initial_status,
        reason=guardrail["reason"],
    )

    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="input_checked",
        input_redacted=input_redacted,
        output_redacted=guardrail,
        decision="allow" if guardrail["allowed"] else "block",
        risk_level=guardrail["risk_level"],
        reason=guardrail["reason"],
    )
    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="security_rag_retrieved",
        input_redacted=security_rag["query_redacted"],
        output_redacted=security_rag,
        decision="allow",
        risk_level="low",
        reason="SecurityRAG retrieved local evidence after rule checks",
    )

    if not guardrail["allowed"]:
        log_event(
            request_id=request_id,
            user_id=user_id,
            event_type="prompt_injection_detected",
            input_redacted=input_redacted,
            output_redacted={"matched_rules": guardrail["matched_rules"]},
            decision="block",
            risk_level="high",
            reason=guardrail["reason"],
        )
        return {
            "status": "blocked",
            "request_id": request_id,
            "risk_level": "high",
            "reason": guardrail["reason"],
            "matched_rules": guardrail["matched_rules"],
            "input_redacted": input_redacted,
            "security_rag": security_rag,
        }

    tokenized_context, public_vault, private_vault = tokenize_pii(prompt)
    safe_agent_context, secret_types = redact_secrets(tokenized_context)
    vault_store = store_vault_refs(request_id, private_vault)

    if secret_types:
        log_event(
            request_id=request_id,
            user_id=user_id,
            event_type="secret_detected",
            input_redacted=input_redacted,
            output_redacted={"secret_types": secret_types},
            decision="allow",
            risk_level="medium",
            reason="Secret was removed before the agent context",
        )

    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="agent_context_minimized",
        input_redacted=input_redacted,
        output_redacted=safe_agent_context,
        decision="allow",
        risk_level="low",
        reason="PII replaced with opaque vault tokens before agent runtime",
    )

    plan = agent_tool_plan(prompt, safe_agent_context, public_vault)
    log_event(
        request_id=request_id,
        user_id=user_id,
        event_type="agent_tool_plan_created",
        input_redacted=safe_agent_context,
        output_redacted=plan,
        decision="allow",
        risk_level="low",
        reason=f"Agent runtime: {plan.get('runtime', 'unknown')}",
    )

    actions: list[dict[str, Any]] = []
    for tool_call in validate_tool_plan(plan):
        actions.append(
            handle_tool_call(
                {"user_id": user_id, "tool_name": tool_call["tool_name"], "args": tool_call["args"]},
                request_id=request_id,
            )
        )

    status = "completed"
    if any(action["status"] == "blocked" for action in actions):
        status = "blocked"
    elif any(action["status"] == "pending_approval" for action in actions):
        status = "pending_approval"
    security_rag["analyst_verdict"] = security_analyst_verdict(status, "Agent processed minimized context; high-risk actions are gated", security_rag["evidence"])

    return {
        "status": status,
        "request_id": request_id,
        "reason": "Agent processed minimized context; high-risk actions are gated",
        "input_redacted": input_redacted,
        "agent_context": safe_agent_context,
        "vault": public_vault,
        "vault_store": vault_store,
        "secrets_removed": secret_types,
        "agent_runtime": plan.get("runtime", "unknown"),
        "agent_model": plan.get("model", ""),
        "agent_summary": plan.get("summary", ""),
        "security_rag": security_rag,
        "agent_tool_plan": validate_tool_plan(plan),
        "agent_plan": [
            "Treat retrieved/user content as data, not instruction",
            "Use tokenized context for reasoning",
            "Ask policy engine before every tool call",
            "Queue high-risk outbound actions for approval",
        ],
        "actions": actions,
    }


def approval_action(approval_id: str, action: str) -> tuple[int, dict[str, Any]]:
    rows = db_rows("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
    if not rows:
        return 404, {"error": "approval not found"}
    approval = rows[0]
    if approval["status"] != "pending":
        return 409, {"error": f"approval already {approval['status']}"}

    if action == "deny":
        with sqlite3.connect(DB_PATH) as con:
            con.execute(
                "UPDATE approvals SET status = 'denied', resolved_at = ? WHERE approval_id = ?",
                (now_iso(), approval_id),
            )
            con.commit()
        log_event(
            request_id=approval["request_id"],
            user_id=approval["user_id"],
            event_type="approval_denied",
            tool_name=approval["tool_name"],
            input_redacted=json.loads(approval["tool_args_redacted"]),
            decision="deny",
            risk_level=approval["risk_level"],
            reason="Human denied the queued action",
        )
        return 200, {"status": "denied", "approval_id": approval_id}

    pending = PENDING_INTERNAL_ARGS.get(approval_id)
    args = pending["args"] if pending else json.loads(approval["tool_args_redacted"])
    execution = execute_tool(approval["tool_name"], args, approval["request_id"], approval["user_id"])
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "UPDATE approvals SET status = 'approved', resolved_at = ? WHERE approval_id = ?",
            (now_iso(), approval_id),
        )
        con.commit()
    log_event(
        request_id=approval["request_id"],
        user_id=approval["user_id"],
        event_type="approval_approved",
        tool_name=approval["tool_name"],
        input_redacted=args,
        output_redacted=execution,
        decision="allow",
        risk_level=approval["risk_level"],
        reason="Human approved the queued action",
    )
    return 200, {"status": "approved", "approval_id": approval_id, "execution": execution}


class DemoHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {"value": data}
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "zero-trust-safety-demo",
                    "time": now_iso(),
                    "integrations": integration_status(),
                },
            )
            return
        if path == "/audit/logs":
            rows = db_rows("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 80")
            self._send_json(200, rows)
            return
        if path == "/approvals":
            rows = db_rows("SELECT * FROM approvals ORDER BY created_at DESC LIMIT 50")
            for row in rows:
                row["tool_args_redacted"] = json.loads(row["tool_args_redacted"])
            self._send_json(200, rows)
            return
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/agent/run":
                self._send_json(200, handle_agent_run(self._read_json()))
                return
            if path == "/tool/call":
                self._send_json(200, handle_tool_call(self._read_json()))
                return
            approval_match = re.match(r"^/approvals/([^/]+)/(approve|deny)$", path)
            if approval_match:
                status, payload = approval_action(approval_match.group(1), approval_match.group(2))
                self._send_json(status, payload)
                return
            self._send_json(404, {"error": "not found"})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - demo server should return visible errors.
            self._send_json(500, {"error": str(exc)})

    def _serve_static(self, path: str) -> None:
        if path == "/":
            path = "/index.html"
        requested = (ROOT / path.lstrip("/")).resolve()
        if ROOT not in requested.parents and requested != ROOT:
            self.send_error(403)
            return
        if not requested.exists() or not requested.is_file():
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(str(requested))[0] or "application/octet-stream"
        body = requested.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{now_iso()}] {self.address_string()} {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the zero-trust safety overlay demo.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    args = parser.parse_args()

    init_db()
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"Zero-Trust Safety Overlay demo running at http://{args.host}:{args.port}")
    print(f"Audit database: {DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
