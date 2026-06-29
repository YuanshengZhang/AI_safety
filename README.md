# AI Guardian SafeScheduler

A local AI safety hackathon demo showing how an agent can process personal data and propose an automation action without directly receiving broad access to Gmail, Calendar, secrets, or raw private data.

The demo story: Sarah receives an email from Frido asking to meet Friday at 11:00 AM. SafeScheduler reads only that email, minimizes personal data, checks the request for security risks, lets the agent propose one calendar event, enforces tool policy, waits for human approval, and writes an audit trail.

## Quick Start

```bash
git clone https://github.com/YuanshengZhang/AI_safety.git
cd AI_safety/2026-06-28/can/outputs/zero-trust-safety-demo
python3 server.py --port 8765
```

Open:

```text
http://127.0.0.1:8765/
```

Default mode is local and free. It does not require Docker, OpenAI API, NeMo Guardrails, OpenBao, or real Gmail/Google Calendar credentials.

## What It Demonstrates

```text
Demo Gmail email
  -> Retrieval + redaction gateway
  -> NeMo / prompt safety checks
  -> SecurityRAG evidence
  -> LLM-style agent planner
  -> Tool Policy Service
  -> Human approval gate
  -> Mock Calendar execution
  -> Audit log
```

The key promise is zero-trust tool use: the agent can propose an action, but policy decides whether tools execute.

## What Is Real vs Mocked

Real demo components:

- local web app and Python backend
- personal-data minimization and vault-token references
- rule-based safety checks and SecurityRAG evidence layer
- Tool Policy Service using `policies/tool-policy.yaml`
- human approval gate
- SQLite audit ledger
- optional Docker, OpenBao, NeMo, and OpenAI-compatible LLM hooks

Mocked for safe presentation:

- Gmail inbox
- Google Calendar
- calendar invitation sending
- production identity/authentication

In one sentence: this is a runnable prototype of a real security architecture, with Gmail and Calendar mocked so the risks can be shown safely during a hackathon.

## Demo Scenarios

Use the Gmail-style inbox in the web UI and click **Run selected email**.

Recommended one-minute presentation flow:

1. Select **Meet Friday at 11am?**
2. Show that the agent only sees minimized context, not raw personal data.
3. Show SecurityRAG evidence and the tool-policy decision.
4. Approve the pending calendar event in **Human gate / Approvals**.
5. Point to the audit log grouped by workflow step.

Risk examples included in the demo:

- **Sunday records request**: prompt injection plus SSN exfiltration attempt
- **Webhook debug dump**: tries to send internal debug data to an outside webhook
- **Planner leaked raw email**: blocks raw email body entering tool arguments
- **Send the schedule by email**: hard-denies `send_email`
- **Meet Friday and add Mallory**: blocks unauthorized attendee injection
- **Meet Friday at 2pm?**: denies because the calendar slot is busy
- **Run honeypot attachment scan**: approval-gated shell action, with Docker sandbox if enabled

## Tool Policy

The tool policy layer controls what SafeScheduler is allowed to do with Gmail and Calendar:

- read one email at a time
- propose one calendar event based on facts in that email
- require owner approval before creating anything
- never send emails
- never add people outside the existing email thread without confirmation
- block raw-email leaks, secret dumps, unsafe tools, and external webhook exfiltration

The policy file is here:

```text
2026-06-28/can/outputs/zero-trust-safety-demo/policies/tool-policy.yaml
```

## SecurityRAG

SecurityRAG is a local knowledge layer. It retrieves trusted evidence before the analyst verdict is shown. It is not a chatbot and it does not override hard rules.

It uses curated local knowledge about:

- MITRE ATT&CK-style phishing techniques
- CISA-style email security guidance
- OWASP LLM risks such as prompt injection and data leakage
- enterprise policy
- prompt-injection examples
- historical incident examples

## Optional Real-Stack Mode

The demo can also connect to real local infrastructure:

- Docker sandbox: `USE_DOCKER=1`
- OpenBao dev vault: `USE_OPENBAO=1`
- NeMo Guardrails: `USE_NEMO=1`
- OpenAI-compatible LLM endpoint: `USE_REAL_LLM=1`

See the detailed guide for setup commands:

```text
2026-06-28/can/outputs/zero-trust-safety-demo/USER_GUIDE.md
```

## Project Layout

```text
2026-06-28/can/outputs/zero-trust-safety-demo/
  server.py                 local backend and safety pipeline
  index.html                browser UI
  app.js                    demo interactions
  styles.css                presentation UI
  policies/tool-policy.yaml SafeScheduler policy artifact
  USER_GUIDE.md             detailed handout
```

## Production Notes

This is not production-ready. To turn it into a real product, the next steps would be real Google OAuth, real Gmail/Calendar APIs, stronger PII detection, authenticated users, hardened sandboxing, production secrets management, stronger audit retention, and security review.
