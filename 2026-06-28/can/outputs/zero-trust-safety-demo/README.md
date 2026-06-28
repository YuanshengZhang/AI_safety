# Zero-Trust Safety Overlay Demo

A zero-trust safety overlay for personal-data agents that combines guardrails, policy-controlled tools, sandboxed execution, secrets isolation, network monitoring, human approval, and audit logs.

This demo is based on the `Zero-Trust Safety Overlay` build spec. It runs in dependency-free fallback mode by default, includes a local SecurityRAG evidence layer, and can opt into real integrations for an OpenAI-compatible LLM, Docker, OpenBao, and NeMo Guardrails.

## Run

```bash
python3 server.py --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

For a step-by-step handout to share with others, see `USER_GUIDE.md`.

## What It Demonstrates

- A synthetic Gmail inbox acts as the personal-data source.
- The main demo email is: Sarah gets an email from Frido to meet Friday at 11:00 AM.
- The agent proposes a calendar event with Frido invited, checks availability, and waits for calendar-owner approval before the mock invitation is sent.
- PII is detected and replaced with opaque vault tokens before the agent or real LLM sees it.
- Secret-like values are removed before they enter agent context or logs.
- SecurityRAG retrieves local evidence from curated security knowledge after rule checks and before the agent/tool decision is explained.
- The analyst explanation can cite only retrieved evidence; if no evidence is found, the verdict falls back to rule checks.
- Every proposed tool call is checked by the policy engine and the SafeScheduler Tool Policy Service before execution.
- `policies/tool-policy.yaml` is included as the policy artifact for allowlists, hard-denies, schema checks, attendee provenance, raw-email boundary checks, and approval behavior.
- Calendar writes require owner approval. `send_email` is hard-denied in the SafeScheduler path; approved calendar events send the mock invitation.
- Dangerous shell commands are blocked before sandboxing.
- Blocked, allowed, and approval decisions are written to SQLite audit logs.
- Outbound HTTP requests are checked by an allowlist, blocklist, raw-IP rule, body-size rule, and secret-exfiltration rule.

## SecurityRAG

SecurityRAG is implemented as a local curated knowledge layer for the demo. It does not override rule checks. It builds a short redacted query from the subject, tool name, and rule flags, then retrieves matching evidence from local entries such as MITRE ATT&CK-style techniques, CISA-style phishing guidance, OWASP LLM risks, enterprise policy, email security notes, prompt-injection patterns, phishing examples, and historical incidents.

The UI shows the redacted query, rule flags, evidence cards, and analyst verdict under **SecurityRAG evidence**.

## SafeScheduler Tool Policy

The Tool Policy Service sits after the planner and before execution. It validates the planner's structured JSON proposal against `policies/tool-policy.yaml`.

For calendar events it checks:

- tool is allowlisted
- required fields are present, including `start_datetime_iso`
- attendees have trusted provenance: `authenticated_sender` or `trusted_user_input`
- `requires_user_confirmation` is true
- raw email was not passed into tool arguments
- the requested slot is available on the mock calendar

If all checks pass, the action becomes a Human Gate approval. If the owner approves, the mock calendar event is created and the invitation is marked sent.

## API Endpoints

The local server exposes the same endpoint shape from the brief:

```text
POST /agent/run
POST /tool/call
GET  /audit/logs
GET  /approvals
POST /approvals/{approval_id}/approve
POST /approvals/{approval_id}/deny
GET  /health
```

## Demo Scenarios

The UI includes a fake Gmail interface with **Inbox**, **Drafts**, **Sent**, and **Spam** folders. It includes targeted messages for:

- clean Frido scheduling: available Friday 11:00 AM slot, valid provenance, pending owner approval
- busy calendar slot: valid request denied because Friday 2:00 PM conflicts with an existing event
- ambiguous date: denied because `start_datetime_iso` is missing
- unauthorized attendee injection: denied because an attendee came from email body text
- raw email boundary leak: denied because raw email reached tool arguments
- hard-denied `send_email`: blocked by SafeScheduler
- Sunday SSN request: prompt-injection email that triggers SecurityRAG evidence and is blocked
- webhook secret exfiltration, unknown vendor upload, sandbox honeypot, and safe allowlisted lookup

The audit log shows all recent demo runs in the SQLite ledger, grouped by request. It is not limited to the currently selected email.

## Real-Stack Mode

The backend supports optional real integrations through environment variables. If a real integration is enabled but unavailable, the server keeps running and reports the failure in `GET /health`.

### Real LLM

Use any OpenAI-compatible chat-completions endpoint, including vLLM, Ollama's OpenAI bridge, LM Studio, or a hosted gateway.

Example for Qwen with vLLM:

```bash
export USE_REAL_LLM=1
export LLM_API_BASE=http://127.0.0.1:8000/v1
export LLM_MODEL=Qwen/Qwen2.5-32B-Instruct
python3 server.py --port 8765
```

The model receives only `agent_context`, which contains vault tokens such as `PII_EMAIL_...`, not raw personal data.

### Real OpenBao

Start dev OpenBao:

```bash
docker compose -f docker-compose.real.yml up openbao
```

Start the demo with OpenBao enabled:

```bash
export USE_OPENBAO=1
export OPENBAO_ADDR=http://127.0.0.1:8200
export OPENBAO_TOKEN=root
python3 server.py --port 8765
```

Token mappings are written to KV v2 under `secret/data/zero-trust-demo/session/<request_id>`. The UI still shows only masked vault metadata.

### Real Docker Sandbox

```bash
export USE_DOCKER=1
python3 server.py --port 8765
```

Approved shell commands run through Docker with `--network none`, memory/CPU limits, a temporary workspace mount, and a timeout. Dangerous commands are still blocked before Docker.

To test it in the UI:

1. Start Docker Desktop.
2. Run the backend with `USE_DOCKER=1`.
3. Select **Run honeypot attachment scan** and click **Run selected email**.
4. Approve the queued shell action under **Human gate / Approvals**.
5. The decision payload should show `sandbox: "docker"` and output like `honeypot attachment scan complete`.

The **Attachment cleanup instructions** email should still be blocked before Docker starts.

### Real NeMo Guardrails

Install and configure NeMo Guardrails in your Python environment, then run:

```bash
export USE_NEMO=1
export NEMO_CONFIG_PATH=./nemo_guardrails_config
python3 server.py --port 8765
```

The included `nemo_guardrails_config/config.yml` is a minimal self-check input configuration. You may need to adapt the model provider settings to your NeMo installation.

To test it in the UI:

1. Install `nemoguardrails` in the Python environment used to run `server.py`.
2. Run the backend with `USE_NEMO=1`.
3. Click **Sunday records request**.
4. The decision payload should include `engine: "nemo_guardrails"` if NeMo handled the check.

If NeMo is enabled but unavailable, the payload and `/health` will show a `rule_based_fallback` engine and a `fallback_reason`.

## Security Model

1. The LLM does not own broad permissions.
   The agent or real LLM proposes actions, but the backend policy layer decides whether tools execute.

2. Secrets never enter the LLM context.
   Secret-like strings are redacted before agent context and audit logging.

3. Retrieved content is data, not instruction.
   Prompt-injection phrases are detected before the agent runtime.

4. High-risk actions require approval.
   Email, write, delete, and shell actions are gated.

5. Everything is logged.
   Decisions are written to `demo_audit.sqlite3`.

6. Unknown risky behavior is default denied or approval-gated.
   Unknown tools are blocked, unknown domains require approval, blocklisted domains are blocked.

## Project Files

```text
server.py                       standard-library safety gateway and API
index.html                      browser demo
styles.css                      operations-dashboard styling
app.js                          scenario runner and live UI updates
policies/default_policy.yaml    policy shape from the source spec
.env.real.example               optional real-stack environment template
docker-compose.real.yml         OpenBao dev service
nemo_guardrails_config/         minimal NeMo Guardrails config
demo_audit.sqlite3              created at runtime
workspace/                      safe file-tool workspace, created at runtime
```

## Notes For A Full Build

This demo keeps the first version simple and runnable. A production-grade version should replace the standard-library server with FastAPI, encrypt approval payload references, use a hardened PII scanner, add real email/calendar connectors, and apply stronger authentication, authorization, and audit retention controls.
