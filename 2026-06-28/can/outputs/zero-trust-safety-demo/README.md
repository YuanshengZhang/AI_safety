# Zero-Trust Safety Overlay Demo

A zero-trust safety overlay for personal-data agents that combines guardrails, policy-controlled tools, sandboxed execution, secrets isolation, network monitoring, human approval, and audit logs.

This demo is based on the `Zero-Trust Safety Overlay` build spec. It runs in dependency-free fallback mode by default, and can opt into real integrations for an OpenAI-compatible LLM, Docker, OpenBao, and NeMo Guardrails.

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
- The agent creates a calendar event with Frido invited and drafts a confirmation email, while private contact data remains tokenized.
- PII is detected and replaced with opaque vault tokens before the agent or real LLM sees it.
- Secret-like values are removed before they enter agent context or logs.
- Every proposed tool call is checked by the policy engine before execution.
- High-risk actions, such as `send_email`, are queued for human approval.
- Dangerous shell commands are blocked before sandboxing.
- Blocked, allowed, and approval decisions are written to SQLite audit logs.
- Outbound HTTP requests are checked by an allowlist, blocklist, raw-IP rule, body-size rule, and secret-exfiltration rule.

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

The UI includes a fake Gmail interface with **Inbox**, **Drafts**, **Sent**, and **Spam** folders. It includes seven runnable/source messages:

- Frido appointment: creates a Friday 11:00 AM calendar event and queues the Gmail reply for human approval.
- Sunday SSN request: prompt-injection email asks the agent to share Sarah's SSN; blocked before the LLM.
- Webhook debug dump: tries to POST a fake API key and SSN to `webhook.site`; blocked by policy.
- Vendor export: unknown outbound domain and large upload; queued for human review.
- Attachment cleanup: tries to read `~/.ssh/id_rsa`; blocked before sandboxing.
- Honeypot attachment scan: safe shell command requires approval, then runs in Docker with no network.
- NeMo docs lookup: safe allowlisted GitHub request; allowed.

The primary Frido path processes realistic personal data, shows the tokenized context given to the agent, creates a calendar action, and queues the Gmail action for approval.

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
3. Click **Prompt injection**.
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
