# Requirements: Multi-Step Security Agent

> Single source of truth for requirements.

## Exercise: Build a Multi-Step Security Agent

### Scenario

You're given a simplified simulated environment where a security agent must investigate a potential security incident. Build an autonomous agent that:

1. **Receives an alert** (provided as a JSON object describing a suspicious event — see sample alerts below)
2. **Plans an investigation** — the agent must reason about what steps to take (**not hardcoded**). If the alert details change (e.g., a different event type or asset), the agent should adapt its investigation plan **without code changes**.
3. **Uses tools** — implement at least 3 mock tools the agent can call (e.g., `lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`). The tools should return realistic stubbed data.
4. **Chains reasoning across steps** — the agent should **use output from one tool to decide what to do next**
5. **Produces a structured verdict** — a summary with severity rating, findings, recommended actions, and confidence level
6. **Includes a human-in-the-loop gate** — before any "high-risk" recommended action (e.g., blocking a user), the agent must pause and request approval

### Sample Alert 1: Anomalous API Activity (Data Exfiltration Pattern)

```json
{
  "alert_id": "ALT-2026-04-7821",
  "timestamp": "2026-04-09T03:12:44Z",
  "source": "api-gateway",
  "severity_hint": "high",
  "event_type": "anomalous_api_activity",
  "description": "Service account 'svc-deploy-prod' made 847 API calls to /admin/users/export in a 3-minute window. Normal baseline is <10 calls/hour. Source IP 10.200.3.47 does not match known CI/CD runner IPs.",
  "entities": {
    "service_account": "svc-deploy-prod",
    "source_ip": "10.200.3.47",
    "target_endpoint": "/admin/users/export",
    "asset": "user-management-api",
    "environment": "production"
  },
  "context": {
    "calls_in_window": 847,
    "window_minutes": 3,
    "baseline_calls_per_hour": 8,
    "auth_method": "api_key",
    "geo_location": "US-East"
  }
}
```

### Sample Alert 2: Privilege Escalation Attempt

```json
{
  "alert_id": "ALT-2026-04-7835",
  "timestamp": "2026-04-09T11:47:02Z",
  "source": "cloud-trail",
  "severity_hint": "medium",
  "event_type": "privilege_escalation_attempt",
  "description": "IAM user 'dev-intern-jpark' attached AdministratorAccess policy to their own role. No change request or approval ticket found. Action originated from a new device fingerprint not seen before for this user.",
  "entities": {
    "iam_user": "dev-intern-jpark",
    "source_ip": "203.0.113.22",
    "target_resource": "arn:aws:iam::123456789012:role/dev-intern-jpark-role",
    "policy_attached": "arn:aws:iam::aws:policy/AdministratorAccess",
    "environment": "staging"
  },
  "context": {
    "user_tenure_days": 12,
    "previous_max_privilege": "ReadOnlyAccess",
    "device_fingerprint": "new_unknown",
    "change_ticket_found": false,
    "mfa_used": false
  }
}
```

Your agent must handle **both** alerts. The first tests data exfiltration detection (high-volume calls to an export endpoint from an unexpected IP). The second tests privilege escalation reasoning (new user, no approval, no MFA, unknown device).

## Requirements

- **Python 3.11+**, using any agentic framework (LangGraph, LangChain, CrewAI, or raw code — your choice)
- Must work with **at least one real LLM API call** (OpenAI, Anthropic, or Google — candidate can use their own free-tier key)
- Include a `README.md` with setup instructions, architecture decisions, and trade-offs
- Include a `requirements.txt` or `pyproject.toml` for dependencies
- Include a `.env.example` file showing which environment variables are needed (e.g., `OPENAI_API_KEY=your-key-here`)
- Include at least **3 unit or integration tests** covering: a tool call, the approval gate, and an edge case (e.g., a tool returning an error)
- The agent must have a **configurable maximum step count** (default: 15) and gracefully terminate if exceeded
- A `Dockerfile` or `Makefile` is welcome but not required
- **Your repo must not contain any API keys or secrets**

## Evaluation Criteria

| Area | Weight | What we look for |
|---|---|---|
| **Agent architecture** | 30% | Clean separation of planning, tool execution, and reasoning. Not a linear script. |
| **Reliability & error handling** | 25% | Retries, timeouts, graceful tool failures, guardrails against runaway loops |
| **Prompt / reasoning quality** | 20% | Effective use of chain-of-thought or ReAct patterns; the agent makes sensible decisions |
| **Code quality** | 15% | Readable, well-structured, testable code |
| **Documentation & trade-offs** | 10% | Clear README explaining what you built, why, and what you'd do differently with more time |

## Bonus (not required)

- Add a second specialized agent (e.g., a "Threat Intel Agent") that collaborates with the primary agent
- Implement a simple memory/context layer so the agent is aware of prior findings
- Show how you'd swap in a local open-source model (DeepSeek/Llama) without changing agent logic

## Delivery

- The agent should be runnable with a **single command** (e.g., `python run.py` or `make run`)
