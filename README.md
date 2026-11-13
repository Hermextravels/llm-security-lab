# LLM Security Lab

[![Python tests](https://github.com/Hermextravels/llm-security-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/Hermextravels/llm-security-lab/actions/workflows/tests.yml)

**A Python security engineering portfolio project** exploring prompt injection, excessive agency, broken authorization, secure LLM tool execution, static analysis, vulnerability triage, and adversarial evaluation.

> **Educational security research.** All identities, orders, approvals, refunds, and attack cases are fictional. Intentionally vulnerable functions are included to demonstrate failures and compare mitigations. No real financial operations are performed.

## Highlights

- **Authorization:** demonstrates cross-user document access and owner-aware retrieval controls.
- **Agent and tool security:** compares intentionally vulnerable refund execution with server-side ownership, argument validation, and trusted approval checks.
- **Prompt injection:** tests attacker-controlled support-ticket text and unauthorized tool requests.
- **Attack evaluation:** separates *unauthorized tool requests* from *unauthorized actions actually executed*; includes benign-task checks.
- **Static analysis:** educational AST-based source/sink scanning and limited interprocedural taint tracking.
- **Vulnerability triage:** classifies findings as confirmed, false positive, or unresolved based on structured synthetic evidence.
- **Statistics and coverage:** calculates zero-failure one-sided binomial confidence bounds and reports coverage against a defined attack taxonomy.
- **Real-model interface:** an OpenAI-compatible Chat Completions tool-calling evaluation harness, with offline mocked tests. Live API measurements are **not** claimed.

## Architecture

```text
Synthetic attack cases / benign requests
                  |
                  v
       Simulated agent or API model
                  |
                  v
        Proposed structured tool call
                  |
          +-------+-------+
          |               |
          v               v
  Vulnerable executor   Secure executor
          |               |
          +-------+-------+
                  |
                  v
       Side-effect verification
                  |
                  v
     Evaluation metrics and reports
```

## Run locally

Requires Python 3.10+ and pytest. The repository was verified with **114 passing tests** on the uploaded source snapshot.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Run the offline evaluation modules:

```bash
python -m app.evaluator
python -m app.tool_call_evaluator
python -m app.vulnerability_triage
python -m app.red_team_evaluator
python -m app.source_sink_scanner app/tool_executor.py
```

Inspect the generated JSON reports in `reports/`.

## Project layout

| Path | Purpose |
| --- | --- |
| `app/documents.py`, `app/agent_tools.py` | Authorization and excessive-agency examples |
| `app/prompt_injection.py`, `app/evaluator.py` | Prompt-injection simulation and baseline evaluation |
| `app/tool_executor.py`, `app/tool_call_evaluator.py` | Structured tool calls and backend authorization |
| `app/source_sink_scanner.py`, `app/taint_analyzer.py` | Educational static analysis and taint prototypes |
| `app/vulnerability_triage.py` | Evidence-based finding classification |
| `app/red_team_evaluator.py` | Offline adversarial evaluation and outcome separation |
| `app/real_llm_evaluator.py` | Optional live tool-call evaluation via compatible API |
| `app/statistical_evaluator.py` | Confidence-bound and category-coverage helpers |
| `datasets/` | Fictional attack and evaluation cases |
| `tests/` | Pytest regression suite |
| `reports/` | Example generated evaluation artifacts |

## Optional live model testing

The live evaluator requires a compatible HTTPS Chat Completions endpoint that supports tool calls:

```bash
export LLM_API_URL='https://YOUR_PROVIDER_HOST/v1/chat/completions'
export LLM_MODEL='YOUR_MODEL_NAME'
export LLM_API_KEY='YOUR_API_KEY'
python -m app.real_llm_evaluator
```

**Do not commit credentials.** Some providers, including Azure deployments, may require different authentication or endpoint formats. Live requests may incur charges. All backend refunds remain in-memory simulations.

## Evaluation methodology and limitations

- The offline red-team agent is **deterministic**, not a real language model. Its results cannot establish real-world prompt-injection resistance.
- Reported percentages derive from **small, constructed datasets**; do not generalize them to production without broader evaluation.
- The static scanners are **heuristic educational prototypes**, not sound or complete data-flow or control-flow analyzers.
- The triage labels are fictional ground truth, not independently reproduced production vulnerabilities.
- The live-model harness can capture model-generated tool calls, but benign response presence is only a **proxy** for successful task completion.
- Zero observed failures do not imply zero risk; confidence calculations assume independent identically distributed trials.
- The secure executor illustrates authorization controls, not a complete production payment system (for example, it does not implement durable idempotency, transactional consistency, or external payment integration).

## Responsible use

Run the vulnerable examples only against the synthetic local lab. Do not use these attack cases against third-party systems without authorization.

## Portfolio focus

This project demonstrates security test design, Python automation, authorization reasoning, LLM tool-call analysis, vulnerability triage, and reproducible evaluation—not a claim that any particular real model or production service has been compromised.
