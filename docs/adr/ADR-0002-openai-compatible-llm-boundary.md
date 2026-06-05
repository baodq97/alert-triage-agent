---
id: ADR-0002
title: OpenAI-compatible API as the single LLM boundary
status: accepted
owner: baodq97
date: 2026-06-05
---

# ADR-0002 — OpenAI-compatible API as the single LLM boundary

Parent: RFC-0001.

## Context

The agent must make at least one real LLM call (OpenAI, Anthropic, or Google), the reviewer grades with their own key, and the bonus asks how a local open-source model (DeepSeek/Llama) could be swapped in without changing agent logic.

## Decision

Use the `openai` SDK wire format as the only LLM interface. Provider, endpoint, and model are environment configuration: `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`. OpenAI, DeepSeek, OpenRouter, Ollama, and vLLM all speak this protocol — swapping models, including local ones, is a `.env` edit with zero agent-logic changes.

## Alternatives considered

- **Anthropic-native client + per-provider adapters** — cleaner access to native features (prompt caching, extended thinking), but multiplies adapter code and forces the reviewer onto a specific provider. Rejected for scope; the adapter seam can be added later behind the same internal interface.
- **LiteLLM / abstraction library** — solves the same problem with another dependency; unnecessary when one wire format already covers every required provider.

## Consequences

- (+) Local-model bonus collapses into configuration; reviewer runs with whatever key they have.
- (+) One structured-output/repair code path to test.
- (−) Anthropic models are reachable only via OpenAI-compatible gateways, and provider-specific features (caching, thinking) are unavailable — acceptable at this scope.
