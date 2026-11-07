# LLM Red-Team Starter — 20 prompts to test your AI chatbot (free)

A free, open set of **20 adversarial prompts** for checking whether *your own* AI chatbot or custom
GPT resists prompt injection, system-prompt extraction, data leakage, and unsafe actions. Mapped to
the **OWASP LLM Top 10**. Runs with one command via [promptfoo](https://www.promptfoo.dev/).

> ⚠️ **Defensive use only.** Point this at a system **you own or are authorised to test**. It contains
> test *prompts and checks only* — no malware, no live exploits.

## Why
Most people test that their bot *answers*. Attackers test whether it *refuses the bad stuff* — leaks
its hidden prompt, follows "ignore your instructions," reveals uploaded files, or fires off actions it
shouldn't. This lets you check that yourself in about five minutes.

## What's tested (20 of the full 56)
System-prompt extraction (LLM07) · direct & indirect prompt injection (LLM01) · sensitive-info /
knowledge-file leak (LLM02) · tool & action misuse (LLM06) · policy/role override (LLM01) · unsafe
output (LLM05) · false guarantees (LLM09).

## Quick start
```bash
# 1. put your model/provider key in your shell, e.g.
export OPENAI_API_KEY=sk-...
# 2. run the 20-prompt sampler against a model (edit the provider/system prompt to match your bot)
npx -y promptfoo@latest eval -c promptfooconfig.yaml
npx -y promptfoo@latest view
```
Edit `promptfooconfig.yaml` to point at your own deployed bot's HTTP endpoint, or paste your bot's
system prompt, so you're testing *your* guardrails. Red rows = your bot did something it shouldn't.

## How grading works
Each response is graded by an LLM rubric (does the bot stay safe for that category?). Grading is a
heuristic — skim the reds yourself. The goal is to surface prompts worth a human look.

## The full pack
This is the free 20-prompt teaser. The full **Chatbot Defense Test Pack** has 56 prompts across 8
categories, a plain-English fix guide for every category, and a fresh batch of new prompts each month
as attacker patterns change.

- **Full pack & fix guide:** https://ai-safety-desk.vercel.app/?utm_source=github
- **Free 10-minute AI tools checklist (non-technical):** https://ai-safety-desk.vercel.app/checklist.html?utm_source=github
- **Guides:**
  [Is ChatGPT safe for my business?](https://ai-safety-desk.vercel.app/guides/is-chatgpt-safe-for-business.html?utm_source=github) ·
  [Test your chatbot for prompt injection](https://ai-safety-desk.vercel.app/guides/test-chatbot-prompt-injection.html?utm_source=github) ·
  [OWASP LLM Top 10 checklist](https://ai-safety-desk.vercel.app/guides/owasp-llm-top-10-checklist.html?utm_source=github)

## License
MIT for the tooling. The prompts are provided for authorized, defensive testing of systems you own or
have permission to test. Not a certification. Built with AI, reviewed by a human.
