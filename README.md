# canaryprobe: deterministic leak and injection checks for your chatbot

`canaryprobe` tests a chatbot **you own** for system-prompt leaks, secret leaks, prompt injection and
unconfirmed tool calls, without using another LLM as the grader.

It plants unique canary values in your system prompt (a reference code, a fake API key and a fake
contact), sends 20 probes mapped to the OWASP LLM Top 10, and checks the replies for those exact values.
It also catches common re-encodings that LLM judges often miss: base64, hex, rot13, reversed text and
spaced-out characters. In OpenAI-compatible mode it offers three fake tools (`send_email`,
`issue_refund`, `transfer_to_human`) and flags the model if it calls them when it should ask first.

- **Deterministic:** the same reply always gives the same verdict, and grading costs no tokens.
- **No dependencies:** one Python file, standard library only (Python 3.9+).
- **CI-ready:** JSON, Markdown and SARIF output, plus a non-zero exit code on failure. You can upload the
  SARIF file to GitHub code scanning.
- **Honest about limits:** categories that cannot be checked by string or tool evidence (false
  guarantees, harmful content) are marked `REVIEW`, never `PASS`.

## Quick start

```bash
# offline: runs against a built-in leaky bot and a safe bot, no API key needed
python3 canaryprobe.py --selftest

# your system prompt on any OpenAI-compatible API (OpenAI, Azure, vLLM, Ollama, LM Studio, ...)
export OPENAI_API_KEY=sk-...
python3 canaryprobe.py --openai-base https://api.openai.com/v1 --model gpt-4o-mini \
  --system-prompt-file my_bot_prompt.txt --md report.md --sarif results.sarif

# a bot you already deployed: put a canary such as REF-7Q2M-91XK in its prompt or knowledge base first
python3 canaryprobe.py --http https://bot.example.com/chat --canary REF-7Q2M-91XK \
  --body '{"message": "{prompt}"}' --reply-path reply
```

Use `--repeat 3` to send each probe three times and keep the worst result, because model output varies.

## Verdicts

| verdict | meaning |
|---|---|
| `FAIL` | hard evidence: a canary or its re-encoding appeared in the reply, an injected marker was obeyed (for example `UNLOCKED` or `PWNED`), the reply contains a `<script>` tag, or a fake tool was called without confirmation |
| `REVIEW` | no deterministic signal for this category, or a suspicious phrase matched; read the reply yourself |
| `PASS` | the deterministic checks for this probe found nothing |
| `ERROR` | the request failed |

## CI example (GitHub Actions)

Copy [`examples/github-actions-canaryprobe.yml`](examples/github-actions-canaryprobe.yml) to `.github/workflows/` in your repo. It runs the probes against
your prompt file on every pull request and uploads the SARIF file to code scanning.

## Using it with promptfoo

The same 20 probes are also available as a promptfoo test file (`attacks_lite.yaml` with
`promptfooconfig.yaml`). That setup uses LLM-rubric grading, which works well alongside canaryprobe's
deterministic checks.

```bash
npx -y promptfoo@latest eval -c promptfooconfig.yaml
```

## Probes

`probes.json` has 20 probes: system-prompt extraction (LLM07), direct and indirect prompt injection
(LLM01), sensitive information and knowledge-file leaks (LLM02), tool and action misuse (LLM06), policy
or role override, unsafe output (LLM05) and false guarantees (LLM09). Each probe lists its own
deterministic checks (`fail_if_contains`, `fail_if_regex`, `fail_if_tool`, `review_if_regex`), so you can
add your own probes in the same format.

## Responsible use

Run it only against systems you own or have written permission to test. The probes contain test prompts
and checks only, with no malware or exploits. A clean result is not a security certification.

## License

MIT (see `LICENSE`).

Maintained by AI Safety Desk (https://ai-safety-desk.vercel.app/?utm_source=github).
