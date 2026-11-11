# AI analysis 

Gemini explains results that the deterministic engine already produced. It never decides what is risky, never calculates a score, never changes a finding or an attack path, and never runs actions.

## What it does

| Subject | Output |
|---|---|
| Finding | What was detected, why it is risky, potential impact, what the evidence establishes, remaining uncertainty, remediation steps with what to verify first |
| Attack path | Overview, one explanation per step, impact, why it deserves attention, what to verify before claiming exploitability, remediation steps |
| Run summary | Overview, priorities with recommended actions, caveats |

## What is sent

Names, rule and score facts, the engine's own explanation text, and trimmed policy statements (effect, actions, resources or principals, conditions). It is never sent: passwords, tokens, API keys, the raw imported file, user accounts or emails.

Imported strings are untrusted. Before sending, the backend removes control characters, redacts strings that look like keys or tokens, and limits length. The system instruction tells the model to treat all of it as data and not to follow instructions found in it.

## What comes back

The response must match a fixed schema, must not exceed length limits, and for attack paths must explain each step exactly once. Anything else is rejected and nothing is stored. Results are stored in their own table, labeled AI-generated, and cached by a hash of the input, the model and the prompt version.

## Failure behavior

If Gemini is not configured, out of quota, slow, unreachable or returns something unusable, the API returns an error with a code (`ai_not_configured`, `ai_quota_exceeded`, `ai_timeout`, `ai_provider_error`, `ai_invalid_response`). Findings, scores, attack paths, comparison and reports keep working. Nothing is retried automatically, because the free tier has low request limits.

## Configuration

`GEMINI_API_KEY` and `GEMINI_MODEL` in `.env`. The model is not hardcoded. Run `python -m app.ai.check` inside the backend container to list the models a key can use and to test the configured one.