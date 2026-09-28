# Threat model

Scope: the API (`backend/`), the web UI proxy (`frontend/`), and the LLM agent that reads a shared knowledge base.
Each row links a threat to the control in the code and the test that checks it. Known gaps are listed honestly at the end.

## Assets
- Knowledge-base documents (may contain internal playbooks and incident details)
- User accounts and roles
- LLM provider quota / API key
- Audit trail

## Threats and controls

| # | Threat | Control | Test |
|---|--------|---------|------|
| 1 | Password guessing / credential stuffing | Argon2 hashing; per-account login limit (5/min, HTTP 429); failed logins logged as JSON | `test_login_is_rate_limited_per_account`, `test_password_is_stored_as_argon2_hash` |
| 2 | Forged or tampered JWT | HS256 with a required 16+ char secret; algorithm pinned on decode; `alg=none` and wrong-key tokens rejected | `test_alg_none_token_is_rejected`, `test_token_signed_with_wrong_key_is_rejected` |
| 3 | Stolen expired token | 8 h expiry enforced | `test_expired_token_is_rejected` |
| 4 | Privilege escalation | RBAC dependency on every route (admin / analyst / viewer); role read from the DB per request so demotion is immediate | `test_viewer_cannot_ingest_but_analyst_can`, `test_role_changes_apply_to_existing_tokens` |
| 5 | Open self-registration abuse | New accounts are `viewer`; `OPEN_REGISTRATION=false` closes signup after bootstrap | `test_registration_can_be_closed_after_bootstrap` |
| 6 | **Indirect prompt injection** (malicious text inside an uploaded document or API response) | Retrieved text fenced in `<untrusted_document>` tags with breakout stripping; system prompt says to treat it as data; the agent has **read-only tools only**, so a hijacked model cannot change state | `test_retrieved_text_is_fenced_and_cannot_break_out`, `test_system_prompt_tells_model_to_distrust_documents` |
| 7 | Tool-argument injection / SSRF | Tool inputs validated by regex (`CVE-YYYY-NNNN+`); tools call fixed hosts only (NVD, CISA, FIRST), never user-supplied URLs | `test_cve_ids_are_validated_before_any_request` |
| 8 | Runaway agent / cost abuse | Step cap (5), tool output truncated to 4 KB, chat limited to 10/min per user, upload size and chunk caps | `test_agent_stops_at_step_limit`, `test_chat_is_rate_limited_per_user`, `test_upload_enforces_size_limit_and_role` |
| 9 | Malicious upload | Extension allow-list (.pdf/.txt/.md), size cap read in a bounded way, text extraction only (nothing is executed or served back) | `test_upload_accepts_text_and_rejects_other_types` |
| 10 | Repudiation | Audit log of role changes, knowledge-base ingests and chats (with tools used) at `GET /audit`; failed logins go to the JSON logs | `test_chat_returns_answer_and_writes_audit_entry` |
| 11 | Secret leakage | Secrets only via env; `.env` git-ignored; CI runs Bandit; Dependabot watches dependencies | CI |
| 12 | Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` on the UI | manual |

## Known gaps (deliberately not hidden)
- **Prompt injection is mitigated, not solved.** Fencing and read-only tools reduce impact but a model can still be
  misled into giving a wrong answer. Treat outputs as analyst assistance, and check cited sources.
- **No per-tenant isolation.** The knowledge base is shared by all users. A poisoned document affects everyone; only
  analysts/admins can add documents, which limits this.
- **Rate limiter is in-process memory.** It resets on restart and is not shared across replicas; use Redis for scale-out.
- **JWT is a single shared HS256 secret with no revocation list.** Tokens live up to 8 h. Rotate the secret to invalidate all.
- **Token is held in browser memory** (safe from persistent XSS theft, but users re-login on refresh). No CSP header yet.
- **No email verification or password reset.** No MFA.
- **Transport security is out of scope for the compose setup**; terminate TLS at the load balancer (ALB) in AWS.
- **Third-party LLM sees prompts and retrieved chunks.** Do not load data you cannot send to your provider.
