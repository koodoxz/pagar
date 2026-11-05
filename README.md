# Pagar — Agentic Tool-Call Firewall, Secret Exfiltration Guard & Atomic Blast-Radius Rollback Engine

[![CI](https://github.com/koodoxz/pagar/actions/workflows/ci.yml/badge.svg)](https://github.com/koodoxz/pagar/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange?logo=rust)](https://www.rust-lang.org/)
[![Unsafe](https://img.shields.io/badge/unsafe_code-forbidden-brightgreen)](#security-guarantees)
[![MCP](https://img.shields.io/badge/MCP-JSON--RPC_2.0_stdio-blue)](https://modelcontextprotocol.io/)

**Pagar** (Old Javanese / Indonesian: *Defensive Perimeter / Palisade*) is a zero-copy, `#![forbid(unsafe_code)]` Rust security engine and native Model Context Protocol (MCP) server that protects host workspaces from autonomous AI coding agents (Claude Code, Cursor, Windsurf, Antigravity).

While **Kurung** confines untrusted WebAssembly guest modules and **Prasasti** records high-frequency agent telemetry, **Pagar** sits directly in front of host-level agent actions:
1. **Pre-Execution Tool-Call Firewall (`pagar-firewall`)**: Inspects shell, SQL, and Git commands before execution to block destructive mutations (`git push --force`, `rm -rf`, `DROP TABLE`, remote pipe execution) and emits deterministic `SHA-256` verdict receipts.
2. **Secret Exfiltration & Prompt Injection Guard (`pagar-firewall`)**: Scans outbound tool payloads and file diffs for leaked cloud credentials, Shannon entropy anomalies, and indirect prompt injection payloads.
3. **Atomic Blast-Radius Scope Lock & Rollback (`pagar-vault`)**: Snapshots declared workspace files (`Phase 0` blast radius) with `SHA-256` baselines and **atomically rolls back** any undeclared file modification, deletion, or rogue file creation byte-for-byte.

---

## Architecture & Crates

| Crate | Responsibility |
| :--- | :--- |
| `crates/pagar-policy` | Constant-time `SHA-256` license commitment verifier and authenticated stream-cipher (`SHA256-CTR + MAC`) rulepack vault. |
| `crates/pagar-firewall` | Pre-execution shell/SQL/Git command firewall, Shannon entropy calculator, secret scanner, and prompt-injection detector. |
| `crates/pagar-vault` | Workspace `SHA-256` baseline snapshotting, out-of-scope file drift auditing, and byte-exact atomic rollback engine. |
| `crates/pagar-cli` | Standalone CLI (`pagar inspect`, `pagar scan-secrets`, `pagar audit-self`) and zero-overhead `stdio` JSON-RPC 2.0 MCP server (`pagar mcp`). |

---

## Quick Start

### 1. Build from Source

```bash
cargo build --release
./target/release/pagar audit-self
```

### 2. Inspect a Command via CLI

```bash
./target/release/pagar inspect --command "git push --force origin main"
```

### 3. Run as an MCP Server (`mcp.json`)

```json
{
  "mcpServers": {
    "pagar": {
      "command": "pagar",
      "args": ["mcp"],
      "env": {
        "PAGAR_LICENSE_KEY": "YOUR_AGENSI_PRO_KEY_OPTIONAL"
      }
    }
  }
}
```

### Exposed MCP Tools

- `pagar_inspect_command`: Pre-execution firewall check for shell, SQL, and Git commands with `SHA-256` verdict receipt.
- `pagar_scan_secrets`: Scans outbound tool payloads or file diffs for leaked cloud credentials, Shannon entropy anomalies, and indirect prompt injections.
- `pagar_lock_scope`: Snapshots workspace files and locks Phase-0 allowed file scope to prevent undeclared agent file drift.
- `pagar_audit_and_rollback`: Audits workspace against a locked `scope_id` and atomically rolls back any unauthorized file modifications, deletions, or rogue file creations.
- `pagar_audit_self`: Returns `SHA-256` binary integrity attestation and active Pagar license tier capabilities.

---

## Community Evaluation vs. Enterprise Pro Tier

Pagar operates in **Community Evaluation Tier** out of the box (up to 15 inspections per session and 2 locked scope files with baseline rules).

Unlocking **Enterprise Pro (`ENTERPRISE_PRO_V1`)** via the official [Agensi.io Pagar Workspace Firewall Skill Bundle](https://agensi.io) supplies the `PAGAR_LICENSE_KEY` that cryptographically unseals the embedded `ENCRYPTED_PRO_VAULT` (`SHA256-CTR + MAC`), enabling:
- **1,000,000 inspections/session** and **10,000 locked workspace files**
- **22 Enterprise Destructive Command Signatures** (Shell, SQL, Git, PowerShell encoded payloads, reverse shells)
- **12 Cloud & Database Credential Signatures** (AWS, OpenAI, Anthropic, Stripe Live, GitHub PAT, Slack, GCP, PEM keys, PostgreSQL/MySQL/MongoDB URIs)
- **8 Indirect Prompt Injection Signatures**

---

## License

Dual-licensed under `Apache-2.0 OR MIT` for the core engine; the encrypted Enterprise Pro signature vault is unlocked via a commercial Agensi.io license key.
