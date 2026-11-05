#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use pagar_firewall::FirewallEngine;
use pagar_policy::LicenseTier;
use pagar_vault::ScopeVault;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pagar",
    version,
    about = "Zero-copy MCP tool-call firewall, secret exfiltration guard, and atomic blast-radius rollback engine for AI agents"
)]
struct Cli {
    /// Optional Pro License Key (overrides PAGAR_LICENSE_KEY environment variable)
    #[arg(long, global = true)]
    license_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a shell, SQL, or git command before execution
    Inspect {
        #[arg(long)]
        command: String,
    },
    /// Scan a text or file payload for leaked cloud credentials and prompt injections
    ScanSecrets {
        #[arg(long)]
        payload: String,
    },
    /// Audit self binary SHA-256 integrity and active license tier
    AuditSelf,
    /// Run native JSON-RPC 2.0 MCP server over stdio
    Mcp,
}

fn resolve_tier(cli_key: Option<String>) -> Result<LicenseTier, String> {
    let key = cli_key.or_else(|| env::var("PAGAR_LICENSE_KEY").ok());
    LicenseTier::from_token(key.as_deref()).map_err(|e| e.to_string())
}

fn compute_self_sha256() -> String {
    if let Ok(exe) = env::current_exe() {
        if let Ok(bytes) = fs::read(exe) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest = hasher.finalize();
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(64);
            for &b in &digest {
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
            return out;
        }
    }
    "unavailable".to_string()
}

fn main() {
    let cli = Cli::parse();
    let tier = match resolve_tier(cli.license_key) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("License verification error: {err}");
            std::process::exit(2);
        }
    };

    match cli.command {
        Commands::Inspect { command } => {
            let mut engine = FirewallEngine::new(tier);
            match engine.inspect_command(&command) {
                Ok(verdict) => {
                    println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::ScanSecrets { payload } => {
            let mut engine = FirewallEngine::new(tier);
            match engine.scan_secrets(&payload) {
                Ok(verdict) => {
                    println!("{}", serde_json::to_string_pretty(&verdict).unwrap());
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::AuditSelf => {
            let engine = FirewallEngine::new(tier.clone());
            let out = json!({
                "binary": "pagar",
                "version": env!("CARGO_PKG_VERSION"),
                "binary_sha256": compute_self_sha256(),
                "license_tier": engine.tier_name(),
                "max_inspections_per_session": tier.max_inspections(),
                "max_scope_files": tier.max_scope_files(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Commands::Mcp => {
            run_mcp_server(tier);
        }
    }
}

fn run_mcp_server(tier: LicenseTier) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut engine = FirewallEngine::new(tier.clone());
    let mut active_vaults: BTreeMap<String, ScopeVault> = BTreeMap::new();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };

        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "pagar-mcp-firewall",
                        "version": env!("CARGO_PKG_VERSION"),
                        "tier": engine.tier_name()
                    }
                }
            }),
            "notifications/initialized" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "pagar_inspect_command",
                            "description": "Pre-execution firewall check for shell, SQL, and git commands with SHA-256 verdict receipt.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": { "type": "string" }
                                },
                                "required": ["command"]
                            }
                        },
                        {
                            "name": "pagar_scan_secrets",
                            "description": "Scans outbound tool payloads or file diffs for leaked cloud credentials, Shannon entropy anomalies, and indirect prompt injections.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "payload": { "type": "string" }
                                },
                                "required": ["payload"]
                            }
                        },
                        {
                            "name": "pagar_lock_scope",
                            "description": "Snapshots workspace files and locks Phase-0 allowed file scope to prevent undeclared agent file drift.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "scope_id": { "type": "string" },
                                    "workspace_root": { "type": "string" },
                                    "allowed_files": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["scope_id", "workspace_root", "allowed_files"]
                            }
                        },
                        {
                            "name": "pagar_audit_and_rollback",
                            "description": "Audits workspace against a locked scope_id and atomically rolls back any unauthorized file modifications, deletions, or rogue file creations.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "scope_id": { "type": "string" },
                                    "auto_rollback": { "type": "boolean" }
                                },
                                "required": ["scope_id", "auto_rollback"]
                            }
                        },
                        {
                            "name": "pagar_audit_self",
                            "description": "Returns SHA-256 binary integrity attestation and active Pagar license tier capabilities.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);

                let tool_result = match tool_name {
                    "pagar_inspect_command" => {
                        let cmd = args.get("command").and_then(|c| c.as_str()).unwrap_or("");
                        match engine.inspect_command(cmd) {
                            Ok(v) => Ok(serde_json::to_value(v).unwrap()),
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    "pagar_scan_secrets" => {
                        let payload = args.get("payload").and_then(|c| c.as_str()).unwrap_or("");
                        match engine.scan_secrets(payload) {
                            Ok(v) => Ok(serde_json::to_value(v).unwrap()),
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    "pagar_lock_scope" => {
                        let scope_id = args
                            .get("scope_id")
                            .and_then(|s| s.as_str())
                            .unwrap_or("default")
                            .to_string();
                        let root_str = args
                            .get("workspace_root")
                            .and_then(|s| s.as_str())
                            .unwrap_or(".");
                        let allowed: Vec<String> = args
                            .get("allowed_files")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        match ScopeVault::lock_scope(&PathBuf::from(root_str), &allowed, &tier) {
                            Ok(vault) => {
                                let snap_count = vault.baseline.len();
                                active_vaults.insert(scope_id.clone(), vault);
                                Ok(json!({
                                    "status": "LOCKED",
                                    "scope_id": scope_id,
                                    "tier": engine.tier_name(),
                                    "allowed_files": allowed,
                                    "snapshotted_files_count": snap_count
                                }))
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    "pagar_audit_and_rollback" => {
                        let scope_id = args
                            .get("scope_id")
                            .and_then(|s| s.as_str())
                            .unwrap_or("default");
                        let auto_rollback = args
                            .get("auto_rollback")
                            .and_then(|b| b.as_bool())
                            .unwrap_or(true);
                        match active_vaults.get(scope_id) {
                            Some(vault) => match vault.audit_and_rollback(auto_rollback) {
                                Ok(rep) => Ok(serde_json::to_value(rep).unwrap()),
                                Err(e) => Err(e.to_string()),
                            },
                            None => Err(format!("unknown scope_id: {scope_id}")),
                        }
                    }
                    "pagar_audit_self" => Ok(json!({
                        "binary": "pagar",
                        "version": env!("CARGO_PKG_VERSION"),
                        "binary_sha256": compute_self_sha256(),
                        "license_tier": engine.tier_name(),
                        "inspections_run": engine.inspections_run(),
                        "max_inspections_per_session": tier.max_inspections(),
                        "max_scope_files": tier.max_scope_files(),
                    })),
                    other => Err(format!("unknown tool: {other}")),
                };

                match tool_result {
                    Ok(val) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string(&val).unwrap()
                            }],
                            "isError": false
                        }
                    }),
                    Err(err_msg) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": err_msg
                            }],
                            "isError": true
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        let _ = writeln!(stdout, "{}", serde_json::to_string(&response).unwrap());
        let _ = stdout.flush();
    }
}
