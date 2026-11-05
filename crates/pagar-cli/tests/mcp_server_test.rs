use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const VALID_PRO_TOKEN: &str =
    "NSTR-PRO-V1-8F4B2E91C7A64D305E129B87F360A4C1D9E87254106BC3F9A82D47E16B53C09A-3B3B5F6ABB8571C2";

#[test]
fn mcp_server_lists_tools_and_enforces_firewall_and_pro_tier() {
    let bin = env!("CARGO_BIN_EXE_pagar");
    let mut child = Command::new(bin)
        .arg("mcp")
        .env("PAGAR_LICENSE_KEY", VALID_PRO_TOKEN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn pagar mcp");

    let stdin = child.stdin.as_mut().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("pagar-mcp-firewall"));

    line.clear();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("pagar_inspect_command"));
    assert!(line.contains("pagar_scan_secrets"));
    assert!(line.contains("pagar_lock_scope"));
    assert!(line.contains("pagar_audit_and_rollback"));
    assert!(line.contains("pagar_audit_self"));

    line.clear();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"pagar_inspect_command","arguments":{{"command":"git push --force origin main"}}}}}}"#
    )
    .unwrap();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("Block"));
    assert!(line.contains("ENTERPRISE_PRO_V1"));

    let _ = child.kill();
    let _ = child.wait();
}

