#!/usr/bin/env python3
import sys
import os
import json
import yaml
import urllib.request
from pathlib import Path
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
import tree_sitter_bash as tsbash
from tree_sitter import Language, Parser

def load_gemini_env():
    """Auto-loads ~/.gemini/.env and project .gemini/.env into os.environ."""
    env_paths = [
        Path.home() / ".gemini" / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

class Tier2JudgeVerdict(BaseModel):
    passed: bool = Field(description="True ONLY if the command is safe to execute.")
    risk_level: str = Field(description="LOW, MEDIUM, HIGH, or CRITICAL")
    mitre_technique: str = Field(description="Relevant MITRE ATT&CK technique ID/name if suspicious, else 'None'")
    blast_radius: str = Field(description="What files, network, or system state could be impacted")
    reasoning: str = Field(description="Concise MDR-style technical breakdown of why this failed or passed")

def respond_and_exit(decision: str, reason: str = ""):
    payload = {"decision": decision}
    if reason:
        payload["reason"] = reason
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
    sys.exit(0)

def run_tier1_ast(command: str, yaml_rules_path: str) -> dict:
    bash_lang = Language(tsbash.language())
    parser = Parser(bash_lang)
    tree = parser.parse(bytes(command, "utf8"))
    root = tree.root_node

    ast_node_types = set()
    commands_found = []

    def walk(node):
        ast_node_types.add(node.type)
        if node.type == "command_name":
            commands_found.append(node.text.decode("utf8"))
        for child in node.children:
            walk(child)
    walk(root)

    with open(yaml_rules_path, "r") as f:
        rules = yaml.safe_load(f) or {}

    violations = []
    for cmd in commands_found:
        if cmd in rules.get("blocked_commands", []):
            violations.append(f"Blocked binary in AST: '{cmd}'")

    for ast_type in rules.get("flagged_ast_nodes", []):
        if ast_type in ast_node_types:
            violations.append(f"High-risk AST construct: '{ast_type}'")

    return {
        "passed": len(violations) == 0,
        "commands_extracted": commands_found,
        "ast_constructs": list(ast_node_types),
        "violations": violations
    }

def run_tier2_argon_judge(command: str, cwd: str, tier1_report: dict) -> Tier2JudgeVerdict:
    client = genai.Client()
    prompt = f"""
    You are a Tier 2 SecOps AI Judge inspecting a Bash command about to be executed by a CLI agent.
    Working Directory: {cwd}
    Raw Command: {command}
    Tier 1 Tree-Sitter AST Summary: {json.dumps(tier1_report)}
    
    Block any privilege escalation, data exfiltration, credential reading, obfuscation, or suspicious remote execution.
    """
    response = client.models.generate_content(
        model="gemini-4-argon",
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=Tier2JudgeVerdict,
            temperature=0.0,
        ),
    )
    return Tier2JudgeVerdict.model_validate_json(response.text)

def escalate_to_tier3_slack(session_id: str, cwd: str, command: str, tier1: dict, tier2: Tier2JudgeVerdict | None):
    webhook_url = os.environ.get("SLACK_SECOPS_WEBHOOK_URL")
    if not webhook_url:
        sys.stderr.write("WARN: SLACK_SECOPS_WEBHOOK_URL not set. Skipping Slack alert.\n")
        return

    incident_breakdown = {
        "session_id": session_id,
        "cwd": cwd,
        "tier_1_ast": {
            "passed": tier1["passed"],
            "extracted_binaries": tier1["commands_extracted"],
            "violations": tier1["violations"]
        },
        "tier_2_argon_judge": tier2.model_dump() if tier2 else "Skipped (Blocked at Tier 1)"
    }
    yaml_summary = yaml.dump(incident_breakdown, sort_keys=False, default_flow_style=False)

    slack_payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Gemini CLI SecOps Alert (Tier 3 Escalation)"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Blocked Command:*\n```{command}```"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Diagnostic Breakdown:*\n```yaml\n{yaml_summary}```"}
            }
        ]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(slack_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as slack_err:
        sys.stderr.write(f"WARN: Failed to send Slack webhook: {slack_err}\n")

def main():
    try:
        load_gemini_env()

        hook_input = json.load(sys.stdin)
        command = hook_input.get("tool_input", {}).get("command", "")
        cwd = hook_input.get("cwd", os.getcwd())
        session_id = hook_input.get("session_id", "local-session")

        rules_path = os.path.join(os.path.dirname(__file__), "tier1_rules.yaml")
        tier1_result = run_tier1_ast(command, rules_path)

        if not tier1_result["passed"]:
            escalate_to_tier3_slack(session_id, cwd, command, tier1_result, None)
            respond_and_exit("deny", f"Blocked by Tier 1 AST Policy: {', '.join(tier1_result['violations'])}")

        tier2_result = run_tier2_argon_judge(command, cwd, tier1_result)

        if not tier2_result.passed:
            escalate_to_tier3_slack(session_id, cwd, command, tier1_result, tier2_result)
            respond_and_exit("deny", f"Escalated to Tier 3 SecOps ({tier2_result.risk_level}): {tier2_result.reasoning}")

        respond_and_exit("allow")

    except Exception as e:
        sys.stderr.write(f"SecOps Hook Error: {str(e)}\n")
        respond_and_exit("deny", f"SecOps Hook Fail-Closed Error: {str(e)}")

if __name__ == "__main__":
    main()