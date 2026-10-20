"""MCP Server for PII Redactor & Data Masker.
100% Python Standard Library JSON-RPC.
"""
import sys
import json
from client import PiiRedactorAndDataMasker

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")

            if method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            {
                                "name": "redact",
                                "description": "Mask sensitive PII (emails, phones, SSNs, credit cards, IPs) with token map",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "text": {"type": "string", "description": "Unsanitized text input"}
                                    },
                                    "required": ["text"]
                                }
                            },
                            {
                                "name": "restore",
                                "description": "Restore sanitized text back to original values using token map",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "redacted_text": {"type": "string"},
                                        "token_map": {"type": "object"}
                                    },
                                    "required": ["redacted_text", "token_map"]
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                call_name = req.get("params", {}).get("name")
                args = req.get("params", {}).get("arguments", {})
                if call_name == "redact":
                    res = PiiRedactorAndDataMasker.redact(args.get("text", ""))
                elif call_name == "restore":
                    res = {"restored_text": PiiRedactorAndDataMasker.restore(args.get("redacted_text", ""), args.get("token_map", {}))}
                else:
                    res = {"error": "Unknown tool"}
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
