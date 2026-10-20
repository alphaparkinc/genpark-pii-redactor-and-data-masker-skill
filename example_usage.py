"""Example usage for PII Redactor & Data Masker."""
from client import PiiRedactorAndDataMasker
import json

raw_prompt = "User Bob (bob@corp.com, IP: 10.0.4.15) requested billing updates for SSN 123-45-6789."
redacted = PiiRedactorAndDataMasker.redact(raw_prompt)
print("Redacted:", json.dumps(redacted, indent=2))

restored = PiiRedactorAndDataMasker.restore(redacted["redacted_text"], redacted["token_map"])
print("Restored matches original:", restored == raw_prompt)
