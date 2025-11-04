#!/usr/bin/env python3
import anthropic
from brainguard_monitor import BrainGuardMonitor

# PUT YOUR API KEY HERE
API_KEY = "sk-ant-api03-..."  # Replace with your real key

client = anthropic.Anthropic(api_key=API_KEY)

def claude_interface(prompt: str) -> str:
    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

monitor = BrainGuardMonitor(model_interface=claude_interface)
report = monitor.run_full_assessment("Claude-3.5-Sonnet")

print(f"\n✅ Overall Health Score: {report.overall_health_score:.1f}/100")
