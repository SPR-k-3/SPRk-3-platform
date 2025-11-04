#!/usr/bin/env python3
"""
Test BrainGuard with local GPT-2 model
"""
from transformers import pipeline
from brainguard_monitor import BrainGuardMonitor

print("Loading GPT-2 model (this may take a minute)...")
generator = pipeline('text-generation', model='gpt2')

def gpt2_interface(prompt: str) -> str:
    """Interface to local GPT-2"""
    try:
        result = generator(prompt, max_length=150, num_return_sequences=1, pad_token_id=50256)
        return result[0]['generated_text']
    except Exception as e:
        return f"[ERROR] {str(e)}"

print("Starting BrainGuard assessment of GPT-2...")
monitor = BrainGuardMonitor(model_interface=gpt2_interface)
report = monitor.run_full_assessment("GPT-2-Local")

print(f"\n✅ Overall Health Score: {report.overall_health_score:.1f}/100")
