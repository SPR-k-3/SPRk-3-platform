"""
Simple integration test without module imports
"""

import sprk3_agentland_integration as integration
from sprk3_agentland_integration import BehaviorContext, ThreatLevel

print("=" * 70)
print("SPR{K}3 - Agentland Defense Integration Test")
print("=" * 70)

defense = integration.AgentlandDefenseIntegration()

print("\n✅ Testing security monitoring...")

threat = defense.monitor_agent_action(
    agent_id="test_agent",
    observation="Test observation",
    action="Test action",
    action_type="general_action",
    context=BehaviorContext.CODE_EXECUTION
)

print(f"Threat Level: {threat.threat_level.value}")
print(f"Confidence: {threat.confidence:.0%}")
print(f"Total Threats: {threat.total_threats}")

if threat.threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]:
    print("\n✅ Action is safe to execute!")
else:
    print(f"\n🚨 Action blocked - {threat.threat_level.value}")

print("\n✅ Integration working!")
