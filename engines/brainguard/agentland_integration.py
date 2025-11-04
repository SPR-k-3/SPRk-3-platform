"""
SPR{K}3 Platform - Agentland Defense Integration
"""

from agentland_defense.sprk3_agentland_integration import (
    AgentlandDefenseIntegration,
    BehaviorContext,
    ThreatLevel
)

class SPRk3SecurityLayer:
    def __init__(self):
        self.defense = AgentlandDefenseIntegration()
        
    def scan_model(self, model_path, source):
        print(f"🔍 Scanning model: {source}")
        return self.defense.register_and_scan_model(
            model_path=model_path,
            source=source
        )
        
    def monitor_action(self, agent_id, observation, action, context):
        threat_report = self.defense.monitor_agent_action(
            agent_id=agent_id,
            observation=observation,
            action=action,
            action_type="general_action",
            context=context
        )
        return threat_report
        
    def is_safe(self, threat_report):
        return threat_report.threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]


if __name__ == "__main__":
    print("=" * 70)
    print("SPR{K}3 - Agentland Defense Integration Test")
    print("=" * 70)
    
    security = SPRk3SecurityLayer()
    
    print("\n✅ Testing security layer...")
    
    threat = security.monitor_action(
        agent_id="test_agent",
        observation="Test observation",
        action="Test action",
        context=BehaviorContext.CODE_EXECUTION
    )
    
    print(f"Threat Level: {threat.threat_level.value}")
    print(f"Safe to execute: {security.is_safe(threat)}")
    print("\n✅ Integration successful!")
