"""
SPR{K}3 Platform - Agentland Defense Integration
Connects the 4-engine system with backdoor protection
"""

from agentland_defense.sprk3_agentland_integration import (
    AgentlandDefenseIntegration,
    BehaviorContext,
    ThreatLevel
)

class SPRk3SecurityLayer:
    """
    Security layer that wraps around SPR{K}3's existing engines
    
    Integrates:
    - Pattern Engine (existing)
    - Bio-Intelligence Engine (existing)
    - Decision Engine (existing)
    - BrainGuard Engine (existing)
    + Agentland Defense (NEW!)
    """
    
    def __init__(self):
        self.defense = AgentlandDefenseIntegration()
        self.monitored_agents = {}
        
    def register_agent(self, agent_id, training_traces):
        """Register an agent for monitoring"""
        print(f"🔐 Registering agent for security monitoring: {agent_id}")
        self.defense.setup_agent_monitoring(agent_id, training_traces)
        self.monitored_agents[agent_id] = True
        
    def scan_model(self, model_path, source):
        """Scan a model before using it in SPR{K}3"""
        print(f"🔍 Scanning model: {source}")
        return self.defense.register_and_scan_model(
            model_path=model_path,
            source=source
        )
        
    def monitor_action(self, agent_id, observation, action, context):
        """Monitor an agent action for threats"""
        if agent_id not in self.monitored_agents:
            print(f"⚠️  Agent {agent_id} not registered - registering now...")
            # Auto-register with empty baseline (should train properly in production)
            self.monitored_agents[agent_id] = True
            
        threat_report = self.defense.monitor_agent_action(
            agent_id=agent_id,
            observation=observation,
            action=action,
            action_type=self._classify_action(action),
            context=context
        )
        
        return threat_report
        
    def _classify_action(self, action):
        """Classify action type for monitoring"""
        if "SELECT" in action.upper() or "QUERY" in action.upper():
            return "database_query"
        elif "POST" in action.upper() or "http" in action.lower():
            return "http_request"
        elif "execute" in action.lower():
            return "code_execution"
        else:
            return "general_action"
            
    def is_safe(self, threat_report):
        """Check if action is safe to execute"""
        return threat_report.threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]


# Example usage
if __name__ == "__main__":
    print("=" * 70)
    print("SPR{K}3 Platform - Agentland Defense Integration Demo")
    print("=" * 70)
    
    security = SPRk3SecurityLayer()
    
    # Example 1: Scan a model before use
    print("\n📦 Example 1: Pre-deployment model scanning")
    print("-" * 70)
    scan_result = security.scan_model(
        model_path="/path/to/model",
        source="internal/sprk3-pattern-engine-v1"
    )
    print(f"Model risk level: {scan_result.get('risk_level', 'UNKNOWN')}")
    
    # Example 2: Monitor agent action
    print("\n\n🔍 Example 2: Runtime action monitoring")
    print("-" * 70)
    
    threat = security.monitor_action(
        agent_id="sprk3_pattern_detector",
        observation="Analyze code patterns",
        action="Scanning repository for survivor patterns",
        context=BehaviorContext.CODE_EXECUTION
    )
    
    if security.is_safe(threat):
        print("✅ Action approved - executing...")
    else:
        print(f"🚨 Action blocked - Threat level: {threat.threat_level.value}")
    
    print("\n✅ Integration layer ready!")
