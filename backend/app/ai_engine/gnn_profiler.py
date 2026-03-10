from typing import List, Dict, Any
import json
from datetime import datetime
from app.models.all_models import RawEventModel

class TemporalGNNProfiler:
    """
    Simulates a Temporal Graph Neural Network (GNN) by algorithmically constructing
    a structural entity relationship graph from chronological honeypot telemetry.
    It scores behaviors to classify Threat Actors and map MITRE ATT&CK matrices.
    """
    
    def __init__(self, events: List[RawEventModel]):
        self.events = sorted(events, key=lambda e: e.timestamp if e.timestamp else datetime.min)
        self.nodes = []
        self.edges = []
        self.node_lookup = {}
        self.mitre_map = {
            "initial_access": set(),
            "execution": set(),
            "persistence": set(),
            "priv_esc": set(),
            "defense_evasion": set(),
            "c2": set(),
            "impact": set()
        }
        self.terminal_logs = []
        
        self.actor_profiles = {
            "FANCY BEAR": {"aggression": 80, "obfuscation": 60, "targets": "GOV / MILITARY", "lateral": "SMB / WMI"},
            "LAZARUS": {"aggression": 90, "obfuscation": 40, "targets": "FINANCIAL", "lateral": "SMB"},
            "SANDWORM": {"aggression": 95, "obfuscation": 30, "targets": "ICP / CRITICAL", "lateral": "RDP / SSH"},
            "UNKNOWN AUTOMATED": {"aggression": 40, "obfuscation": 10, "targets": "OPPORTUNISTIC", "lateral": "SCANNING"}
        }

    def _add_node(self, node_id: str, label: str,  color: str, shape: str = "dot", size: int = 20) -> int:
        if node_id not in self.node_lookup:
            n_id = len(self.nodes) + 1
            self.node_lookup[node_id] = n_id
            self.nodes.append({"id": n_id, "label": str(label)[:25], "color": color, "shape": shape, "size": size})
        return self.node_lookup[node_id]

    def _add_edge(self, source_id: int, target_id: int, label: str = ""):
        # Prevent self-referencing duplicates
        if source_id == target_id:
            return
        
        # Check for existing edge
        for e in self.edges:
            if e["from"] == source_id and e["to"] == target_id and e.get("label") == label:
                return
                
        self.edges.append({"from": source_id, "to": target_id, "label": label})

    def construct_temporal_graph(self):
        """
        Parses chronological events to build relationships: IP -> Port -> Commands -> Files
        """
        # Base System Node
        sys_node = self._add_node("SYSTEM_ROOT", "Honeynet Core", "#ef4444", "star", 30)
        
        for evt in self.events:
            ts = evt.timestamp.strftime("%H:%M:%S") if evt.timestamp else "00:00:00"
            ip = evt.attacker_ip or "Unknown IP"
            port = evt.target_port or 0
            
            # Attacker Node
            ip_node = self._add_node(f"IP_{ip}", ip, "#00f3ff", "diamond", 15)
            
            # Service Node
            svc_name = f"Port {port}"
            if port == 22: svc_name = "SSH Service"
            elif port == 21: svc_name = "FTP Service"
            elif port == 80: svc_name = "HTTP Service"
            elif port == 445: svc_name = "SMB Service"
            
            svc_node = self._add_node(f"PORT_{port}", svc_name, "#bc13fe", "dot", 20)
            
            self._add_edge(ip_node, svc_node, "targets")
            self._add_edge(svc_node, sys_node, "hosted_by")
            
            # MITRE & Logs Mapping based on payload
            payload = {}
            if evt.raw_payload:
                try:
                    payload = json.loads(evt.raw_payload)
                except:
                    pass
                    
            commands = evt.commands or payload.get("input") or ""
            uploaded = evt.uploaded_files or ""
            
            # Edge: Commands Executed
            if commands:
                cmd_short = commands.split(" ")[0] if " " in commands else commands
                cmd_node = self._add_node(f"CMD_{cmd_short[:10]}", f"CMD: {cmd_short[:10]}", "#ffee00", "square", 15)
                self._add_edge(svc_node, cmd_node, "spawns")
                
                self.terminal_logs.append({
                    "time": ts,
                    "user": "root@sys" if port == 22 else "www-data",
                    "userColor": "#ef4444" if port == 22 else "#bc13fe",
                    "msg": commands
                })
                
                # Mitre Execution
                self.mitre_map["execution"].add("T1059") # Cmd/Scripting
                if "powershell" in commands.lower():
                    self.mitre_map["execution"].add("T1059.001")
                if "base64" in commands.lower() or "xor" in commands.lower():
                    self.mitre_map["defense_evasion"].add("T1027") # Obfuscated Files
                    
            # Edge: Files Dropped
            if uploaded:
                file_node = self._add_node(f"FILE_{uploaded[:10]}", f"Payload: {uploaded[:10]}", "#ff0055", "hexagon", 15)
                self._add_edge(ip_node, file_node, "drops")
                
                self.terminal_logs.append({
                    "time": ts,
                    "user": "system",
                    "userColor": "#00f3ff",
                    "msg": f"[ALERT] Malicious payload drop detected: {uploaded}"
                })
                
                self.mitre_map["c2"].add("T1105") # Ingress Tool Tx
                
            # Brute Force logic
            if evt.event_type == "SSH_BRUTE_FORCE" or "password" in payload:
                self.mitre_map["initial_access"].add("T1078") # Valid Accounts
                self.mitre_map["persistence"].add("T1098") # Account Manipulation

            # Web Exploit logic
            if port in [80, 443, 8080]:
                self.mitre_map["initial_access"].add("T1190") # Exploit Public App
                
                if "sql" in commands.lower() or "select" in commands.lower():
                    self.mitre_map["impact"].add("T1485") # Data Destruction potential
                    
            # Lateral movement / Scan
            if evt.ports_scanned or port == 445:
                self.mitre_map["initial_access"].add("T1133") # Ext Remote Svcs
                
        # Limit terminal logs to the last 20 events chronologically
        self.terminal_logs = self.terminal_logs[-20:]
                
    def analyze_behavior(self) -> Dict[str, Any]:
        """
        Calculates Graph Degree Centrality to determine Threat Actor Profiling and Kill Chain.
        """
        # Calculate Graph Topology Math
        node_degrees = {n["id"]: 0 for n in self.nodes}
        for edge in self.edges:
            node_degrees[edge["from"]] += 1
            node_degrees[edge["to"]] += 1
            
        max_degree = max(node_degrees.values()) if node_degrees else 0
        edge_count = len(self.edges)
        
        # Determine Actor Match based on structure
        actor_name = "UNKNOWN AUTOMATED"
        confidence = 54.2
        killchain = "Pending..."
        kc_percent = 30
        kc_active_idx = 4
        
        has_execution = "T1059" in self.mitre_map["execution"]
        has_drops = "T1105" in self.mitre_map["c2"]
        has_obf = "T1027" in self.mitre_map["defense_evasion"]
        
        if edge_count > 50 and has_obf and has_execution:
            actor_name = "FANCY BEAR"
            confidence = 88.7 + (max_degree % 10)
            killchain = "Exploit (ACTIVE)"
            kc_percent = 25
            kc_active_idx = 3 # Weaponize/Exploit
        elif edge_count > 30 and has_drops:
            actor_name = "LAZARUS"
            confidence = 76.4 + (max_degree % 10)
            killchain = "Deliver (ACTIVE)"
            kc_percent = 20
            kc_active_idx = 2
        elif max_degree > 15:
            actor_name = "SANDWORM"
            confidence = 82.1
            killchain = "Weaponize (ACTIVE)"
            kc_percent = 15
            kc_active_idx = 1
        elif edge_count > 0:
            killchain = "Recon (ACTIVE)"
            kc_percent = 20
            kc_active_idx = 0
            confidence = 99.1
            
        traits = self.actor_profiles.get(actor_name, self.actor_profiles["UNKNOWN AUTOMATED"])
        
        # Flatten MITRE Map for frontend active states
        mitre_flat = {}
        for tactic, techniques in self.mitre_map.items():
            for t in techniques:
                if t in ["T1190", "T1059", "T1573", "T1068", "T1486"]:
                    mitre_flat[t] = "critical"
                elif t in ["T1133", "T1098", "T1055", "T1070", "T1071", "T1090"]:
                    mitre_flat[t] = "high"
                else:
                    mitre_flat[t] = "med"
                    
        return {
            "actor": {
                "name": actor_name,
                "confidence": round(confidence, 1),
                "traits": {
                    "Persistence": "AGGRESSIVE" if traits["aggression"] > 80 else "MODERATE",
                    "Lateral Movement": traits["lateral"],
                    "Obfuscation": "HIGH (XOR/BASE64)" if traits["obfuscation"] > 50 else "LOW",
                    "Targeting": traits["targets"]
                }
            },
            "killchain": {
                "stage_name": killchain,
                "percent": kc_percent,
                "active_index": kc_active_idx,
            },
            "graph": {
                "nodes": self.nodes,
                "edges": self.edges
            },
            "mitre": mitre_flat,
            "logs": self.terminal_logs
        }
