from typing import List, Dict, Any
import json
from datetime import datetime
from app.models.all_models import RawEventModel

class TemporalGNNProfiler:
    """
    Behavioral graph analysis over honeypot telemetry.

    Builds an interaction graph (source IP ↔ sensor ↔ port ↔ session ↔ command)
    from chronological events, computes real graph metrics (degree / betweenness
    centrality, connected components) with networkx, maps observed indicators to
    MITRE ATT&CK tactics, and classifies the *style* of activity from measured
    signals — command volume, interactivity, technique spread, cadence. It does
    NOT attribute to named threat groups: a honeypot has no basis for that.
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
        self._shell_prev = {}   # session_id -> last command node id (for sequential chaining)


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

            # ── Analysis Lab sandbox sessions — an analyst driving commands ──
            if (evt.honeypot_type or "") == "AnalysisShell" or (evt.protocol or "") == "shell":
                self._ingest_shell_event(evt, ts, sys_node)
                continue

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
                
    def _ingest_shell_event(self, evt, ts: str, sys_node: int):
        """Analysis Lab sandbox: a green SHELL SESSION node, commands chained in
        execution order, connection attempts as destination nodes."""
        sess = (evt.session_id or "adhoc")
        sess8 = sess[:8]
        shell_node = self._add_node(f"SHELL_{sess}", f"SHELL {sess8}", "#22c55e", "box", 26)
        self._add_edge(shell_node, sys_node, "sandbox_on")

        cmd = (evt.commands or "").strip()
        etype = (evt.event_type or "")

        if etype == "shell.connection.attempt" or cmd.startswith("connect"):
            dst = cmd.replace("connect (external)", "").replace("connect", "").strip() or (
                f"{evt.attacker_ip}:{evt.target_port}"
            )
            dst_node = self._add_node(f"DST_{dst}", dst, "#ff0055", "triangle", 16)
            self._add_edge(shell_node, dst_node, "connects")
            self.terminal_logs.append({
                "time": ts, "user": "sandbox", "userColor": "#22c55e",
                "msg": f"[conn] outbound attempt → {dst} (blocked, no egress)",
            })
            self.mitre_map["c2"].add("T1071")
            return

        if not cmd:
            return

        step = self._shell_prev.get(sess, {}).get("n", 0) + 1
        cmd_short = cmd.split(" ")[0][:14] or cmd[:14]
        cmd_node = self._add_node(f"SCMD_{sess}_{step}", f"{step}. {cmd_short}", "#ffee00", "square", 15)
        prev = self._shell_prev.get(sess)
        if prev:
            self._add_edge(prev["node"], cmd_node, f"then")
        else:
            self._add_edge(shell_node, cmd_node, "runs")
        self._shell_prev[sess] = {"node": cmd_node, "n": step}

        self.terminal_logs.append({
            "time": ts, "user": f"analyst@{sess8}", "userColor": "#22c55e", "msg": cmd,
        })

        low = cmd.lower()
        self.mitre_map["execution"].add("T1059")
        if "powershell" in low:
            self.mitre_map["execution"].add("T1059.001")
        if any(k in low for k in ("wget", "curl", "tftp", "certutil")):
            self.mitre_map["c2"].add("T1105")
        if any(k in low for k in ("base64", " xor", "gpg", "openssl enc")):
            self.mitre_map["defense_evasion"].add("T1027")
        if any(k in low for k in ("nmap", "masscan", "ping -c", "ss -", "netstat")):
            self.mitre_map["initial_access"].add("T1046")
        if any(k in low for k in ("cat /etc/passwd", "whoami", "id;", "uname", "cat /etc/shadow")):
            self.mitre_map["priv_esc"].add("T1078")
        if any(k in low for k in ("crontab", "systemctl enable", ".bashrc", "authorized_keys")):
            self.mitre_map["persistence"].add("T1098")

    def analyze_behavior(self) -> Dict[str, Any]:
        """
        Real graph metrics + evidence-based activity classification.
        Kill-chain stage is the furthest tactic actually observed in telemetry.
        """
        node_degrees = {n["id"]: 0 for n in self.nodes}
        for edge in self.edges:
            node_degrees[edge["from"]] += 1
            node_degrees[edge["to"]] += 1
        max_degree = max(node_degrees.values()) if node_degrees else 0
        edge_count = len(self.edges)

        # real centrality / structure via networkx
        betweenness_top = 0.0
        components = 0
        try:
            import networkx as nx
            g = nx.Graph()
            g.add_nodes_from(node_degrees.keys())
            g.add_edges_from((e["from"], e["to"]) for e in self.edges)
            if g.number_of_nodes() >= 3:
                bc = nx.betweenness_centrality(g)
                betweenness_top = round(max(bc.values()) if bc else 0.0, 3)
            components = nx.number_connected_components(g) if g.number_of_nodes() else 0
        except Exception:
            pass

        # measured signals
        cmd_events = [e for e in self.events if e.commands]
        total_cmds = sum(len((e.commands or "").splitlines()) or (1 if e.commands else 0) for e in cmd_events)
        sessions = {e.session_id for e in self.events if e.session_id}
        ports = {e.target_port for e in self.events if e.target_port}
        span_s = 0.0
        ts = [e.timestamp for e in self.events if e.timestamp]
        if len(ts) >= 2:
            span_s = (max(ts) - min(ts)).total_seconds()
        rate = (len(self.events) / span_s) if span_s > 0 else 0.0

        observed_tactics = {k for k, v in self.mitre_map.items() if v}
        has_execution = bool(self.mitre_map["execution"])
        has_c2 = bool(self.mitre_map["c2"])
        has_persist = bool(self.mitre_map["persistence"])
        has_obf = bool(self.mitre_map["defense_evasion"])
        interactive = total_cmds >= 3 and len(sessions) >= 1

        # evidence-based classification (no named groups)
        if not self.events:
            style, confidence = "No activity", 0.0
        elif len(ports) >= 5 and total_cmds == 0:
            style = "Automated port scanner"
            confidence = min(95.0, 50 + len(ports) * 4)
        elif total_cmds == 0 and len(self.events) > 3:
            style = "Credential-stuffing / login bruteforce bot"
            confidence = min(90.0, 45 + len(self.events))
        elif interactive and (has_persist or has_obf or has_c2):
            style = "Hands-on-keyboard post-exploitation"
            confidence = min(97.0, 60 + total_cmds * 2 + 10 * len(observed_tactics))
        elif interactive and has_execution:
            style = "Interactive operator (early-stage)"
            confidence = min(88.0, 50 + total_cmds * 3)
        elif rate > 2.0:
            style = "High-rate automated tool"
            confidence = min(85.0, 40 + rate * 5)
        else:
            style = "Opportunistic automated probe"
            confidence = min(80.0, 40 + len(self.events) * 2)

        # kill-chain stage = furthest tactic actually seen
        KC = [("recon", ["initial_access"]), ("weaponize", []), ("deliver", ["c2"]),
              ("exploit", ["execution", "priv_esc"]), ("install", ["persistence"]),
              ("c2", ["c2"]), ("actions", ["impact", "defense_evasion"])]
        stages = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
                  "Installation", "Command & Control", "Actions on Objectives"]
        kc_active_idx = 0
        if self.mitre_map["initial_access"]:
            kc_active_idx = 0
        if has_execution or self.mitre_map["priv_esc"]:
            kc_active_idx = max(kc_active_idx, 3)
        if has_persist:
            kc_active_idx = max(kc_active_idx, 4)
        if has_c2:
            kc_active_idx = max(kc_active_idx, 5)
        if self.mitre_map["impact"] or has_obf:
            kc_active_idx = max(kc_active_idx, 6)
        kc_percent = round(100 * (kc_active_idx + 1) / len(stages))

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
                "name": style,
                "confidence": round(confidence, 1),
                "traits": {
                    "Interactivity": "INTERACTIVE" if interactive else "AUTOMATED",
                    "Commands executed": str(total_cmds),
                    "Ports touched": str(len(ports)),
                    "Tactics observed": str(len(observed_tactics)),
                    "Event rate": f"{rate:.2f}/s" if rate else "n/a",
                },
            },
            "killchain": {
                "stage_name": f"{stages[kc_active_idx]} (observed)",
                "percent": kc_percent,
                "active_index": kc_active_idx,
            },
            "graph_metrics": {
                "nodes": len(self.nodes),
                "edges": edge_count,
                "max_degree": max_degree,
                "top_betweenness": betweenness_top,
                "components": components,
            },
            "graph": {"nodes": self.nodes, "edges": self.edges},
            "mitre": mitre_flat,
            "logs": self.terminal_logs,
        }
