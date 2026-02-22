
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict

class AIEngine:
    def __init__(self):
        self.rules = {
            "SQL_INJECTION": r"(?i)(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|--|#|/\*|HAVING|EXEC)",
            "XSS": r"(?i)(<script|javascript:|onload=|onerror=|alert\(|document\.cookie)",
            "PATH_TRAVERSAL": r"(?i)(\.\./|\.\.\\|/etc/passwd|c:\\windows)",
            "COMMAND_INJECTION": r"(?i)(;|\||`|\$\(|\&\&)",
            "SSH_BRUTE_FORCE": r"(?i)(Failed password|Invalid user|authentication failure)"
        }
        # In-memory history: {ip: [{"timestamp": datetime, "port": int, "payload": str}]}
        self.history = defaultdict(list)
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 5     # Distinct ports
        self.PORT_SCAN_WINDOW = 10       # Seconds
        self.DDOS_THRESHOLD = 20         # Requests
        self.DDOS_WINDOW = 5             # Seconds
        self.BRUTE_FORCE_THRESHOLD = 5   # Failed attempts
        self.BRUTE_FORCE_WINDOW = 60     # Seconds

    def _cleanup_history(self, ip: str):
        """Remove events older than the largest window (60s)"""
        now = datetime.now()
        # Keep only events within the last 60 seconds
        self.history[ip] = [event for event in self.history[ip] 
                          if (now - event["timestamp"]).total_seconds() < self.BRUTE_FORCE_WINDOW]
        
        if not self.history[ip]:
            del self.history[ip]

    def _detect_behavioral(self, ip: str) -> Optional[str]:
        """Check for behavioral patterns based on history"""
        if ip not in self.history:
            return None
            
        events = self.history[ip]
        if not events:
            return None

        now = datetime.now()
        
        # 1. DDoS Detection
        recent_requests = [e for e in events if (now - e["timestamp"]).total_seconds() < self.DDOS_WINDOW]
        if len(recent_requests) > self.DDOS_THRESHOLD:
            return "DDOS"

        # 2. Port Scan Detection
        scan_window_events = [e for e in events if (now - e["timestamp"]).total_seconds() < self.PORT_SCAN_WINDOW]
        distinct_ports = {e["port"] for e in scan_window_events if e["port"]}
        if len(distinct_ports) > self.PORT_SCAN_THRESHOLD:
            return "NMAP_SCAN"

        # 3. Brute Force Detection (Generic)
        # Check for repeated similar payloads or specifically failed auth patterns
        auth_failures = [e for e in events 
                        if (now - e["timestamp"]).total_seconds() < self.BRUTE_FORCE_WINDOW
                        and re.search(self.rules["SSH_BRUTE_FORCE"], e["payload"])]
        
        if len(auth_failures) > self.BRUTE_FORCE_THRESHOLD:
             return "BRUTE_FORCE"
             
        return None

    def analyze_log(self, payload: str, ip: str = None, port: int = None):
        """
        Analyzes a raw log entry and returns the identified attack type and severity.
        Supports stateful analysis if IP is provided.
        """
        detected_attacks = []
        severity = "LOW"
        
        # 1. Signature-based Analysis
        for attack_name, pattern in self.rules.items():
            if re.search(pattern, payload):
                detected_attacks.append(attack_name)
                if attack_name in ["SQL_INJECTION", "COMMAND_INJECTION"]:
                    severity = "CRITICAL"
                elif attack_name in ["XSS", "SSH_BRUTE_FORCE"]:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

        # 2. Stateful Analysis
        if ip:
            # Update history
            self.history[ip].append({
                "timestamp": datetime.now(),
                "port": port,
                "payload": payload
            })
            self._cleanup_history(ip)
            
            behavioral_attack = self._detect_behavioral(ip)
            if behavioral_attack:
                detected_attacks.append(behavioral_attack)
                if behavioral_attack == "DDOS":
                    severity = "CRITICAL"
                elif behavioral_attack == "NMAP_SCAN":
                    severity = "HIGH"
                elif behavioral_attack == "BRUTE_FORCE":
                    severity = "HIGH"

        if not detected_attacks:
            return {"type": "NORMAL", "severity": "INFO", "mitre": None}
        
        # Prioritize most severe attack
        # If multiple, take the last one added (behavioral often overrides signature)
        primary_attack = detected_attacks[-1] 
        
        from .mitre_map import map_attack_to_mitre
        mitre_info = map_attack_to_mitre(primary_attack)

        return {
            "type": primary_attack,
            "severity": severity,
            "mitre": mitre_info
        }
