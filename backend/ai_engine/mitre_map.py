
def map_attack_to_mitre(attack_type: str):
    mapping = {
        "SQL_INJECTION": {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access"
        },
        "XSS": {
            "id": "T1059.007",
            "name": "Command and Scripting Interpreter: JavaScript",
            "tactic": "Execution"
        },
        "PATH_TRAVERSAL": {
            "id": "T1006",
            "name": "Direct Volume Access", # Approximation
            "tactic": "Defense Evasion"
        },
        "COMMAND_INJECTION": {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        },
        "SSH_BRUTE_FORCE": {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access"
        },
        "NMAP_SCAN": {
            "id": "T1595.001",
            "name": "Active Scanning: Scanning IP Blocks",
            "tactic": "Reconnaissance"
        },
        "DDOS": {
            "id": "T1498",
            "name": "Network Denial of Service",
            "tactic": "Impact"
        },
        "BRUTE_FORCE": {
            "id": "T1110",
            "name": "Brute Force",
            "tactic": "Credential Access"
        }
    }
    return mapping.get(attack_type, None)
