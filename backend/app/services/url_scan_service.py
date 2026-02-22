import re
import random
from typing import Dict, Any

class URLScanService:
    @staticmethod
    def analyze_limit(url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential threats.
        Includes heuristic checks and simulated ML/Threat Intel.
        """
        
        score = 0
        findings = []
        
        # 1. Heuristic Checks
        if "@" in url:
             score += 30
             findings.append("Suspicious user info in URL (@ symbol)")
        
        if url.count('.') > 3:
             score += 20
             findings.append("Abnormal number of subdomains")
             
        if "http:" in url and "https:" not in url:
             score += 10
             findings.append("Unencrypted HTTP protocol")
             
        suspicious_keywords = ["login", "verify", "account", "update", "bank", "secure", "paypal", "crypto"]
        for kw in suspicious_keywords:
            if kw in url and "google.com" not in url: # varied whitelist for demo
                score += 15
                findings.append(f"Suspicious keyword found: {kw}")
                
        # 2. Simulated Threat Intel / ML Model
        # In a real app, this would query VirusTotal, Google Safe Browsing, or a trained BERT model
        # We simulate a "ML Prediction" based on length/entropy
        if len(url) > 50:
            score += 10
            findings.append("Unusually long URL length")
            
        # Random element for demo if it looks clean but we want to show 'AI' working
        # (Only if we haven't found much yet)
        if score < 20 and "malicious" in url:
             score = 90
             findings.append("Known malicious domain signature")

        # Normalize Score
        score = min(score, 100)
        
        risk_level = "SAFE"
        if score > 30: risk_level = "SUSPICIOUS"
        if score > 70: risk_level = "MALICIOUS"
        
        return {
            "url": url,
            "risk_score": score,
            "risk_level": risk_level,
            "findings": findings,
            "domain_age": f"{random.randint(1, 3650)} days", # Simulated
            "ip_address": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}", # Simulated
            "server_location": random.choice(["USA", "Russia", "China", "Germany", "Unknown"])
        }
