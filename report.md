# Shadow Trust - SentinelHive: Comprehensive Project Report

## 1. Executive Overview

**Shadow Trust - SentinelHive** is a next-generation Threat Intelligence and SOC (Security Operations Center) Honeynet Platform designed with a map-first, intelligence-driven approach. It blends a hybrid edge-to-cloud architecture with real-time global threat monitoring, malicious payload analysis, and automated attack classification.

This report comprehensively details the features currently developed, the planned infrastructure integrations, the comprehensive HTML dashboard tab system, and the underlying AWS data flow architecture detailing the utilization of honeypots, EC2 instances, S3 storage, and AI processing layers.

---

## 2. AWS Architecture & Data Flow System

Based on the strategic architecture of the environment, SentinelHive leverages Amazon Web Services (AWS) extensively for its backend compute, storage, data collection, and threat telemetry workflows.

### 2.1 Identity and Access Management (IAM)
The connection between the Project Dashboard and AWS is established via strict **IAM User & Security Policies**, utilizing dedicated **Security Groups and Access Keys**. This enforces the principle of least privilege, ensuring the platform only accesses required VPC constraints and compute resources.

### 2.2 EC2 Instances & Infrastructure Strategy
The SOC relies on multiple isolated EC2 deployments within defined VPC boundaries (combining **Private and Public Subnets** and secure **VPN tunnels** for secure admin access):
*   **Honeypot Server (Ubuntu EC2):** Formats the core deception layer. It is configured as a CLI-based Ubuntu Server intentionally left vulnerable with many open ports and internal weak security to entice attackers.
*   **Decoy Nodes:** Includes nodes like **"xiurg"**, **"medusa"** (Windows target environment), and **"Madrox"** (Virtual environment/GUI OS system) representing various sector surfaces (Education, Defence, Finance).

### 2.3 The Honeypot Ecosystem
The active Ubuntu Honeypot server runs a trio of specialized deception daemons:
1.  **Cowrie:** An SSH / Telnet interaction honeypot designed to log brute-force attempts and record attacker shell interactions.
2.  **Dionaea:** A malware capture honeypot designed to trap malicious payloads and binaries sent over various protocols.
3.  **Honeytrap:** A low-interaction network honeypot observing network traffic and connection requests across multiple ports.

### 2.4 Data Telemetry & Flow Lifecycle
1.  **Collection:** Logs are actively collected from Cowrie, Dionaea, and Honeytrap.
2.  **Storage Sync (S3):** A specialized Python script continuously synchronizes this raw telemetry data from all 3 honeypots directly into a secure **S3 Storage Bucket**.
3.  **Extraction (Boto3):** Data is sequentially pulled and structured using a SQL/Python module via the **Boto3 API**, migrating it from S3 into an edge **SQLite** database.
4.  **AI Layer #1 (Categorization):** The raw SQLite data passes through the first Artificial Intelligence node, which categorizes, parses, and formats the data strictly into the metrics needed for the Project Dashboard display.
5.  **Dashboard Ingestion:** The categorized intelligence arrives at the Project Dashboard for visual monitoring.
6.  **AI Layer #2 (Behavioral Profiling):** Dashboard intelligence is fed into a deeper, secondary AI layer. Using all historical data, it defines the behavioral profiles of attackers and creates threat forecasts for the system.
7.  **Database Storage & Auth:** Advanced profiles and final system states are written to the core **Database** (Supabase/PostgreSQL), which handles continuous overarching **Authentication & Authorization** for operators accessing the platform.

---

## 3. Current Completed Features (What Has Been Made)

The current state of SentinelHive reflects a highly functional, visually stunning, and API-connected SOC environment.

1.  **Map-First Intelligence Dashboard:** A deeply interactive tactical command center featuring a global world map, live interception statistics, and threat origin tracking.
2.  **Honeypot Node Management:** Allows administrators to orchestrate node deployments natively from the UI (e.g., stopping/starting mock services mapped to different geographic sectors).
3.  **AWS Orchestrator API Backend:** A fully realized Python FastAPI backend utilizing `boto3`. Endpoints handle:
    *   STS Caller Identity Validation (`/api/v1/aws/test`).
    *   EC2 provisioning and termination logic for dynamically deploying decoy instances (`/api/v1/vm/launch`).
    *   Comprehensive AWS diagnostic debugging checks spanning S3 buckets and IAM roles.
4.  **Role-Based Access Control (RBAC):** Integrated UI clearance checks categorizing users into Tier 1 (Operative), Tier 2 (Specialist), and Tier 3 (Overseer/Admin), restricting access to sensitive tabs.
5.  **Malware & APK Analysis Feeds:** Dashboards designed to display live feeds of caught malware, Unique APK packagers parsed, and critical vulnerability counts.
6.  **Immersive "Lockdown" UI Mechanics:** Includes physical-looking blast shutter animations (`shutter-top`, `shutter-bottom`), heartbeat warning pulses, and secure restricted access modalities for aesthetic SOC realism.
7.  **Dynamic Frontend API Linking:** Connected vanilla JavaScript utilities bridging frontend views seamlessly to the backend for metrics, stats, and real-time history fetching.

---

## 4. Planned & Upcoming Features (What Is Willing To Be Made)

1.  **VPC / Subnet Isolation Logic Extension:** Full automated terraform-like provisioning from the UI to isolate spawned mock-nodes dynamically into locked-down Private Subnets vs Public-facing honeypot clusters. VPN tunneling integrations for secure inspector access.
2.  **AI Layer Integration Expansion:** Physically connecting the backend Machine Learning scripts to satisfy the "AI Layer #1" (Categorization) and "AI Layer #2" (Forecasting) mechanisms described in the architecture flow, allowing predictive analytics on the `behavior.html` page.
3.  **Advanced Attack Simulations:** Activating the mock payloads mapped in the `simulation.html` interfaces to execute safe, internal Red Team tests against the `Madrox` and `medusa` honeypots.
4.  **Fully Functional Unified Database:** Bridging edge node SQLite databases asynchronously with the centralized Supabase PostgreSQL instance via background workers seamlessly without data loss.

---

## 5. Detailed Breakdown of HTML Tabs & Interface Pages

The application boasts a massive array of interconnected HTML pages categorized by domain functional areas.

### Command Center
*   **`dashboard.html`**: The central Tactical Overview. Features an interactive global threat map (Leaflet), animated radar sweeps, live attack traffic volume charts (Chart.js), an APK analysis feed, and micro-metrics for system uptime, network flow, and AI engine status.
*   **`events.html`**: The Event Stream log. Displays an ongoing list of parsed telemetry from the honeypots in a terminal-like table view.

### Grid Monitoring
*   **`nodes.html`**: The Honeypot Nodes manager. It displays active node deployments against a visual "Server Rack" UI (showing 42U rack slots with blinking LED representation). Users can deploy, start, and stop VM node services mapped to sectors (e.g., EDU-01, DEF-09).
*   **`sectors.html`**: The Sector Monitors view. Groups deployed infrastructure into industry specifics (Education, Defence, Commerce, Finance) showing localized threat intelligence and incident metrics per sector.
*   **`geo.html`**: Geo Intelligence. A deeper dive into global IP attributions, ASN tracking, and country-based origin targeting.

### Intelligence
*   **`mitre.html`**: The MITRE ATT&CK Matrix. Mapped interface showing observed attacker behaviors categorized by MITRE enterprise tactics (Initial Access, Execution, Persistence, etc.).
*   **`graphs.html`**: Attack Analytics. Detailed historical representations of attack volumes and payload distribution mapped over time.
*   **`credentials.html`**: Credentials Vault. Stores compromised or attempted usernames, passwords, and SSH keys thrown by brute-force attackers across the Cowrie honeypots.
*   **`behavior.html`**: Behavior Profiling. Will host the visual output of **AI Layer #2**, detailing attacker tooling preferences, command sequences, and future intent forecasts.
*   **`simulation.html`**: Attack Simulation. An administrative interface allowing blue teams to trigger synthetic attacks (like DDoS, SQLi, or Brute-Force) against deployed honeypots to test alerting pipelines.

### Tools Suite
*   **`malware.html`**: Binary Analysis & Malware Sandbox. Focuses on payloads caught by Dionaea, detailing hashes (MD5/SHA256) and malware types.
*   **`urlscan.html`**: URL Scanner. Allows operators to manually scan suspicious domains for threats and phish-kit indicators.
*   **`apk.html`**: APK Inspector. Specialized mobile app analysis tool calculating security scores and unique package behaviors.
*   **`vm_lab.html`**: Virtual Lab. Secure web-based interactive proxy (like Guacamole connection) to safely interact with infected VMs without exposing operator machines.

### System Configuration
*   **`admin.html` / `admin_login.html`**: Administrative interfaces for Overseer privileges and overarching system locks.
*   **`config.html`**: Global SOC Configuration settings.
*   **`profile.html`**: Officer Profile. Manages operator credentials, JWT token states, and UI preferences.
*   **`aws_connection.html`**: Dedicated interface for inputting IAM Access Keys to bridge the platform into the overarching Amazon Web Services API for deploying and monitoring EC2s.

---
**End of Document**
