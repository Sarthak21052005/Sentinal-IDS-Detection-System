# SENTINAL – AI Intrusion Defense System

**Phase 1: Network Intrusion Detection MVP**

SENTINAL is a network intrusion detection and defense system developed as a major project for B.Tech Computer Science and Engineering (Cyber Security).

The objective of SENTINAL is to monitor network traffic, identify suspicious network activities, generate security alerts, classify threats, and demonstrate controlled intrusion prevention.

> **Current development phase:** Phase 1 – Core IDS implementation  
> **Project status:** Active development  
> **Primary runtime:** Ubuntu Linux VM  
> **Development environment:** Windows 11  
> **Attack simulation environment:** Kali Linux VM

---

## 1. Project Overview

SENTINAL is designed to monitor network traffic and detect potentially malicious activities through packet inspection and rule-based detection.

The Phase 1 implementation focuses on building a working network intrusion detection foundation before introducing advanced AI/ML capabilities.

### Phase 1 Features

| Feature | Description | Status |
|---|---|---|
| Live packet capture | Capture network packets using Scapy | Implemented and tested |
| Packet processing | Extract IP, MAC, protocol, port and packet metadata | Implemented; basic tests passed |
| ARP spoofing detection | Detect conflicting IP-to-MAC mappings | Pending |
| DNS anomaly detection | Identify suspicious DNS behavior | Pending |
| Rule-based signature detection | Detect suspicious traffic using predefined rules | Pending |
| Threat scoring | Assign threat scores and severity levels | Pending |
| FastAPI backend | Provide REST APIs for system operations | Implemented |
| SQLite event logging | Store and retrieve security events | Implemented and tested |
| React security dashboard | Display alerts, statistics and network events | Pending |
| Basic IPS demonstration | Demonstrate controlled traffic blocking in the lab | Pending |

**Scope note:** AI/ML-based detection is intentionally excluded from Phase 1. It may be introduced in a subsequent development phase.

---

## 2. Technology Stack

| Component | Technology |
|---|---|
| Operating system (development) | Windows 11 |
| Runtime environment | Ubuntu Linux |
| Attack simulation | Kali Linux |
| Programming language | Python |
| Packet capture | Scapy |
| Backend framework | FastAPI |
| API server | Uvicorn |
| ORM | SQLAlchemy |
| Database | SQLite |
| Frontend target | React.js |
| Styling target | Tailwind CSS |
| Real-time communication target | WebSockets |
| Version control | Git and GitHub |
| Virtualization | Oracle VirtualBox |

---

## 3. System Architecture

SENTINAL currently uses a two-VM isolated network lab.

```text
                 WINDOWS 11 HOST
              Development and Management
                       |
                 Git / GitHub
                       |
             -----------------------
             |                     |
        Ubuntu VM               Kali VM
        IDS Runtime             Attacker
             |                     |
             |                 Test Traffic
             |                     |
             +------ IDS-LAB ------+
                       |
                  Scapy Capture
                       |
                Packet Processor
                       |
              Detection Engine
                       |
                Threat Scoring
                       |
                 FastAPI API
                       |
                  SQLite DB
                       |
               React Dashboard
                 (Planned)
```

### Responsibilities

**Windows Host**
- Source code editing using VS Code.
- Git and GitHub operations.
- React frontend development.
- Browser-based API testing.

**Ubuntu VM**
- Runs the SENTINAL backend.
- Runs Scapy packet capture.
- Runs packet processing and detection modules.
- Stores security events in SQLite.

**Kali Linux VM**
- Generates controlled network traffic.
- Used for testing packet capture and future detection mechanisms.

---

## 4. Virtual Lab Configuration

The project uses VirtualBox with two virtual machines.

### Virtual Machines

| VM | Role |
|---|---|
| IDS-UBUNTU-TARGET | SENTINAL runtime and monitoring |
| IDS-KALI-ATTACKER | Controlled attack and traffic simulation |

### Network Configuration

Both VMs have two network adapters:

- Adapter 1: NAT for Internet connectivity.
- Adapter 2: Internal Network named `IDS-LAB`.

The internal network is isolated from the external network.

| Machine | Interface | IP Address |
|---|---|---|
| Kali | Internal network interface | `10.10.10.10/24` |
| Ubuntu | Internal network interface | `10.10.10.20/24` |

The internal network uses the subnet:

```text
10.10.10.0/24
```

There is no gateway configured on the internal IDS-LAB network.

Network connectivity and persistence after VM restart have been verified.

### Important Security Restriction

All attack simulations and IPS experiments must be performed exclusively inside the isolated IDS-LAB network.

Do not perform spoofing or blocking demonstrations on public, college, home, or production networks.

---

## 5. Repository Structure

Current and planned repository organization:

```text
Sentinal-IDS-Detection-System/
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── requirements.txt
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── schemas.py
│   │
│   └── database/
│       ├── __init__.py
│       ├── database.py
│       └── models.py
│
├── detection-engine/
│   ├── packet_capture.py
│   ├── packet_processor.py
│   └── __init__.py
│
├── ips/
│
├── frontend/
│
├── tests/
│
├── documentation/
│
├── start_backend.sh
├── start_capture.sh
├── start_sentinal.sh
│
├── .gitignore
└── README.md
```

Some directories are reserved for upcoming implementation modules.

The `detection-engine` directory intentionally retains its hyphenated name. Its Python files are currently executed directly rather than imported as a conventional Python package.

---

## 6. Development Environment Setup

### 6.1 Clone the Repository

On the Ubuntu VM:

```bash
git clone https://github.com/Sarthak21052005/Sentinal-IDS-Detection-System.git
cd Sentinal-IDS-Detection-System
```

If the repository is already cloned, do not clone it again. Pull the latest changes instead.

### 6.2 Install Python Dependencies

```bash
sudo apt update

sudo apt install -y python3 python3-venv python3-pip git
```

### 6.3 Create the Virtual Environment

From the project root:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

### 6.4 Install Project Requirements

```bash
python -m pip install --upgrade pip

pip install -r backend/requirements.txt
```

Current backend requirements:

```text
fastapi
uvicorn[standard]
scapy
sqlalchemy
```

---

## 7. Backend Implementation

The backend uses FastAPI and SQLAlchemy.

### Implemented API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Root endpoint |
| GET | `/api/health` | Check backend health |
| POST | `/api/events` | Insert a security event |
| GET | `/api/events` | Retrieve security events |

### Start the Backend Manually

From the repository root:

```bash
source .venv/bin/activate

python -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload
```

Swagger documentation:

```text
http://10.10.10.20:8000/docs
```

Health endpoint:

```text
http://10.10.10.20:8000/api/health
```

### Example Health Response

```json
{
    "status": "healthy",
    "system": "SENTINAL",
    "backend": "FastAPI"
}
```

---

## 8. SQLite Database Implementation

SENTINAL uses SQLite with SQLAlchemy.

The database is stored locally on the Ubuntu VM.

Database location:

```text
backend/sentinal.db
```

The database file is generated automatically when the backend initializes its tables.

### Security Event Table

The current `security_events` model contains:

| Field | Purpose |
|---|---|
| id | Unique event identifier |
| timestamp | Event creation time |
| event_type | Type of detected event |
| source_ip | Source IP address |
| destination_ip | Destination IP address |
| protocol | Network protocol |
| threat_score | Rule-based threat score |
| severity | LOW, MEDIUM or HIGH |
| detection_method | Detection method or rule |
| description | Event description |
| response_action | Action taken or requested |
| response_status | Response execution status |

### Test Event Insertion

Open:

```text
http://10.10.10.20:8000/docs
```

Use `POST /api/events` with:

```json
{
    "event_type": "ARP_SPOOFING",
    "source_ip": "10.10.10.10",
    "destination_ip": "10.10.10.20",
    "protocol": "ARP",
    "threat_score": 70,
    "severity": "HIGH",
    "detection_method": "RULE_BASED",
    "description": "Conflicting IP-MAC mapping detected",
    "response_action": "ALERT",
    "response_status": "NOT_APPLICABLE"
}
```

Retrieve events using:

```text
GET /api/events
```

Both insertion and retrieval have been tested successfully with sample events.

**Note:** These initial events were manually submitted through Swagger. They are not yet automatically generated by the detection engine.

### Database Storage Policy

The SQLite database must not be committed to GitHub.

The `.gitignore` file excludes:

```gitignore
*.db
*.sqlite3
```

The Ubuntu VM remains the primary runtime data store.

---

## 9. Scapy Live Packet Capture

Live packet capture is implemented using Scapy.

File:

```text
detection-engine/packet_capture.py
```

The capture module:
- Monitors the Ubuntu internal interface `enp0s8`.
- Captures live packets.
- Passes packets to the packet processor.
- Displays extracted packet metadata.
- Supports a configurable packet count.
- Runs continuously when no count is specified.

### Start Packet Capture

From the project root:

```bash
sudo .venv/bin/python \
    detection-engine/packet_capture.py \
    --interface enp0s8
```

Capture a limited number of packets:

```bash
sudo .venv/bin/python \
    detection-engine/packet_capture.py \
    --interface enp0s8 \
    --count 20
```

Packet capture requires appropriate network capture privileges. The capture process is run with elevated privileges; the FastAPI backend should run as a normal user.

---

## 10. Packet Processing

File:

```text
detection-engine/packet_processor.py
```

The packet processor extracts and normalizes:

- Timestamp.
- Source and destination MAC addresses.
- Source and destination IP addresses.
- Protocol.
- Source and destination ports when available.
- Packet size.
- ARP operation and address fields.
- DNS query information and response answers when available.

The output is a normalized Python dictionary.

### Verified Packet Capture Test

Kali generated ordinary ping traffic towards Ubuntu:

```bash
ping -c 5 10.10.10.20
```

Ubuntu successfully captured traffic from both machines.

Verified observations included:

- ARP requests.
- ARP replies.
- IP packets.
- Source and destination MAC extraction.
- Source and destination IP extraction.

The live capture test was successfully completed on 20 November 2026.

**Important:** Packet capture and metadata extraction are implemented. ARP spoofing detection and DNS anomaly classification are still pending.

---

## 11. Startup Scripts

Two separate Bash scripts are provided for convenience.

### Start FastAPI

File:

```text
start_backend.sh
```

Run:

```bash
chmod +x start_backend.sh
./start_backend.sh
```

This starts the FastAPI application on port 8000.

### Start Scapy Capture

File:

```text
start_capture.sh
```

Run:

```bash
chmod +x start_capture.sh
./start_capture.sh
```

This starts Scapy capture on `enp0s8`.

### Normal Startup Procedure

Use two separate Ubuntu terminals:

**Terminal 1:**

```bash
./start_backend.sh
```

**Terminal 2:**

```bash
./start_capture.sh
```

The user must authenticate with sudo when packet capture starts.

The older `start_sentinal.sh` launcher is retained as an experimental script and is not the recommended startup method.

---

## 12. Current Development Workflow

The project uses Windows for development and Ubuntu for runtime execution.

### Windows

1. Open the project in VS Code.
2. Modify source code.
3. Commit changes to the feature branch.
4. Push changes to GitHub.

### Ubuntu

1. Pull the latest changes.
2. Activate the Ubuntu virtual environment.
3. Run the backend.
4. Run packet capture.
5. Verify functionality.

Example Git workflow:

```bash
git status

git add .

git commit -m "Describe your changes"

git push origin feature/backend-foundation
```

Use `git status` before staging and make sure generated files, database files, virtual environments and secrets are not committed.

---

## 13. Git Branching Strategy

The repository uses:

- `main`: Stable integration branch.
- `feature/backend-foundation`: Backend and initial packet capture development branch.

Development should happen on feature branches.

After testing and review, changes should be merged into `main` through a GitHub Pull Request.

Avoid committing unfinished or untested code directly to `main`.

---

## 14. Phase 1 Remaining Work

The following implementation tasks remain.

### Detection Engine

- ARP IP-to-MAC baseline.
- ARP mapping conflict detection.
- DNS query and response correlation.
- DNS anomaly detection.
- Rule-based signature detection.
- Threat scoring and severity classification.

### Backend Integration

- Connect captured packet data to detection modules.
- Automatically create security events from detections.
- Add event statistics APIs.
- Add live event updates through WebSockets.

### IPS

- Implement a controlled and reversible blocking demonstration.
- Maintain an allowlist for safe lab operation.
- Log response actions and their results.
- Verify blocked traffic in the isolated lab.

### Frontend

- React dashboard.
- Overview statistics.
- Live monitoring.
- Security alerts.
- Event history.
- IPS response history.

### Testing and Documentation

- Unit tests for detection rules.
- Controlled ARP spoofing tests.
- Controlled DNS anomaly tests.
- End-to-end integration tests.
- Performance and false-positive evaluation.
- Final demonstration documentation.

---

## 15. Important Security and Development Rules

1. Perform attack simulations only on the isolated IDS-LAB network.
2. Never run automatic blocking on a public or production network.
3. Do not run the complete FastAPI backend as root.
4. Do not commit `.venv`, `node_modules`, database files or packet captures.
5. Do not treat an ARP mapping change or low DNS TTL alone as conclusive proof of an attack.
6. Keep detection, scoring, event logging and response modules separate.
7. Use consistent event schemas across all modules.
8. Keep `main` stable and integrate through feature branches.
9. Do not describe manually submitted test events as automatically detected threats.
10. Do not claim Phase 1 features are complete until they have been implemented and tested.

---

## 16. Current Project Milestone

As of 21 November 2026, the following components have been implemented and verified:

- VirtualBox isolated lab configuration.
- Kali-to-Ubuntu network connectivity.
- GitHub repository and feature branch workflow.
- FastAPI backend foundation.
- SQLite database initialization.
- Security event insertion and retrieval.
- Scapy live packet capture.
- Basic packet metadata extraction.
- Separate backend and packet capture startup scripts.

SENTINAL is now ready to progress from passive packet monitoring to active rule-based intrusion detection.

---

**Project:** SENTINAL – AI Intrusion Defense System  
**Institution:** Graphic Era Deemed to be University, Dehradun  
**Program:** B.Tech Computer Science and Engineering – Cyber Security  
**Project Phase:** Phase 1 – Core IDS Implementation

