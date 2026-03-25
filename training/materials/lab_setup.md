# 🔬 Lab Environment Setup Guide

> Technical guide for setting up NAIL training lab environments.

## Architecture

```
┌──────────────────────────────────────────┐
│           Lab Controller (Host)           │
│  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Agent 1   │  │ Agent 2   │  │ Agent 3│ │
│  │ (Chatbot) │  │ (Code)    │  │ (RAG)  │ │
│  └──────────┘  └──────────┘  └────────┘ │
│  ┌──────────┐  ┌──────────┐             │
│  │ Monitor   │  │ Scoring   │             │
│  │ Dashboard │  │ Engine    │             │
│  └──────────┘  └──────────┘             │
└──────────────────────────────────────────┘
```

## Requirements

### Hardware (per student station)
- CPU: 4+ cores
- RAM: 16 GB minimum
- Storage: 50 GB free
- Network: 10 Mbps+

### Software
- Docker Desktop 24+ or Podman 4+
- Python 3.11+
- Git
- Web browser (Chrome/Firefox)
- Terminal emulator

## Quick Setup

```bash
# Clone lab environment
git clone https://github.com/NAIL-INSTITUTE-FOR-AGENTIC-SECURITY/nail-training-labs.git
cd nail-training-labs

# Build and start all services
docker compose up -d

# Verify all services are running
docker compose ps

# Access points:
# Lab Dashboard:  http://localhost:8080
# Agent 1 (Chat): http://localhost:8081
# Agent 2 (Code): http://localhost:8082
# Agent 3 (RAG):  http://localhost:8083
# Monitor:        http://localhost:8084
```

## Lab Scenarios

### Track 1 Labs

| Lab | Agents | Vulnerabilities | Difficulty |
|-----|--------|-----------------|:----------:|
| T1-L1: Customer Chatbot | 1 | Prompt injection, output manipulation | ⭐ |
| T1-L2: Code Assistant | 1 | Tool misuse, privilege escalation | ⭐⭐ |
| T1-L3: Research Agent | 1 | Memory poisoning, data exfiltration | ⭐⭐ |

### Track 2 Labs

| Lab | Agents | Vulnerabilities | Difficulty |
|-----|--------|-----------------|:----------:|
| T2-L1: Multi-Agent Red Team | 4 | Cross-agent attacks | ⭐⭐⭐ |
| T2-L2: Production Assessment | 3 | All categories | ⭐⭐⭐⭐ |
| T2-L3: Capstone | 5+ | Full assessment | ⭐⭐⭐⭐⭐ |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Docker won't start | Ensure virtualisation enabled in BIOS |
| Port conflict | Change ports in `.env` file |
| Agent unresponsive | `docker compose restart agent-X` |
| Out of memory | Reduce agent count, increase swap |
| Network timeout | Check firewall rules, use offline mode |

## Reset

```bash
# Reset all labs to initial state
docker compose down -v
docker compose up -d

# Reset specific lab
docker compose restart agent-1
```

## Offline Mode

For venues without reliable internet:

```bash
# Pre-pull all images (run before event)
docker compose pull

# Save images for offline use
docker save -o nail-labs.tar $(docker compose config --images)

# Load on offline machines
docker load -i nail-labs.tar
```
