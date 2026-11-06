# SOAR Automated Playbook: playbook-incident-auto-triage

## Overview
This playbook implements automated incident enrichment and triage using **Azure Logic Apps** (Consumption / Multi-tenant tier) integrated directly with **Microsoft Sentinel**.

## Architecture & Workflow Pipeline
```
[ High-Severity Sentinel Incident Created ]
                    │
                    ▼ (Trigger)
   [ Microsoft Sentinel incident (preview) ]
                    │
                    ▼ (Dynamic ARM ID Binding)
      [ Add comment to incident (V3) ]
                    │
                    ▼
[ Incident Timeline Updated with Triage Note ]
```

## Configuration Details
- **Logic App Name:** `playbook-incident-auto-triage`
- **Region:** `East Asia`
- **Plan Type:** Consumption (serverless, pay-per-operation = $0.00 for lab)
- **Trigger:** `When a response to an incident is triggered` / `Microsoft Sentinel incident`
- **Action:** `Add comment to incident (V3)`
- **Dynamic Content:** `Incident ARM ID`
- **Automated Commentary Injected:**
  ```text
  [SOAR AUTOMATED RESPONSE]
  Playbook executed successfully.
  Action taken: Incident enriched and triaged automatically.
  Recommended SOC actions: Review attacker IP, inspect SAM accounts on vm-honeypot, and enforce network isolation if required.
  ```

## Evidence
- Screenshot: `../screenshots/23_logic_app_soar_playbook_designer.png`
