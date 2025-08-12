# AWS GuardDuty Real-Time Alerts with EventBridge & SNS

## Overview
This project demonstrates how to configure **Amazon GuardDuty** to send real-time security finding alerts via **Amazon EventBridge** and **Amazon SNS**.  
The goal was to automatically detect GuardDuty findings (e.g., suspicious activity, potential security threats) and send instant notifications to an email address.

---

## Architecture
1. **Amazon GuardDuty** – Detects threats and suspicious activity in the AWS environment.
2. **Amazon EventBridge** – Listens for GuardDuty findings and triggers alerts.
3. **Amazon SNS (Simple Notification Service)** – Delivers email notifications.
4. **CloudWatch Metrics (optional)** – Monitors SNS delivery success/failure.

**Flow:**

---

## Steps Implemented

### 1. Enable GuardDuty
- Activated GuardDuty in the target AWS region (**us-east-1**).
- Confirmed GuardDuty is monitoring AWS accounts for suspicious activity.

### 2. Create an SNS Topic
- **Topic Name:** `GuardDuty`
- Added email subscription to the topic.
- Verified the subscription via email confirmation.

### 3. Create an EventBridge Rule
- **Event Pattern** (high severity findings ≥ 7):
    ```json
    {
      "source": ["aws.guardduty"],
      "detail-type": ["GuardDuty Finding"],
      "detail": {
        "severity": [
          { "numeric": [">=", 7] }
        ]
      }
    }
    ```
- Target: SNS Topic (`GuardDuty`).
- Purpose: Automatically forward GuardDuty findings to SNS.

### 4. Test with Sample Findings
- Generated GuardDuty sample findings via AWS CLI:
    ```bash
    aws guardduty create-sample-findings \
      --detector-id <DETECTOR_ID> \
      --region us-east-1
    ```
- Verified:
    - EventBridge rule triggered.
    - SNS email notifications received.
    - Findings appeared in GuardDuty console.

---

## Key AWS Services Used
- **Amazon GuardDuty** – Threat detection.
- **Amazon EventBridge** – Event routing and filtering.
- **Amazon SNS** – Message delivery.
- **Amazon CloudWatch** – Monitoring & alerting.

---

## Security Considerations
- Ensured SNS topic policy allows `events.amazonaws.com` to publish.
- Limited EventBridge rule to GuardDuty findings only.
- Used severity filtering to reduce noise.

---

## Outcome
- Fully automated GuardDuty alert pipeline.
- Immediate email alerts for high-severity security findings.
- Configurable architecture for multiple recipients or integrations (Slack, Lambda, etc.).

