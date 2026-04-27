# PRACTICEHunt 02 — What Did They Leave Behind?

Section 02 of the LogN Pacific BEC investigation. With initial access confirmed, the focus shifts from *how* the attacker got in to *what they did once inside* — recon, persistence, and the fraudulent send. This section moves out of `SigninLogs` and into `CloudAppEvents`, the table that logs O365 data-plane activity (mailbox operations, rule creation, file access).

---

## Q09 — First Post-Auth Action

**Goal:** Identify the very first action the attacker performed after authenticating.

**Approach:** Switch tables to `CloudAppEvents` and filter on the same attacker IP (`205.147.16.190`) within the attack window. Sort ascending by timestamp and look at the first `ActionType`. Note: `CloudAppEvents` uses `Timestamp`, not `TimeGenerated` — a common gotcha when pivoting between tables.

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| project Timestamp, ActionType, AccountDisplayName, Application
| order by Timestamp asc
| take 10
```

The first event at `9:56:24 PM` is **`MailItemsAccessed`** — the attacker's first move inside Mark's mailbox was *reading*, not exfiltrating or sending. That sequencing matters: it tells us the attacker was doing reconnaissance before acting, looking for the right financial thread to hijack.

The full sequence in the first 11 minutes paints the entire BEC playbook:

| Time | Action | Translation |
|---|---|---|
| 9:56:24 PM | `MailItemsAccessed` | Reading Mark's inbox (recon) |
| 9:57:53 PM | `MailItemsAccessed` | More reading |
| 10:02:33 PM | `New-InboxRule` | Setting up persistence |
| 10:03:59 PM | `New-InboxRule` | Second rule |
| 10:04:34 PM | `Create` + `Send` | Fraudulent email going out |
| 10:07 PM+ | SharePoint / OneDrive access | Hunting for more financial docs |

**Flag:** `MailItemsAccessed`

<img width="851" height="375" alt="image" src="https://github.com/user-attachments/assets/e2e87a68-4fa0-4fb2-b4c1-992f48ad661b" />

> **Lesson:** `CloudAppEvents` is where post-auth O365 activity lives — mailbox reads, rule creation, file access, sends. When `SigninLogs` runs out, this is the next pivot. Also worth noting: `AccountDisplayName` shows `Mark Smith` for control-plane actions (PowerShell, rule creation) but a session GUID for data-plane operations like `MailItemsAccessed`. Same actor, different log shape.

## Q10 — Rule Creation Method

**Goal:** Identify the `ActionType` Azure logs when an inbox rule is created.

**Approach:** Already visible in the Q09 results — at `10:02:33 PM` and `10:03:59 PM`, the attacker triggered an `ActionType` of `New-InboxRule`. That's the underlying PowerShell cmdlet name, which O365 logs verbatim whether the rule was created via Outlook UI, OWA, or direct Exchange Online PowerShell. No new query needed.

**Flag:** `New-InboxRule`

> **Lesson:** Inbox rules are a top-tier BEC persistence mechanism — silent, durable, and rarely audited by users. Detection engineering tip: alert on any `New-InboxRule` event where the rule body contains keywords like `delete`, `move to RSS`, or external forward addresses. That signature catches BEC persistence with very low false positive rates.
