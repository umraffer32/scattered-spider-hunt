# PRACTICEHunt 02 — What Else Did They Access?

Section 05 of the LogN Pacific BEC investigation. Email fraud is confirmed and contained on paper — but BEC is rarely just about one email. The IR Lead's question now: did the attacker exfiltrate anything *else*? File stores, shared drives, sensitive documents? Scoping the full blast radius is the difference between a contained incident and a slow-burning data breach.

This section returns to **`CloudAppEvents`**, this time filtering for file-access `ActionType`s instead of mailbox operations.

---

## Q21 — Cloud App Accessed

**Goal:** Identify the cloud application the attacker accessed beyond email.

**Approach:** Filter `CloudAppEvents` to the attacker's IP within the attack window, scoped to file-related actions. The `Application` field tells us which cloud service the access landed on.

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType in ("FileAccessed", "FileDownloaded", "FilePreviewed", "FileSyncDownloadedFull")
| project Timestamp, ActionType, Application, ObjectName
| order by Timestamp asc
```

A `FileAccessed` event landed at `10:07:16 PM` — under a minute after the fraudulent email was sent — on **`Microsoft OneDrive for Business`**. The `ObjectName` URL points at Mark's personal OneDrive root: `.../personal/m_smith_lognpacific_org/Documents/Forms/All.aspx`. That `All.aspx` path is OneDrive's full-library browse view, meaning the attacker was scanning every file Mark had stored, not opening a specific known document.

<img width="1254" height="227" alt="image" src="https://github.com/user-attachments/assets/31f0c759-66fd-4f52-a2b9-90419311091a" />

**Flag:** `Microsoft OneDrive for Business`

> **Lesson:** BEC investigations frequently stop at "the fake invoice was sent" — but a session with valid credentials usually does more than one thing. The attacker had `9:59 PM` to whenever the session expired, and they used it to browse OneDrive looking for more material. In real-world response, you scope BEC by listing every cloud app touched during the attacker's session window: Exchange, SharePoint, OneDrive, Teams, Power Platform. Each one extends the breach surface and adds to the regulatory disclosure picture.
