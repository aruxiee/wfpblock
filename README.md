
# 🚫 wfpblock: Simple Stealthy WFP Network Silencer

Leverages the **Windows Filtering Platform (WFP)** and bypasses traditional application-layer restrictions to enforce persistent high-priority blocks at the kernel level.

⚠️ **Please Note:** This project is strictly for **Educational and Authorized Penetration Testing**. I am not responsible for any of the shenanigans you guys pull.

---

## 🔍 Details

Unlike standard firewall rules that operate at user-mode, `wfpblock` communicates directly with the WFP `Base Filtering Engine (BFE)`. It injects custom filter entries into the network stack to intercept and drop traffic based on criteria before it reaches the application.

### How it uses WFP
The script utilizes the following WFP components:
*   **Layer Key (`FWPM_LAYER_OUTBOUND_TRANSPORT_V4`)**: Hooks into the outbound transport layer. This is deeper than the *App Layer* (ALE), so even if an application uses raw sockets the traffic is still intercepted.
*   **Weight Escalation**: It sets the filter weight to $2^{64}-1$ (`u64::MAX`). In WFP if two rules conflict, the higher weight wins. This makes `wfpblock` override any `Permit` rules set by EDRs or Windows Firewall.
*   **Persistence (`FWPM_FILTER_FLAG_PERSISTENT`)**: Filters are written to the WFP policy database, meaning the block remains active even if the system reboots until manually removed by the tool.

### wfpblock vs. Standard Options
Methods like `netsh advfirewall` are highly visible, logged extensively, and easily reverted by security software. `wfpblock` steps the game up a little bit.
*   **Protocol Deception**: Blocks **Port 443 (HTTPS)** but allows **ICMP (Ping)**, making a remote service appear *online* to troubleshooting tools while killing its ability to transmit encrypted telemetry data.
*   **Anti-Tamper**: Operates with maximum kernel priority so standard user-mode security agents often cannot self-heal or override the block without direct kernel-level intervention (does require an elevated shell).
*   **Minimal Footprint**: Does not create visible entries in the Windows Firewall GUI.

---

## 🧪 The Test

To verify the effectiveness of the silencer without using a browser.

- **Inject the Block**
    ```powershell
    .\wfpblock.exe 8.8.8.8
    ```
- **Verify via PowerShell**
    ```powershell
    Test-NetConnection -ComputerName 8.8.8.8 -Port 443
    ```
    *   *Expected Result*: `TcpTestSucceeded : False`
- **Check for "False Positive" Health**
    ```powershell
    ping 8.8.8.8
    ```
    *   *Expected Result*: Ping succeeds, so the deception is active.

---

## 🚀 Use Cases

### Use Cases
*   **Red Team Operations**: Blinding EDR/AV agents by cutting off their connection to cloud-based analysis engines.
*   **Security Research**: Testing heartbeat mechanisms in security software.
*   **Malware Analysis**: Preventing a sample from reaching its C2 server while keeping machine network-active for other tools.

### Impact
By removing specific communication channels, the operator can execute lateral movement or data exfiltration while the system's security telemetry remains silent. This increases *dwell time* inside a compromised network.

---

## 🛠️ MITRE

| ID | Technique | Purpose |
| :--- | :--- | :--- |
| **T1562.004** | Impair Defenses: Disable or Modify System Firewall | Using WFP to bypass/override existing firewall policies. |
| **T1071.001** | Application Layer Protocol: Web Protocols | Specifically targeting Port 443 to disrupt C2/Telemetry. |
| **T1112** | Modify Registry | Persistent WFP filters are stored in system registry hives. |

---

## 💡 Some Improvement Ideas

*   **Dynamic Path Resolution**: Implement the AppID logic to target `.exe` files by their NT device paths.
*   **CIDR Subnet Support**: Modify the conditions to block entire IP ranges (e.g. an entire AWS region used by a security vendor).
*   **Event Subscription**: Add a `FwpmNetEventSubscribe0` listener to log when and which process tried to talk to the blocked IP.
*   **Inverse Filtering**: Create a *Whitelist-Only* mode where all traffic is blocked *except* for the operator's C2 IP.

---

<p align="center">
  With ❤️ by <b>Aradhya</b>
</p>
