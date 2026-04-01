# WebSocket Smuggler (Modular)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
The **WebSocket Smuggler (Modular)** is a specialized Burp Suite extension designed to automate the detection and exploitation of **HTTP Request Smuggling** vulnerabilities that arise from faulty WebSocket connection handling by reverse proxies.

This tool is essential for testing modern applications where simple header manipulation is insufficient, focusing on attacks that require precise timing, raw socket control, or chaining with other vulnerabilities like Server-Side Request Forgery (SSRF).

---

## Key Features
* **Intelligent Response Parsing:** Automatically distinguishes between harmless HTTP Pipelining (Safe), potential smuggling, and confirmed smuggling (with `Upgrade` header detection), eliminating common false positives.
* **Dual Attack Mode:** Supports two distinct types of blind smuggling attacks (Simple Desync vs. SSRF Trigger).
* **Wordlist Fuzzing Engine:** Load custom wordlists to brute-force internal endpoints or parameters within the smuggled request.
* **Multi-Threaded Attacks:** Configure the number of concurrent threads (1–50) to speed up large wordlist scans.
* **Attack Controls:** Pause, resume, and stop attacks on demand, giving you full control over traffic generation.
* **Configurable Timing:** Adjust socket timeout and inter-request delay to tune speed vs. stealth for different targets.
* **Native Burp UI:** Integrates seamlessly with Burp Suite, using the native **Request/Response editors** for professional traffic analysis. Results table is color-coded by status for instant visual triage.
* **Raw Socket Engine:** Bypasses Burp's high-level HTTP stack to ensure the smuggled payload is sent immediately and atomically, improving exploitation reliability.
* **CSV Export:** Export the full results table to CSV for reporting and further analysis.
* **Persistent Configuration:** All settings are saved across Burp restarts no need to reconfigure every session.
* **Input Validation:** All fields are validated before attacks launch, with clear error messages.

---

## Architecture

The extension follows a modular architecture with clean separation of concerns:

| File | Responsibility |
| :--- | :--- |
| `WebSocketSmuggler.java` | Entry point registers extension, tab, context menu, unload handler |
| `SmugglerUI.java` | All Swing UI, event handling, persistence, CSV export, color-coded table |
| `AttackEngine.java` | Raw socket logic, thread pool management, pause/resume/stop |
| `AttackConfig.java` | Immutable configuration holder with input validation |
| `AttackLog.java` | Data class for storing attack history entries |
| `ResponseAnalyzer.java` | Enhanced response parsing — detects Upgrade headers, tracks response length |

---

## Installation

### Prerequisites
* **Java JDK 17+**
* **IntelliJ IDEA** (Recommended for development)
* **Gradle** (Used for building the JAR)

### Build Instructions
1.  **Execute Command:** Navigate to your project's terminal and run the build command:
    ```bash
    ./gradlew clean jar
    ```
2.  **Locate JAR:** The extension file will be generated in the `build/libs/` directory.

### Loading into Burp Suite
1.  Open Burp Suite.
2.  Navigate to **Extensions** → **Installed**.
3.  Click **Add**, set **Extension Type** to `Java`, and select the generated JAR file.
4.  A new top-level tab named **"WebSocket Smuggler"** will appear in the main Burp menu.

---

## Quick Start

1.  Browse the target application through Burp Suite's Proxy.
2.  In **Proxy → HTTP History**, right-click any request to the target and select **"Send to WebSocket Smuggler"**.
3.  The extension tab will activate with the target set. Configure your attack settings and click **Run Attack**.

> You can run a single probe immediately (no wordlist needed), or load a wordlist for dictionary-based fuzzing.

---

## Usage Guide (Attack Modes)

The tool operates in two modes, controlled by the **"Enable SSRF-Triggered Smuggling"** checkbox on the extension tab.

### Mode 1: Simple Smuggling (Default)

This mode tests for **naive proxies** (like Varnish) that fail to check the backend's response code for the WebSocket upgrade.

| Field | Value | Purpose |
| :--- | :--- | :--- |
| **[ ] Enable SSRF** | *(Unchecked)* | Uses Simple Mode. |
| **Simple Bait Path** | `/socket` | The backend WebSocket endpoint (the target of the initial connection). |
| **WS Version** | `777` or `13` | The version used to initiate the handshake. |
| **Smuggled Path** | `/flag` | The internal resource you are trying to access. |

> Some proxies will not even require the existence of a WebSocket endpoint for this technique to work.

https://github.com/user-attachments/assets/8b7b1f10-ec1a-49ca-9bc1-fb3f994d570e

### Mode 2: SSRF-Triggered Smuggling

This mode is used to bypass **smart proxies** (like Nginx) by chaining the attack with an external SSRF vulnerability to force a valid status code.

| Field | Value | Purpose |
| :--- | :--- | :--- |
| **[x] Enable SSRF** | *(Checked)* | Activates SSRF Injection logic. |
| **SSRF Injection Path** | `/check-url?server=` | The full path up to the injected URL (e.g., must include the parameter name and the equals sign). |
| **Python Server URL** | `http://<YOUR_VPS_IP>:80` | The **external endpoint** running your custom Python script. |
| **Smuggled Path** | `/flag` | The resource to smuggle the request to. |

https://github.com/user-attachments/assets/e386c160-5f32-4d10-9e36-b0750f0896d5

#### Attacker Server Setup (Real-World)
The external server used in this mode **cannot** be Burp Collaborator or Interactsh. These tools return a static `200 OK` response, but this attack requires the proxy to see a raw `101 Switching Protocols` status code to open the tunnel.

You must use a server capable of sending this raw response, typically by running your custom Python script exposed via:
1.  **A Public VPS (e.g., AWS, DigitalOcean).**
2.  **A Tunneling Service (e.g., Ngrok or Cloudflare Tunnel).**

---

## Advanced Usage: Wordlist Fuzzing

You can perform dictionary-based attacks to discover internal endpoints or fuzz parameters through the smuggled tunnel.

1.  **Load a Wordlist:** Click the `Load Wordlist` button and select a text file containing your payloads.
2.  **Set the Placeholder:** In the **Smuggled Path** field, use the `{PAYLOAD}` placeholder. The extension will replace this tag with each line from your wordlist.
    * *Example 1 (Endpoint Fuzzing):* `/{PAYLOAD}`
    * *Example 2 (Parameter Fuzzing):* `/admin/delete?user={PAYLOAD}`
3.  **Run Attack:** Click `Run Attack`. The extension will iterate through the list, sending a full smuggling sequence for every item.

> **Note:** Fuzzing works with both Simple Mode and SSRF Mode. You can also run an attack without a wordlist for a quick single-shot probe.

---

## Attack Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Socket Timeout (ms)** | `5000` | 100–60000 | How long to wait for the server response. Increase for slow proxies or tunneled SSRF. |
| **Request Delay (ms)** | `50` | 0–10000 | Delay between requests in wordlist mode. Increase to avoid rate-limiting. |
| **Threads** | `1` | 1–50 | Number of concurrent attack threads. Increase for faster wordlist scans. |

---

## Attack Controls

Long-running fuzzing attacks can be managed using the control panel:

* **Run Attack:** Fires a single probe (no wordlist) or starts wordlist iteration. Requires a target sent via right-click context menu.
* **Pause/Resume:** Temporarily halts the attack thread without losing progress. Useful if you need to inspect results or modify network settings.
* **Stop:** Completely terminates the current attack cycle.
* **Clear Results:** Clears the results table and attack history.
* **Export CSV:** Exports the full results table to a CSV file for reporting.

A **progress bar** shows real-time completion status during wordlist attacks.

---

## Interpreting Results (Status Logic)

The extension analyzes the raw byte stream and HTTP headers to determine if the connection was pipelined or smuggled. Results are **color-coded** for instant visual triage.

| Status | Color | Meaning | Verdict |
| :--- | :--- | :--- | :--- |
| **Smuggling Confirmed (101 + Upgrade)** | 🔴 Red | The tool detected a `101 Switching Protocols` response **with** `Connection: Upgrade` and `Upgrade: websocket` headers. The tunnel was fully opened. | **Vulnerable** |
| **Smuggling Detected (X → Y)** | 🔴 Red | The tool received **2 responses** where the second has a **success code** (2xx/3xx). This means the smuggled request reached the backend and was processed (e.g., `426 → 200`). | **Vulnerable** |
| **Potential Smuggling (101)** | 🔴 Red | The tool detected a `101` response but without full Upgrade headers. Likely vulnerable, investigate further. | **Likely Vulnerable** |
| **Pipelining (Safe)** | 🟢 Green | The tool detected **2 responses** where both are **error codes** (4xx/5xx). The proxy parsed both requests individually and rejected them (e.g., `426 → 403`). | **Not Vulnerable** |
| **Single Response** | 🟡 Amber | The tool received one response (e.g., `403`) and the socket closed immediately. | **Blocked/Failed** |
| **Error** | ⚪ Gray | A connection or network error occurred. | **Check Logs** |

The results table also includes a **Length** column showing the response size in bytes — length anomalies across fuzzing runs can indicate interesting responses.

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
