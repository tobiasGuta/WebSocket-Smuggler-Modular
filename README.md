# WebSocket Smuggler (Modular)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
The **WebSocket Smuggler (Modular)** is a specialized Burp Suite extension designed to automate the detection and exploitation of **HTTP Request Smuggling** vulnerabilities that arise from faulty WebSocket connection handling by reverse proxies.

This tool is essential for testing modern applications where simple header manipulation is insufficient, focusing on attacks that require precise timing, raw socket control, or chaining with other vulnerabilities like Server-Side Request Forgery (SSRF).

---

## Key Features
* **Boundary-Aware Response Parsing:** Parses HTTP response boundaries, headers, `Content-Length`, and chunked encoding before reporting evidence. Findings are labeled for manual validation unless a separate differential test confirms impact.
* **Dual Attack Mode:** Supports two distinct types of blind smuggling attacks (Simple Desync vs. SSRF Trigger).
* **Wordlist Fuzzing Engine:** Load custom wordlists to brute-force internal endpoints or parameters within the smuggled request.
* **Multi-Threaded Attacks:** Configure the number of concurrent threads (1–50) to speed up large wordlist scans.
* **Attack Controls:** Pause, resume, and stop attacks on demand, giving you full control over traffic generation.
* **Configurable Network Limits:** Adjust connect, read, idle, capture-size, and inter-request delay limits to tune speed vs. reliability for different targets.
* **Native Burp UI:** Integrates seamlessly with Burp Suite, using the native **Request/Response editors** for professional traffic analysis. Results table is color-coded by status for instant visual triage.
* **Raw Socket Engine:** Bypasses Burp's high-level HTTP stack to ensure the smuggled payload is sent immediately and atomically, improving exploitation reliability.
* **Request Context Preservation:** Can copy allowlisted headers from the selected Burp request so authenticated and tenant-routed targets are tested in the same application context.
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
| `RequestTemplateBuilder.java` | Builds the two-request raw socket payload while preserving selected request headers |
| `ResponseAnalyzer.java` | Boundary-aware response parsing, Upgrade header evidence, response length tracking |

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
3.  The target is loaded into the extension without sending attack traffic. Configure your attack settings and click **Run Attack**.

> You can run a single probe immediately (no wordlist needed), or load a wordlist for dictionary-based fuzzing.
> By default, **Require Burp scope** blocks attacks unless the selected target is in Burp's configured target scope.

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
| **SSRF Injection Path** | `/check-url?server={SSRF_SERVER}` | The request target containing `{SSRF_SERVER}`. In normal mode, the server URL is URL-encoded before substitution. |
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

> **Note:** Fuzzing works with both Simple Mode and SSRF Mode. If a wordlist is loaded, `{PAYLOAD}` is required. If no wordlist is loaded, `{PAYLOAD}` is rejected so it is not silently replaced with a placeholder value.

---

## Attack Settings

| Setting | Default | Range | Purpose |
| :--- | :--- | :--- | :--- |
| **Connect Timeout (ms)** | `3000` | 100–60000 | Maximum time for TCP connect and TLS handshake setup. |
| **Read Timeout (ms)** | `5000` | 100–60000 | Maximum total time spent capturing response data for one probe. |
| **Idle Timeout (ms)** | `1000` | 100–60000 | Stop capturing after this long without new response data. |
| **Max Capture (KB)** | `1024` | 1024–10240 | Maximum response bytes retained per probe. Truncated captures are labeled. |
| **Request Delay (ms)** | `50` | 0–10000 | Delay between requests in wordlist mode. Increase to avoid rate-limiting. |
| **Threads** | `1` | 1–50 | Number of concurrent attack threads. Increase for faster wordlist scans. |
| **Max Payload (bytes)** | `2048` | 1–65536 | Maximum UTF-8 byte size for each wordlist payload. |
| **Allow raw request targets** | Off | Off/On | Advanced mode. Allows non-origin-form request targets and control characters in request targets/payloads. Normal mode rejects them. |

Normal mode requires generated request targets to be origin-form paths beginning with `/`, rejects carriage returns and control characters, URL-encodes the `{SSRF_SERVER}` substitution, and validates every wordlist payload before sending traffic.

---

## Request Context

The selected Burp request is used as the source for allowlisted headers, not just as a socket destination.

* **Preserve selected headers:** Enabled by default. Copies matching headers into both the WebSocket upgrade request and the smuggled request.
* **Headers:** Comma-separated header allowlist. Defaults to `Host, Cookie, Authorization, Origin`.
* Add custom application routing headers such as `X-Tenant-ID`, `X-Org-ID`, or `X-Forwarded-Host` when the target depends on them.
* Protocol-controlled headers such as `Connection`, `Upgrade`, `Sec-WebSocket-*`, `Content-Length`, `Transfer-Encoding`, and `Expect` are not copied because the attack payload must control those values.
* **Connection Mode:** Always uses a direct raw TCP/TLS connection. Burp upstream proxy settings, SOCKS configuration, client certificate handling, match-and-replace rules, and project-level TLS behavior are not applied to attack traffic.
* **Verify TLS certificates:** Disabled by default to preserve lab/proxy testing behavior. Enable it to use the JVM default trust store and HTTPS hostname verification.
* **SNI Override:** Optional TLS identity/SNI hostname. Blank uses the selected request host. When TLS verification is enabled, this hostname is also used for certificate hostname matching.
* **Connect Host:** Optional socket destination override. This changes where the TCP connection is opened without changing the preserved `Host` header or TLS verification hostname.

---

## Attack Controls

Long-running fuzzing attacks can be managed using the control panel:

* **Run Attack:** Fires a single probe (no wordlist) or starts wordlist iteration. Requires a target sent via right-click context menu.
* **Require Burp scope:** Blocks `Run Attack` for targets outside Burp's configured target scope. Enabled by default.
* **Run differential validation:** Optional. Sends four probes for each payload: direct protected-path request, normal HTTP pipelining, failed WebSocket-upgrade sequence, and accepted WebSocket-upgrade sequence. Only the explicit `Run Attack` action starts this traffic.
* **Pause/Resume:** Pauses new submissions and worker progress checks. Already-active socket reads may continue until data arrives, idle timeout fires, or the read timeout expires.
* **Stop:** Cancels the current run, stops queued work, and closes active sockets.
* **Clear Results:** Clears the results table and attack history.
* **Export CSV:** Exports the full results table to a CSV file for reporting.

A **progress bar** shows real-time completion status. Wordlist submissions use a bounded queue instead of queuing the entire wordlist at once.

---

## Interpreting Results (Status Logic)

The extension parses response boundaries before interpreting status lines or headers. Results are **color-coded** for triage, but analyzer output is evidence, not proof of exploitability. In normal mode, treat observations as manual-validation prompts. If **Run differential validation** is enabled, the extension compares direct, pipelined, failed-upgrade, and accepted-upgrade probes and only uses differential language when the accepted-upgrade path exposes a protected 2xx/3xx response while the controls do not return an equivalent 2xx/3xx class. Differential runs keep all four request/response pairs in the evidence viewer tabs.

| Status | Color | Meaning | Verdict |
| :--- | :--- | :--- | :--- |
| **WebSocket Upgrade Accepted - Manual Validation Required** | Amber | A real `101 Switching Protocols` response included `Connection: Upgrade` and `Upgrade: websocket` headers. This confirms the handshake was accepted, not that smuggling occurred. | **Evidence Only** |
| **Second HTTP-Like Response Observed (X -> Y) - Manual Validation Required** | Amber | Two complete HTTP response boundaries were parsed and the second response was 2xx/3xx. This can be normal HTTP pipelining. | **Evidence Only** |
| **Differential Behavior Observed - ... - Manual Validation Required** | Red | Differential mode saw a protected 2xx/3xx response only after an accepted WebSocket upgrade; direct, normal-pipelined, and failed-upgrade controls did not expose it. | **High-Value Evidence** |
| **Possible Pipelining - Control path also returned protected response - Manual Validation Required** | Amber | Differential mode saw the protected response through the accepted upgrade, but at least one control did too. | **Evidence Only** |
| **Possible Pipelining (X -> Y) - Manual Validation Required** | Amber | Two complete HTTP response boundaries were parsed and the second response was not 2xx/3xx. | **Evidence Only** |
| **Single Response (X) - Manual Validation Required** | Amber | One complete HTTP response was parsed. | **Evidence Only** |
| **No Response / Connection Closed** | Gray | No parseable HTTP response was received. | **No Evidence** |
| **Error** | Gray | A connection or network error occurred. | **Check Logs** |

Statuses may include capture suffixes such as `[EOF]`, `[Idle Timeout]`, `[Read Timeout]`, `[Connection Reset]`, `[Capture Truncated]`, or `[Evidence Complete]`. The results table also includes a **Length** column showing the captured response size in bytes; length anomalies across fuzzing runs can indicate interesting responses.

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
