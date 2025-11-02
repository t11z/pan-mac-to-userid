# Palo Alto Networks MAC to User-ID

> ⚠️ **Disclaimer**  
>  
> This script is intended **for demonstration and educational purposes only**.  
> Mapping users to IP addresses based solely on **static MAC-to-User associations** is **not a security measure** and **should never be used in production environments**.  
>  
> User-ID information obtained this way is inherently **unreliable**, as MAC addresses can be easily spoofed or reassigned.  
>  
> For production-grade deployments, always use **official, trusted identity sources** such as:  
> • Directory-based User-ID (LDAP, Active Directory, etc.)  
> • Terminal-Server-based User-ID (Port to User Mapping)
> • GlobalProtect, Captive Portal, or other PAN-OS Authentication Integration  
>  
> Use this utility at your own risk and **only in isolated lab or test environments**.

Bulk-register user-to-IP mappings on a **Palo Alto Networks firewall** using the XML API (`type=user-id`), based on users and MAC addresses defined in a YAML file.

The script automatically:
- Reads user → MAC mappings from YAML
- Resolves MAC addresses to IPs (via local ARP cache and optional ARP scanning)
- Builds a PAN-OS-compliant XML `<uid-message>` payload
- Submits all login entries in a single API call to the firewall

Ideal for small-scale lab automation, proof-of-concepts, or environments where users are dynamically identified via local devices.

---

## ⚙️ Features

- **YAML-based configuration** — simple and readable  
- **Automatic ARP discovery** using system cache and `scapy`  
- **Bulk XML UID message builder** for efficient firewall updates  
- **Direct API integration** with `type=user-id`  
- **Linux-only** (due to ARP scanning and interface enumeration)  
- **Graceful fallback** if `scapy` is unavailable  

---

## 🧰 Requirements

| Component | Description |
|------------|-------------|
| Python 3.8+ | Core runtime |
| `requests` | For API communication |
| `PyYAML` | For YAML parsing |
| `scapy` *(optional)* | For ARP network scanning |
| Linux environment | Uses `ip -4 addr show` and `arp -a` |

Install dependencies via:

```bash
pip install requests pyyaml scapy
```

---

## 🗂 YAML File Structure

Example `users.yaml`:

```yaml
users:
  - id: alice
    macs:
      - 00:11:22:33:44:55
      - 66:77:88:99:AA:BB
    tags:
      - tag01
      - tag02: 0
      - name: tag03
        timeout: 3600
  - id: bob
    macs:
      - AA:BB:CC:DD:EE:FF
    tags:
      - tag01
```

Each entry may list one or more MAC addresses per user.
If a MAC address is not found in the ARP cache or scan results, it’s skipped with a log entry.

Optional `tags` allow associating users with PAN-OS tags (and per-tag timeouts). The payload will include a `<register-user>`
block alongside the login mappings, e.g.:

```xml
<uid-message>
  <type>update</type>
  <payload>
    <login>
      <entry name="alice" ip="192.0.2.10"/>
    </login>
    <register-user>
      <entry user="alice">
        <tag>
          <member>tag01</member>
          <member timeout="0">tag02</member>
          <member timeout="3600">tag03</member>
        </tag>
      </entry>
    </register-user>
  </payload>
</uid-message>
```

---

## 🚀 Usage

```bash
sudo ./user_mac_to_firewall_pan_os.py users.yaml \
  --api-url https://192.168.1.1 \
  --api-key <YOUR_FIREWALL_API_KEY>
```

### Optional Arguments

| Flag | Description |
|------|--------------|
| `--scan-timeout` | ARP scan timeout per network (default: 2 s) |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `--domain` | Prefix usernames as `domain\username` |
| `--entry-timeout` | Set an expiration timeout (seconds) for each login entry |

> 💡 If you provide `--api-url https://192.168.1.1`, the script automatically appends `/api/` internally.

---

## 🔒 PAN-OS API Requirements

The script uses the **XML API** with `type=user-id`.  
You need a valid **API key** from your firewall or Panorama.

Generate it manually once (example):

```bash
curl -k -X GET 'https://<firewall>/api/?type=keygen&user=admin&password=<password>'
```

You’ll receive XML output with the `<key>` field, which you can reuse in this script.

---

## 🧩 Example Log Output

```
2025-11-01 12:05:14 INFO Parsed ARP cache entries: 24
2025-11-01 12:05:15 INFO Discovered 3 directly connected IPv4 networks
2025-11-01 12:05:18 INFO Found 15 hosts in 192.168.1.0/24
2025-11-01 12:05:18 INFO API request successful: HTTP 200
2025-11-01 12:05:18 INFO API response body:
<response status="success">
  <result>
    <status>success</status>
  </result>
</response>
```

---

## 🧠 Internals

1. **ARP Parsing:**  
   Reads local ARP table via `arp -a`.

2. **Network Discovery:**  
   Enumerates directly connected IPv4 networks with `ip -4 addr show`.

3. **Optional Scanning:**  
   Uses `scapy` ARP probes for live host discovery.

4. **Payload Builder:**  
   Constructs `<uid-message>` according to PAN-OS documentation, e.g.:

   ```xml
   <uid-message>
     <version>1.0</version>
     <type>update</type>
     <payload>
       <login>
         <entry name="ACME\alice" ip="192.168.1.42" timeout="3600"/>
       </login>
     </payload>
   </uid-message>
   ```

5. **Firewall API Call:**  
   Sends payload to `https://<firewall>/api/` with parameters:
   - `type=user-id`
   - `key=<API_KEY>`
   - `cmd=<XML_PAYLOAD>`

---

## ⚠️ Notes & Limitations

- Must run with **root privileges** to perform ARP scans.  
- Designed for **Linux environments** (uses `ip` and `arp` utilities).  
- The script does **not** persist sessions or handle logout messages.  
- Tested on PAN-OS 10.2, 11.0, and 11.1.

---

## 🧾 License

MIT License — feel free to fork, extend, or adapt for your own automation workflows.
