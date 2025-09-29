# lfa-simulation
A Containernet-based **link-flooding (LFA/Crossfire-style)** simulation that produces a high-quality mixed-traffic dataset for DDoS detection research.

This framework instantiates a realistic ISP↔IDC-like topology (47 OVS switches, 41 hosts, 60 IDC containers, 1 DNS server), generates **normal + attack** traffic across multiple protocols, and captures packets at a chokepoint for downstream feature extraction (e.g., CICFlowMeter/IPFIX) and labeling.

---

## ✨ Highlights

- **Mixed traffic at scale:** HTTP/HTTPS/SSH (TCP) + DNS/NTP/STUN (UDP) for normal users; coordinated, rotating multi-protocol attacks from bots.
- **Deterministic capture point:** tcpdump on the **s6↔s42** interconnect yields a single, clean PCAP.
- **Clock discipline:** Waits for NTP sync → disables auto corrections during the run → re-enables afterward.
- **Low noise:** IPv6 disabled to avoid ICMPv6 clutter; RSTP enabled with convergence wait.
- **Structured logs/metadata:** Separate normal/attack logs and per-round metadata (CSV-like) under `/tmp`.

---

## 🧭 Simulation Overview

**Purpose:** Simulate chain-link flooding DDoS behaviors and produce a labeled, analysis-friendly traffic capture.

### Topology

- **Switches:** `s1`–`s47` (OVS, RSTP enabled)
- **Hosts:**
  - **Bots:** `h1`–`h30`
  - **Normals:** `h31`–`h41`
  - Host IPs: `10.0.0.1`… under `ipBase=10.0.0.0/12`
- **IDC containers:** 5 groups × 12 hosts = **60**
  - Names: `idc_g{1..5}_h{1..12}`
  - IPs: `10.0.{g}0.{i+1}/12` (e.g., `10.0.10.2`, `10.0.20.3`, …)
  - Exposed ports: `80, 443, 22, 53, 123, 3478`
  - Domain form: `idcg{g}h{i}.lfa.com`
- **DNS server:** `dns_server` @ `10.0.100.2/12` (answers `*.lfa.com`)

> **Capture chokepoint:** `s6` interface **toward `s42`** (auto-discovered). PCAP is written to `/tmp/s6_mixed_traffic.pcap` and copied to `~/study/iar/topo/`.

### Links (key ones reflected in the script)

- **h1..h41 ↔ s1..s41:** `bw=1.0` (Mbit), `delay=0ms`, `r2q=1`
- **IDC ↔ s43..s47:** `bw=2.0` (Mbit), `delay=0.5ms`, `r2q=1`
- **Core “city” links:** assorted `bw` (128–1000 Mbit) and `delay` (~0.5–13 ms), `r2q=1`
- **Hot path:** `s6 ↔ s42`: `bw=5.0` (Mbit), `delay=2.1ms`, `r2q=1`

> ⚠️ **No packet loss/jitter** is configured in the provided script. If you need them, add `loss=`/`jitter=` to the relevant `TCLink` definitions.

---

## 📦 Prerequisites

- **OS:** Ubuntu 22.04+ (tested) / 24.04 recommended
- **Core stack:** Containernet/Mininet, Docker, Open vSwitch (OVS)
- **Python:** 3.8+ (system Python is fine)
- **CLI tools (host &/or containers as appropriate):**
  - `curl`, `ssh`, `sshpass`, `scp`
  - `tcpdump`, `tshark` (optional for validation)
  - `dnsutils` (`dig`)
  - `ntpdate` and/or `chrony` (`chronyc`) or `ntpstat`
  - `stun` (e.g., `stun-client`)
  - `hping3`
- **Controller:** an OpenFlow controller on `127.0.0.1:6633` (e.g., `ryu.app.simple_switch_13`)
- **Docker image:** `idc:latest` with `/entrypoint.sh` and services installed:
  - HTTP(S): `apache2` or `nginx` + openssl (self-signed OK)
  - SSH: `openssh-server`
  - DNS: (only if IDC nodes should answer) otherwise DNS lives in `dns_server`
  - NTP: `ntp`/`chrony` (serve on 123/UDP)
  - STUN: `coturn`/`stund`/`stunserver` (serve on 3478/UDP)

> The script queries **DNS at `dns_server`** and targets IDC domains (`idcg{g}h{i}.lfa.com`) for HTTP/HTTPS/SSH/NTP/STUN.

### Quick install (host)

```bash
sudo apt update
sudo apt install -y python3-pip docker.io openvswitch-switch \
  tcpdump tshark dnsutils ntpdate chrony stun sshpass hping3 \
  openssh-client curl

# (Containernet install steps vary; ensure `from mininet.net import Containernet` works)
```

#### 🔨 Build the IDC/DNS Images

Example (adjust to your layout):

```bash
cd topo/image
docker build -t idc:latest -f Dockerfile .
# Optionally a separate DNS image or reuse idc:latest for dns_server
```

**idc:latest must include /entrypoint.sh** to start the services and (for dns_server) serve the *.lfa.com zone mapping:

```bash
idcg{g}h{i}.lfa.com  -> 10.0.{g}0.{i+1}
ns.lfa.com           -> 10.0.100.2
```

## ▶️ Run
1.	Start a controller (in terminal A):

```bash
ryu-manager ryu.app.simple_switch_13
```

2.	Launch the simulation (in terminal B):

```bash
sudo python3 lfa.py
```

The script will:

- Ensure time is synchronized, then disable automatic NTP adjustments for the run.
- Build topology, enable RSTP on all bridges, and wait ~90 s for convergence.
- Disable IPv6 on all nodes/containers.
- Start tcpdump on s6→s42.
- Run normal traffic (multi-threaded) and attack traffic (bots).
- Stop capture, re-enable NTP, drop you into Mininet CLI, then exit to stop.

### 📄 Outputs

- PCAP
    - /tmp/s6_mixed_traffic.pcap (also copied to ~/study/iar/topo/)
- Logs
    - Global: /tmp/lfa_simulation.log
    - Normal: /tmp/normal_traffic_log.txt
    - Attack: /tmp/attack_traffic_log.txt
- Metadata (CSV-like)
    - Normal: /tmp/normal_traffic_meta_*.txt
    - Attack: /tmp/attack_traffic_meta.txt

#### 🔁 Traffic Details (as implemented)

**Normal traffic (generated by generate_normal_traffic)**

- Threads: 3 (default), duration: 360 s
- Services: http, https, ssh, dns, ntp, stun
- Rates: ~100–1000 kbps per HTTP(S) round (rate-limited curl)
- Requests: per HTTP(S) round 5–10, User-Agents randomized
- DNS: dig @10.0.100.2 idcg{g}h{i}.lfa.com
- NTP: ntpdate -q idcg{g}h{i}.lfa.com
- STUN: stun idcg{g}h{i}.lfa.com:3478
- SSH: simple command (echo test) to verify reachability


The script records per-round metadata: timestamps, endpoints, protocol, rate, duration, file type/HTTP method, etc.


**Attack traffic (generated by generate_attack_traffic)**

- Bots: h1–h30
- Decoys: Round-robin across IDC subnets and hosts; domain form idcg{g}h{i}.lfa.com
- Types/weights: http(0.35), https(0.35), ssh(0.10), udp(0.20)
- Rate: rate_mbps=10 total (default) distributed across bots; per-flow randomized (0.8×–2.0×)
- UDP: hping3 -2 with random ports, size 64–256 bytes, --interval u50000, --count 20
- SSH attack: scp upload of a dummy file
- Switch interval: 10 s (rotate targets)

If you need spoofed traffic, extend the UDP branch with --rand-source and adjust labeling accordingly (not enabled by default in the script).

#### 🔬 From PCAP to CSV (example)

Using CICFlowMeter (adjust paths to your environment):

```bash
# Example: convert PCAP to a CSV of bidirectional flows
cicflowmeter -f /tmp/s6_mixed_traffic.pcap -c ./cleandflow/lfa_simulation_X.csv
```

Labeling (example workflow)

Provide your own labeling script or adapt one (e.g., label_flow.py) that maps 5-tuples/IP ranges to roles:

```json
// roles.json (example)
{
  "bots":    ["10.0.0.1-10.0.0.30"],
  "normals": ["10.0.0.31-10.0.0.41"],
  "idc_subnets": ["10.0.10.0/24","10.0.20.0/24","10.0.30.0/24","10.0.40.0/24","10.0.50.0/24"]
}
```

```bash
python3 label_flow.py -i /path/to/your/csv/files/lfa_simulation_X.csv --roles-json roles.json -o lfa_simulation_X_labeled.csv
```

Note: The simulation uses a /12 ipBase; the /24 subnet notation above is for convenience in labeling. Align ranges with your exact IP plan if you modify the script.


### ✅ Validation Snippets

- **Normal vs UDP service counts**

```bash
tshark -r /tmp/s6_mixed_traffic.pcap -Y "ip.src==10.0.0.31 && ip.src<=10.0.0.41" | wc -l
tshark -r /tmp/s6_mixed_traffic.pcap -Y "udp.port==53 or udp.port==123 or udp.port==3478" | wc -l
```

- **Protocol distribution (rough)**

```bash
tshark -r /tmp/s6_mixed_traffic.pcap -q -z io,stat,60,"COUNT(tcp) tcp","COUNT(udp) udp"
```


## 🛠️ Troubleshooting

- **tcpdump didn’t start**
    - Check /tmp/tcpdump_error.log
    - Ensure sudo permissions and that s6 has a link to s42

- **RSTP flaps / loops**
	- The script enables RSTP and sleeps 90 s. Don’t shorten this unless you know your convergence time.

- **NTP sync timeout**
	- Host must reach NTP. The script tries timedatectl, chronyd, ntp, and ntpdate -q as fallbacks.

- **IPv6 noise in captures**
	- IPv6 is disabled on all nodes/containers by the script. If you re-enable it, expect ICMPv6.

## 🧪 Customize Traffic Mix

- **Change attack intensity**: generate_attack_traffic(..., rate_mbps=20)
- **Rotate more/less frequently**: switch_interval=5/20
- **Alter service weights**: edit attack_types / weights and the normal services mix
- **Add loss/jitter**: set loss=/jitter= on TCLink for s6↔s42 or elsewhere

## 🤝 Contributing
1. Fork this repo
2.	Create a feature branch: git checkout -b feature/xyz
3.	Commit changes: git commit -m "Add feature XYZ"
4.	Push: git push origin feature/xyz
5.	Open a Pull Request

## 📜 License

MIT License — see LICENSE.

## 📮 Contact

Please open a GitHub Issue or email hi.shuisong@gmail.com.