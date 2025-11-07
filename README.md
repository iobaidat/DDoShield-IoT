# DDoShield-IoT
**Testbed for Evaluating IDS Performance against Botnet Distributed Denial of Service Attacks in IoT Environments**

DDoShield-IoT is an open-source testbed to **simulate IoT botnet DDoS traffic**, **run ML-based IDS in real time**, and **evaluate detection quality** in a controlled, reproducible environment. It orchestrates Docker containers (Attacker, Devs, IDS, Target Server) and connects them over an **ns-3** emulated network so you can vary topology, delay, loss, bottlenecks, and bandwidth.

<p align="center">
<img alt="DDoShield-IoT Overview" src="DDoShield-IoT.png" width="70%">
</p>

---

## Requirements
- OS: **Ubuntu 22.04/24.04** or **Debian 12**
- Hardware: ≥ **4 CPU cores**, **8 GB RAM** (16 GB+ recommended), **25 GB** free disk
- Internet access during install
- Sudo privileges (installer will prompt where needed)

---

## Download & Install
The following downloads DDoShield-IoT and sets up Docker, Docker Buildx, and ns‑3 (version pinned in `network/ns3_version`).

```bash
# 1) Install git.
sudo apt-get install -y git

# 2) Clone the DDoShield-IoT repository.
cd ~ && git clone https://github.com/iobaidat/DDoShield-IoT.git

# 3) Change the permissions of the files in the downloaded repository (add execute permissions to files in DDoShield-IoT).
sudo chmod +x -R DDoShield-IoT/

# 4) Navigate to the downloaded repository.
cd ~/DDoShield-IoT

# 4) Install dependencies (show progress). Do NOT prefix with sudo.
./install.sh -v
````

> **Important:** After `./install.sh` completes, **reboot the machine** before running `main.py`. Docker non‑root access is not active until after a reboot.

### Notable installer options
- `--ns3-only` / `--docker-only` – install only one side
- `--ns3-profile {optimized|debug}` – choose ns‑3 build profile (default: `optimized`)
- `--ns3-configure-only` – ensure the exact version in `network/ns3_version` is present, then (optionally) clean, reconfigure, and rebuild
- `--ns3-clean {auto|none|clean|distclean}` – cleaning strategy before configure (default: `auto`)

Examples:
```bash
# Reconfigure/rebuild only, no Docker steps (optimized)
./install.sh --ns3-configure-only --ns3-profile optimized

# Reconfigure/rebuild with full clean (debug)
./install.sh --ns3-configure-only --ns3-clean distclean --ns3-profile debug
```
---

## Usage: Full Workflow

### 1) Navigate to DDoShield-IoT repository

```bash
cd ~/DDoShield-IoT
```

### 2) CLI help

```bash
./main.py --help
```

### 3) Create nodes
To Create a specific number of Devs (i.e., IoT Devices), use the following command:

```bash
./main.py -d <N> -v debug create
# examples: create 3 device
./main.py -d 3 -v debug create
```

> **Note — First Run Takes Longer**
> The very first `./main.py -d <N> create` (optionally with `-v debug`) can take a while
> because Docker builds all node images (Attacker, Devs, TServer, IDS) and pulls base
> layers. Subsequent runs are **much faster** thanks to Docker layer caching.
>
> Tips:
>
> * Use `-v debug` once to see full build progress, e.g.:
>
>   ```bash
>   ./main.py -d 3 -v debug create
>   ```
> * Other verbosity options if you prefer less output:
>
>   * `-v info` – concise status
>   * `-v verbose` – includes child process output
>   * `-v debug` – maximum detail
> * After the first run you can omit `-v` (default output is concise).
> - Check disk usage with `docker system df`.
> - To reclaim space later: `docker system prune -a` (removes **unused** images, **stopped**
>   containers, unused networks, and build cache). After pruning, the next
>   `./main.py -d <N> create` will rebuild images again from scratch and take longer.

### 4) Start the ns-3 network

```bash
./main.py -d <N> -v debug ns3
# examples:
./main.py -d 3 -v debug ns3
```

This creates bridges/taps, attaches containers, configures the simulator, and starts emulation. The target server (TServer) is reachable at **10.0.0.1** by default.

### 5) Run the IDS (real time)

Open a **new terminal** (second terminal) and attach to the IDS container (named `emu3`):

```bash
docker exec -it emu3 bash
```

Start the online IDS with:

```bash
./home/ids-online-predict.py --bundle /home/ids-model-bundle --duration 180
```

* `--bundle` → path to the deployed model bundle
* `--duration` → total run time (seconds)

Once you start the IDS, you should see the IDS traffic classification output.

> **Model training pipeline** is in the repo at:
>
> `DDoShield-IoT/docker/IDS/model_train_pipeline`

### 6) Launch attacks from the C&C (Attacker)

Open **another terminal** (third terminal) and attach to the Attacker container (named `emu2`):

```bash
docker exec -it emu2 bash
```

Then open the C&C Server:
```bash
telnet localhost
# Credentials:
#   user: root
#   pass: root
```

To launch an attack, make sure that Devs are connected to the C&C Server.

**Check that bots (compromised Devs) are connected**

* Type `botcount` in the C&C console to show how many bots are currently connected.
* The terminal title bar will also display the number of connected bots.

Type the attack command in the C&C console. Example attack commands:

```text
udp 10.0.0.1 2 dport=9
syn 10.0.0.1 2 dport=9
ack 10.0.0.1 2 dport=9
```

**What those fields mean**

* `udp` / `syn` / `ack` → the attack type
* `10.0.0.1` → target IP (TServer)
* `2` → attack duration (seconds)
* `dport=9` → destination port to target on the TServer

**Attacks**
General form:

```
<attack> <target-ip> <duration-seconds> [options]
```

**See available attacks**

* Type `?` in the C&C console to list all supported attack commands.

* Check [attack-instructions](attack-instructions.md) to list all supported attack commands and their options

**Tips**

* To exit the C&C: type `quit` or `exit`.
* If no bots show up in `botcount`, make sure the Dev containers were created and attached to the ns-3 network (`./main.py -d <N> create` then `./main.py -d <N> ns3`).

### 7) Destroy nodes (cleanup)

```bash
./main.py -d <N> -v debug destroy
# example:
./main.py -d 3 -v debug destroy
```

---

## Examples

### Create 5 devices, start network, run IDS

```bash
# In the first terminal, run:
./main.py -d 5 create
./main.py -d 5 ns3

# Open a second terminal, run:
docker exec -it emu3 bash
./home/ids-online-predict.py --bundle /home/ids-model-bundle --duration 180
```

### Three short attacks back-to-back

```bash
# Open a third terminal, run:
docker exec -it emu2 bash
telnet localhost
# then run (below are three different attacks):
udp 10.0.0.1 2 dport=19
syn 10.0.0.1 2 dport=80
ack 10.0.0.1 2 dport=22
```

### Recreate with a different device count

```bash
./main.py -d 5 destroy
./main.py -d 12 create
./main.py -d 12 ns3
```

### Destroy and reclaim resources

```bash
./main.py -d 12 destroy
```

---

> ### Capturing PCAPs (Wireshark or tcpdump)
> You can capture traffic from any node in the testbed for analysis. Install tools on the **host**:
>
> ```bash
> sudo apt-get install -y wireshark tcpdump
> ```
>
> **Node naming cheat-sheet**
> - `emu1` = TServer (target)
> - `emu2` = Attacker (C&C)
> - `emu3` = IDS
> - `emu4` and above = IoT devices (e.g., with `-d 2`, devices are `emu4`, `emu5`)
>
> #### Option A — Wireshark (GUI)
> 1) Open **Wireshark** on the host.
> 2) Select the interface named **`si-emuN`** for the node you want to monitor  
>    (e.g., **`si-emu3`** to monitor all packets delivered to the IDS).
> 3) Click **Start**. When done, **File → Save As…** to export a **.pcap**.
>
> #### Option B — tcpdump (CLI, host-side)
> Use this one-liner to capture on the **host interface** that corresponds to a container’s `eth0`.
> It writes a timestamped **.pcap** in the current directory.
>
> ```bash
> # Example: capture for the IDS (emu3)
> cid=emu3; sudo tcpdump -i "$(ip -o link | awk -F': ' -v idx=$(docker exec "$cid" cat /sys/class/net/eth0/iflink) '$1==idx {split($2,a,\"@\"); print a[1]}')" \
>   -s0 -n -w "${cid}_$(date +%s).pcap"
> ```
>
> - Similar to Wireshark, to capture the **Attacker** use `cid=emu2`, for the **TServer** use `cid=emu1`, etc.
> - Press **Ctrl+C** to stop. The PCAP is saved in your current directory.
>
> **Tips**
> - Limit duration or rotate files to avoid large captures:
>   ```bash
>   # 60-second chunks, keep 5 files max (rotating), full packets, no DNS lookups
>   cid=emu3; sudo tcpdump -i "$(ip -o link | awk -F': ' -v idx=$(docker exec "$cid" cat /sys/class/net/eth0/iflink) '$1==idx {split($2,a,\"@\"); print a[1]}')" \
>     -s0 -n -G 60 -W 5 -w "${cid}_%Y%m%d-%H%M%S.pcap"
>   ```
> - Verify a capture: open in Wireshark or run `capinfos <file>.pcap`.
> - If your distro restricts GUI capture without root, add your user to the `wireshark` group and re-log, or run Wireshark/tcpdump with `sudo`.


---

## Tips & Troubleshooting

* **“permission denied” on docker** → Reboot after install so your user is in the `docker` group.
* **First `create` is slow** → Images are being built and cached; later runs are faster.
* **“Error creating container side bridges”** → Re-run `./main.py -d <N> ns3` after `create`; ensure interfaces exist before continuing.
* **No IDS output** → Ensure traffic is flowing (make sure ns3 is running: `./main.py -d <N> ns3`) and that IDS is running with the command above.
* **Logs / artifacts**

  * Run logs: `results/logs/<run_id>/`
  * ns-3 sources/build: `network/ns-allinone-<ver>/ns-<ver>/`
  * Reclaim disk: `docker system prune -a` (careful: removes unused images, stopped containers, unused networks, and build cache).

---

## Citing DDoShield-IoT

If you use DDoShield-IoT in your research, please cite:

[DDoShield-IoT: A Testbed for Simulating and Lightweight Detection of IoT Botnet DDoS Attacks](devivo2024ddoshieldiot.pdf)

```bibtex
@inproceedings{devivo2024ddoshieldiot,
  title={{DDoShield-IoT}: A Testbed for Simulating and Lightweight Detection of {IoT} Botnet {DDoS} Attacks},
  author={Simona De Vivo and Islam Obaidat and Dong Dai and Pietro Liguori},
  booktitle={54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks Workshops (DSN-W)},
  pages={1--8},
  year={2024}
}
```

---

## Contributing

PRs and issues are welcome!

**Code layout**

* `install.sh` — install dependencies (Docker, ns-3, etc.)
* `main.py` — orchestrates containers and ns-3 runs
* `docker/` — Dockerfiles and assets for Attacker/IDS/TServer/Devs
* `connections/` — scripts that connect Docker ↔ ns-3
* `network/` — ns-3 sources and config

## Contact

* Islam Obaidat — [iaobaidat@ncat.edu](mailto:iaobaidat@ncat.edu)