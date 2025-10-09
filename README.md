# DDoShield-IoT
**Testbed for Evaluating IDS Performance against Botnet Distributed Denial of Service Attacks in IoT Environments**

DDoShield‑IoT is an open‑source testbed for researching and evaluating IDS performance against IoT botnet DDoS attacks. It orchestrates Docker containers (attacker, IoT devices, IDS, and target server) and connects them through an ns‑3 emulated network.

---

## Quickstart (2 commands)
```bash
# 1) Install dependencies (show progress), then REBOOT
./install.sh -v

# 2) First run (show progress while Docker images build)
./main.py -d 2 -V debug create
```
> After the first run, you can omit `-V debug` (default output is concise).

---

## Prerequisites
- OS: **Ubuntu 22.04/24.04** or **Debian 12**
- Privileges: **sudo** required for installation
- Hardware: **≥ 4 CPU cores**, **≥ 8 GB RAM** (16 GB+ recommended), **≥ 20 GB** free disk
- Internet access to fetch ns‑3 release tarball and Docker images

> **Important:** After `./install.sh` completes, **reboot the machine** before running `main.py`. Docker non‑root access is not active until after a reboot.

---

## Installation
The installer sets up **Docker**, **Docker Buildx**, and **ns‑3** (version pinned in `network/ns3_version`).

```bash
# See progress
./install.sh -v

# Show all installer options
./install.sh -h
```

### Notable installer options
- `--ns3-only` / `--docker-only` – install only one side
- `--ns3-profile {optimized|debug}` – choose ns‑3 build profile (default: `optimized`)
- `--ns3-configure-only` – ensure the exact version in `network/ns3_version` is present, then (optionally) clean, **reconfigure**, and **rebuild**
- `--ns3-clean {auto|none|clean|distclean}` – cleaning strategy before configure (default: `auto`)

Examples:
```bash
# Reconfigure/rebuild only, no Docker steps (optimized)
./install.sh --ns3-configure-only --ns3-profile optimized

# Reconfigure/rebuild with full clean (debug)
./install.sh --ns3-configure-only --ns3-clean distclean --ns3-profile debug
```

---

## Using the Testbed

### CLI help
```bash
./main.py --help
```

### Create environment
```bash
# First run: show detailed progress
./main.py -d <devs> -V debug create

# Later runs (quieter):
./main.py -d <devs> create
```

### Start ns‑3 emulation
```bash
./main.py -d <devs> ns3
```

### Destroy environment
```bash
# Safe tear‑down (honors labels; see below)
./main.py -d <devs> destroy
```

### Verbosity (main.py)
- `-V quiet` – minimal output (default)
- `-V info` – key steps
- `-V verbose` – detailed steps
- `-V debug` – everything (recommended for first run)

Colorized output can be controlled with `--color {auto,always,never}`.

---

## Components
- **Attacker** – tools/scripts for exploiting/controlling Devs
- **Devs** – N emulated IoT devices
- **TServer** – sink/target server for DDoS traffic
- **IDS** – real‑time IDS container (ML models) with traffic mirroring

---

## Labels & Safe Cleanup
All containers are labeled to avoid touching unrelated host containers:
- `ddosim.project=<project>`
- `ddosim.role=<role>`
- `ddosim.run_id=<run-id>`

`destroy` respects `--destroy-scope {project,run,all}` to control cleanup scope.

---

## Logs & Artifacts
- Run logs: `results/logs/<run_id>/`
- ns‑3 sources/build: `network/ns-allinone-<ver>/ns-<ver>/`
- Docker cache size: `docker system df`  
- (Optional) prune old images/containers once you’re done: `docker system prune -a`

---

## Typical Workflow
1. **Install**: `./install.sh -v` → **REBOOT**
2. **Create**: `./main.py -d 2 -V debug create`
3. **Start ns‑3**: `./main.py -d 2 ns3`
4. **Attach to IDS** (example):
   ```bash
   docker exec -it emu3 bash
   ./ids-online.py
   ```
5. **Run attacks** from attacker/C&C (TServer is `10.0.0.1`)
6. **Destroy** when done: `./main.py -d 2 destroy`

---

## ns‑3 Cleaning (reference)
From `./ns3` tool:
- `./ns3 clean` – remove CMake/build artifacts
- `./ns3 distclean` – remove configuration, build, docs, tests, Python artifacts
- `ccache -C` – clear compiler cache (shared across projects; optional)

The installer’s `--ns3-clean` flag uses these under the hood.

---

## Security Notes
- The project does **not** store sudo passwords.
- If you prefer passwordless sudo for specific networking commands, configure `/etc/sudoers` with minimal, command‑scoped rules (optional).

---

## Troubleshooting
**Must reboot after install**  
If `main.py` cannot talk to Docker without sudo, you didn't reboot. Reboot and try again.

**Buildx package name differs**  
The installer tries `docker-buildx` first and falls back to `docker-buildx-plugin` if available.

**ns‑3 “build.py not found”**  
Newer ns‑3 uses the `./ns3` tool. The installer handles this automatically.

**Interface not found during destroy**  
Messages like “Cannot find device br‑emuX” are safe to ignore (interface already removed).

**Quiet mode prints extra output**  
Use `-V quiet` and consult run logs under `results/logs/<run_id>/` for details.

---

## Citing DDoShield‑IoT
If you use this project in your research, please cite:

**DDoShield-IoT: A Testbed for Simulating and Lightweight Detection of IoT Botnet DDoS Attacks**  
`devivo2024ddoshieldiot.pdf`

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
Issues and PRs are welcome! See the code layout:
- `install.sh` – installs Docker, Buildx, ns‑3; supports `-v`, `--ns3-configure-only`, profiles, and cleaning
- `main.py` – orchestration of containers and ns‑3 emulation
- `connections/` – tap/bridge setup scripts to wire Docker ↔ ns‑3
- `docker/` – Dockerfiles and assets for Attacker/IDS/Devs/TServer
- `network/` – ns‑3 sources and version pin (see `network/ns3_version`)

---

## Contact
- Islam Obaidat: <iaobaidat@ncat.edu>