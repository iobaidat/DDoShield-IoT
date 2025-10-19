#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoSim (Docker + ns-3)
-----------------------------------
"""

import sys
import subprocess
import os
import signal
import time
import argparse
import datetime
import shutil
import logging
from typing import Any, Dict, Optional
from pathlib import Path
from shlex import quote as shq

# ------------------------------- Defaults ------------------------------------
DEFAULTS: Dict[str, Any] = {
    "project_label": "ddosim",
    "container_basename": "emu",
    "num_devs": 1,
    "emulation_time_sec": 600,
    "churn_mode": "0",
    "ns3_file_log_mode": "0",
    "scenario_size_meters": "5",
    "network_type": "csma",  # "wifi" supported
    "build_jobs": max(1, (os.cpu_count() or 2) - 1),
    "images": {
        "tserver": "tserver",
        "attacker": "myattackbox",
        "ids": "ids",
        "dev": "mydnsmasqbox",
    },
    "paths": {
        "results_subdir": "results",
        "pids_dir": os.path.join(".", "var", "pid"),
    },
    "destroy_scope": "project",  # project | run | all
}

CONFIG: Dict[str, Any] = DEFAULTS.copy()
# ------------------------------- Console UX ----------------------------------
# Color + structured output helpers (no external deps).
ENABLE_COLOR = True  # computed by set_color_mode()
COLOR_MODE = "auto"  # auto | always | never

class _Ansi:
    RESET   = "\x1b[0m"
    BOLD    = "\x1b[1m"
    DIM     = "\x1b[2m"
    FG_RED  = "\x1b[31m"
    FG_GRN  = "\x1b[32m"
    FG_YEL  = "\x1b[33m"
    FG_BLU  = "\x1b[34m"
    FG_CYN  = "\x1b[36m"
    FG_GRY  = "\x1b[90m"

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _conn_verbose_flag() -> str:
    return " -v" if PRINT_CHILD_OUTPUT else ""

def _conn_env_prefix() -> str:
    # scripts that read env verbosity (singleEndSetup/singleDestroy)
    return f"DDOSIM_SCRIPT_VERBOSE={'1' if PRINT_CHILD_OUTPUT else '0'}"

def set_color_mode(mode: str | None) -> None:
    global ENABLE_COLOR, COLOR_MODE
    COLOR_MODE = (mode or "auto").lower()
    if COLOR_MODE == "always":
        ENABLE_COLOR = True
    elif COLOR_MODE == "never":
        ENABLE_COLOR = False
    else:
        ENABLE_COLOR = _supports_color()

class _ColorFormatter(logging.Formatter):
    _map = {
        "DEBUG": _Ansi.FG_GRY,
        "INFO": _Ansi.FG_CYN,
        "WARNING": _Ansi.FG_YEL,
        "ERROR": _Ansi.FG_RED,
    }
    def format(self, record: logging.LogRecord) -> str:
        if not ENABLE_COLOR:
            return super().format(record)
        orig = record.levelname
        try:
            c = self._map.get(orig, "")
            record.levelname = f"{c}{orig}{_Ansi.RESET}"
            msg = super().format(record)
            return msg
        finally:
            record.levelname = orig

def _c(txt: str, style: str) -> str:
    if not ENABLE_COLOR:
        return txt
    return f"{style}{txt}{_Ansi.RESET}"

def print_run_context(op: str) -> None:
    # Pretty key:value block for current run
    items = [
        ("Operation", op),
        ("Number of Devs", str(NUM_DEVS)),
        ("Simulation time", str(EMULATION_TIME_SEC)),
        ("Network Type", NETWORK_TYPE),
        ("Churn", "no churn" if CHURN_MODE == "0" else "static churn" if CHURN_MODE == "1" else "dynamic churn"),
        ("NS3 File Log", "disabled" if NS3_FILE_LOG_MODE == "0" else "enabled"),
        ("Project label", str(CONFIG["project_label"])),
        ("Destroy scope", str(CONFIG["destroy_scope"])),
        ("Run ID", RUN_ID),
    ]
    if NETWORK_TYPE == "wifi":
        items.insert(5, ("Scenario Size (Disk)", str(SCENARIO_SIZE_METERS)))
    width = max(len(k) for k, _ in items)
    print()
    for k, v in items:
        kfmt = _c(f"{k:<{width}}", _Ansi.DIM)
        vfmt = _c(str(v), _Ansi.BOLD)
        print(f"{kfmt} : {vfmt}")
    print()


# ------------------------------- Help/CLI UX ---------------------------------
import argparse as _argparse

class ColorHelpFormatter(_argparse.RawTextHelpFormatter, _argparse.ArgumentDefaultsHelpFormatter):
    def _color(self, s, style):
        return _c(s, style) if 'ENABLE_COLOR' in globals() and ENABLE_COLOR else s

    def format_help(self):
        text = super().format_help()

        # Colorize common section titles
        text = text.replace("usage:", self._color("USAGE", _Ansi.FG_CYN + _Ansi.BOLD))
        text = text.replace("positional arguments:", self._color("COMMAND", _Ansi.FG_BLU + _Ansi.BOLD))
        # Python 3.10+ uses "options" instead of "optional arguments"
        text = text.replace("optional arguments:", self._color("OPTIONS", _Ansi.FG_BLU + _Ansi.BOLD))
        text = text.replace("options:", self._color("OPTIONS", _Ansi.FG_BLU + _Ansi.BOLD))

        # Light style tweaks
        lines = []
        for ln in text.splitlines():
            if ln.strip().startswith("-") and ln.strip().endswith(":"):
                # don't over-style argument names lines
                lines.append(ln)
            else:
                lines.append(ln)
        return "\n".join(lines)

class DDoSimArgumentParser(_argparse.ArgumentParser):
    def error(self, message):
        msg = _c(f"error: {message}", _Ansi.FG_RED + _Ansi.BOLD) if ENABLE_COLOR else f"error: {message}"
        self.print_usage()
        self.exit(2, msg + "\n\n" + self.format_help())

# ------------------------------- Globals -------------------------------------
LOGGER = logging.getLogger("ddosim")
REPO_ROOT: str = os.path.dirname(os.path.realpath(__file__))
RESULTS_DIR: Optional[str] = None
LOG_DIR: Optional[str] = None
PIDS_DIR: str = CONFIG["paths"]["pids_dir"]
RUN_ID: str = os.environ.get("DDOSIM_RUN_ID", datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid()))

NUM_INFRA_NODES = 3  # TServer, Attacker, IDS
NUM_DEVS = CONFIG["num_devs"]
NUM_NODES = NUM_INFRA_NODES + NUM_DEVS

EMULATION_TIME_SEC = CONFIG["emulation_time_sec"]
CHURN_MODE = CONFIG["churn_mode"]
NS3_FILE_LOG_MODE = CONFIG["ns3_file_log_mode"]
SCENARIO_SIZE_METERS = CONFIG["scenario_size_meters"]
NETWORK_TYPE = CONFIG["network_type"]
BUILD_JOBS = CONFIG["build_jobs"]

CONTAINER_BASENAME = CONFIG["container_basename"]
CONTAINER_NAMES = []  # populated in main()

NS3_VERSION = ""
NS3_HOME_ENV = ""

# Labels
LABEL_PROJECT_KEY = "ddosim.project"
LABEL_ROLE_KEY = "ddosim.role"
LABEL_RUN_KEY = "ddosim.run_id"

# Verbosity control
# quiet   -> WARNING logs, child output suppressed
# info    -> INFO logs, child output suppressed (summary only)
# verbose -> INFO logs, child output streamed live
# debug   -> DEBUG logs, child output streamed live
VERBOSITY = "quiet"
PRINT_CHILD_OUTPUT = False  # toggled by set_verbosity()


# ------------------------------- Logging -------------------------------------
def configure_logging(level_name: Optional[str] = None) -> None:
    target = (level_name or os.getenv("DDOSIM_LOGLEVEL", "INFO")).upper()
    level = getattr(logging, target, logging.INFO)

    if LOGGER.handlers:
        for h in list(LOGGER.handlers):
            LOGGER.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    fmt = "[%(levelname)s] %(message)s"
    handler.setFormatter(_ColorFormatter(fmt))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)


def set_verbosity(verbosity: Optional[str]) -> None:
    """
    Map human-friendly verbosity to logging level and child-output behavior.
    """
    global VERBOSITY, PRINT_CHILD_OUTPUT
    v = (verbosity or os.getenv("DDOSIM_VERBOSITY", "quiet")).lower()
    VERBOSITY = v
    if v == "quiet":
        configure_logging("INFO")
        PRINT_CHILD_OUTPUT = False
    elif v == "verbose":
        configure_logging("INFO")
        PRINT_CHILD_OUTPUT = True
    elif v == "debug":
        configure_logging("DEBUG")
        PRINT_CHILD_OUTPUT = True
    else:
        # default 'info'
        configure_logging("INFO")
        PRINT_CHILD_OUTPUT = False

# ------------------------------- Config --------------------------------------
def load_config() -> None:
    """
    Load config from DDOSIM_CONFIG or ./ddosim.yaml (YAML preferred; JSON fallback).
    Merge shallowly over defaults.
    """
    global CONFIG, PIDS_DIR

    conf_path = os.environ.get("DDOSIM_CONFIG", os.path.join(REPO_ROOT, "config.yaml"))
    if not os.path.exists(conf_path):
        LOGGER.debug("Config not found at %s; using defaults.", conf_path)
        CONFIG = DEFAULTS.copy()
        PIDS_DIR = CONFIG["paths"]["pids_dir"]
        return

    data: Dict[str, Any] = {}
    try:
        try:
            import yaml  # type: ignore
            with open(conf_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            import json
            with open(conf_path, "r", encoding="utf-8") as f:
                data = json.load(f)
    except Exception as e:
        LOGGER.error("Failed to read config %s: %s ; using defaults.", conf_path, e)
        CONFIG = DEFAULTS.copy()
        PIDS_DIR = CONFIG["paths"]["pids_dir"]
        return

    CONFIG = DEFAULTS.copy()
    for k, v in data.items():
        if isinstance(v, dict) and isinstance(CONFIG.get(k), dict):
            merged = CONFIG[k].copy()
            merged.update(v)
            CONFIG[k] = merged
        else:
            CONFIG[k] = v

    PIDS_DIR = CONFIG["paths"]["pids_dir"]


# ------------------------------- Utilities -----------------------------------
def ensure_results_dir() -> None:
    global RESULTS_DIR, LOG_DIR
    RESULTS_DIR = os.path.join(REPO_ROOT, CONFIG["paths"]["results_subdir"])
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # Log directory per run
    LOG_DIR = os.path.join(RESULTS_DIR, "logs", RUN_ID)
    os.makedirs(LOG_DIR, exist_ok=True)
    LOGGER.debug("Results directory: %s", RESULTS_DIR)
    LOGGER.debug("Log directory: %s", LOG_DIR)


def _write_log(label: Optional[str], content: Optional[str]) -> None:
    if not label or not content:
        return
    if not LOG_DIR:
        return
    try:
        path = os.path.join(LOG_DIR, f"{label}.log")
        with open(path, "a", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
    except Exception:
        pass


def run(cmd: str, *, check: bool = True, shell: bool = True, label: Optional[str] = None,
        force_capture: Optional[bool] = None) -> subprocess.CompletedProcess:
    """
    Wrapper around subprocess.run with consistent logging and error handling.
    - If PRINT_CHILD_OUTPUT is False (quiet/info), capture output and save to logs.
    - If PRINT_CHILD_OUTPUT is True (verbose/debug), stream output to console.
    - force_capture overrides global behavior for specific calls.
    """
    capture = (not PRINT_CHILD_OUTPUT) if force_capture is None else force_capture
    LOGGER.debug("Running: %s", cmd)
    try:
        cp = subprocess.run(
            cmd, shell=shell, check=check,
            stdout=(subprocess.PIPE if capture else None),
            stderr=(subprocess.STDOUT if capture else None),
            text=True
        )
        if capture and label:
            _write_log(label, cp.stdout or "")
        return cp
    except subprocess.CalledProcessError as e:
        if capture and label:
            _write_log(label, e.stdout or "")
        if capture and (e.stdout):
            LOGGER.error("Command failed: %s\nSee log: %s/%s.log", cmd, LOG_DIR, label or "step")
        else:
            LOGGER.error("Command failed (rc=%s): %s", e.returncode, cmd)
        if check:
            raise
        return e


def get_container_pid(name: str) -> Optional[str]:
    cp = run(f"docker inspect --format '{{{{ .State.Pid }}}}' {name}", check=False, label="docker_inspect", force_capture=True)
    if isinstance(cp, subprocess.CalledProcessError):
        return None
    pid = (cp.stdout or "").strip()
    return pid or None


def write_pidfile(name: str, pid: str) -> None:
    os.makedirs(PIDS_DIR, exist_ok=True)
    with open(os.path.join(PIDS_DIR, name), "w", encoding="utf-8") as f:
        f.write(str(pid))


def read_pidfile(name: str) -> Optional[int]:
    path = os.path.join(PIDS_DIR, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None


def max_node_index_in_pids() -> int:
    try:
        candidates = []
        for name in os.listdir(PIDS_DIR):
            if name.startswith(CONTAINER_BASENAME):
                tail = name[len(CONTAINER_BASENAME):]
                if tail.isdigit():
                    candidates.append(int(tail))
        return max(candidates) if candidates else 0
    except FileNotFoundError:
        return 0


def verify_expected_node_count() -> None:
    if not os.path.exists(PIDS_DIR) or not os.listdir(PIDS_DIR):
        LOGGER.error("Run the 'create' command first and try again.")
        sys.exit(2)
    docker_files = max_node_index_in_pids()
    if docker_files != NUM_NODES:
        LOGGER.error("Please correct the number of nodes (-d %d) in the command", docker_files)
        sys.exit(2)


def set_env_ns3_home() -> None:
    global NS3_VERSION, NS3_HOME_ENV
    version_file = os.path.join(REPO_ROOT, "network", "ns3_version")
    if not os.path.exists(version_file):
        LOGGER.error("Missing file: %s", version_file)
        sys.exit(2)

    with open(version_file, "r", encoding="utf-8") as f:
        NS3_VERSION = f.readline().strip()

    NS3_HOME_ENV = os.path.join(REPO_ROOT, "network", f"ns-allinone-{NS3_VERSION}", f"ns-{NS3_VERSION}")
    os.environ["NS3_HOME"] = NS3_HOME_ENV
    os.environ["DOCKER_CLI_EXPERIMENTAL"] = "enabled"


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def ensure_sudo() -> None:
    """Ensure we have a valid sudo timestamp; prompt the user if needed.
    - First try non-interactive check (sudo -vn).
    - If missing, run interactive 'sudo -v' so the user can enter a password.
    - On success, subsequent sudo calls should not prompt for a while.
    """
    cp = subprocess.run("sudo -vn", shell=True)
    if cp.returncode != 0:
        LOGGER.info("Elevated privileges required; please enter your password (sudo).")
        cp2 = subprocess.run("sudo -v", shell=True)
        if cp2.returncode != 0:
            LOGGER.error("Sudo authentication failed. Aborting.")
            sys.exit(2)
        LOGGER.debug("Sudo credentials cached.")


# -------------------------- Setup / Build ------------------------------------
def build_images_and_ns3() -> None:
    # Docker builds (logs captured unless verbose/debug)
    run(f"DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t {CONFIG['images']['tserver']} docker/TServer/.",
        label="build_tserver")
    run(f"DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t {CONFIG['images']['attacker']} docker/Attacker/.",
        label="build_attacker")
    run(f"DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t {CONFIG['images']['ids']} docker/IDS/.",
        label="build_ids")
    run(f"DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t {CONFIG['images']['dev']} docker/Devs/.",
        label="build_dev")

    # ns-3 dir check
    rc = subprocess.run('[ -d "$NS3_HOME" ]', shell=True).returncode
    if rc != 0:
        LOGGER.error("Unable to find ns-3 at %s ; ensure install.sh was run.", os.environ.get("NS3_HOME", ""))
        sys.exit(2)

    # Copy latest scratch
    if CONFIG["network_type"] == "wifi":
        run(f"cd network && bash update.sh tap-wifi-virtual-machine.cc {NS3_VERSION}", label="ns3_update_wifi")
    else:
        run(f"cd network && bash update.sh tap-csma-virtual-machine.cc {NS3_VERSION}", label="ns3_update_csma")

    LOGGER.info("ns-3 up to date!")
    LOGGER.info("cd %s", os.environ["NS3_HOME"])

    # Build ns-3
    rc = run(f"cd $NS3_HOME && ./ns3 build -j {CONFIG['build_jobs']}", check=False, label="ns3_build").returncode
    if rc != 0:
        LOGGER.warning("ns-3 build failed; attempting reconfigure and rebuild...")
        run(
            "cd $NS3_HOME && ./ns3 clean && ./ns3 distclean && "
            "./ns3 configure --enable-sudo --disable-examples --disable-tests --disable-python "
            f"--build-profile=optimized && ./ns3 build -j {CONFIG['build_jobs']}",
            label="ns3_build_reconfig"
        )
    else:
        # When not verbose, capture a short cmake/ninja status to log file
        _ = run(f"cd $NS3_HOME && echo 'Build OK at '$(date)", label="ns3_build_status", force_capture=True)

    LOGGER.info("ns-3 Build finished | %s", datetime.datetime.now())


def docker_label_flags(role: str) -> str:
    return (
        f'--label {LABEL_PROJECT_KEY}="{CONFIG["project_label"]}" '
        f'--label {LABEL_ROLE_KEY}="{role}" '
        f'--label {LABEL_RUN_KEY}="{RUN_ID}"'
    )


def start_role_containers() -> None:
    acc = 0
    dataset = Path(REPO_ROOT) / "docker" / "videos"
    acc += run(
        " ".join([
            "docker run --platform linux/amd64",
            f"--mount type=bind,src={shq(str(dataset))},dst=/srv/www,ro",
            "--mount type=tmpfs,target=/dev/shm/ftp,tmpfs-size=64m",
            "--restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged",
            "-dit --net=none", docker_label_flags("tserver"),
            f"--name {CONTAINER_NAMES[1]}", CONFIG["images"]["tserver"]
        ]),
        check=False, label="docker_run_tserver"
    ).returncode

    acc += run(
        f"docker run --platform linux/amd64 --restart=always "
        f"--sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged -dit --net=none "
        f"{docker_label_flags('attacker')} --name {CONTAINER_NAMES[2]} {CONFIG['images']['attacker']}",
        check=False, label="docker_run_attacker"
    ).returncode

    acc += run(
        f"docker run --platform linux/amd64 --restart=always "
        f"--sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged "
        f"-v {REPO_ROOT}/docker/IDS/pcap_datasets:/dataset "
        f"-dit --net=none {docker_label_flags('ids')} "
        f"--name {CONTAINER_NAMES[3]} {CONFIG['images']['ids']}",
        check=False, label="docker_run_ids"
    ).returncode

    for i in range(NUM_INFRA_NODES + 1, NUM_NODES + 1):
        acc += run(
        f"docker run --platform linux/amd64 "
        f"-v {dataset}:/data:ro "
        f"--restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged "
        f"-dit --net=none {docker_label_flags('dev')} "
        f"--name {CONTAINER_NAMES[i]} {CONFIG['images']['dev']}",
        check=False, label=f"docker_run_dev_{i}"
    ).returncode

    if acc != 0:
        LOGGER.error("One or more containers failed to start.")
        sys.exit(2)

    time.sleep(1)
    LOGGER.info("Finished running containers | %s", datetime.datetime.now())


def setup_ns3_taps_and_bridges() -> None:
    acc = 0
    for i in range(1, NUM_NODES + 1):
        acc += run(f"{_conn_env_prefix()} bash connections/singleSetup.sh {CONTAINER_NAMES[i]}{_conn_verbose_flag()}",
                   check=False, label=f"tap_setup_{i}").returncode
    if acc != 0:
        LOGGER.error("Error creating bridge and tap interfaces")
        sys.exit(2)

    acc += run(f"{_conn_env_prefix()} sudo bash connections/singleEndSetup.sh{_conn_verbose_flag()}",
               check=False, label="tap_endsetup", force_capture=False).returncode
    if acc != 0:
        LOGGER.error("Error finalizing bridges and tap interfaces")
        sys.exit(2)

    acc = 0
    for i in range(1, NUM_NODES + 1):
        pid = get_container_pid(CONTAINER_NAMES[i])
        if pid:
            write_pidfile(CONTAINER_NAMES[i], pid)
        acc += run(f"{_conn_env_prefix()} bash connections/container.sh {CONTAINER_NAMES[i]} {i}{_conn_verbose_flag()}",
                   check=False, label=f"container_br_{i}").returncode

    if acc != 0:
        LOGGER.error("Error creating container side bridges")
        sys.exit(2)

    LOGGER.info("Finished setting up bridges | %s", datetime.datetime.now())


def setup_ids_mirroring() -> None:
    subprocess.run("sudo modprobe ifb", shell=True, check=True)
    subprocess.run(
        "PID=`docker inspect --format '{{ .State.Pid }}' emu3` && "
        "sudo ip netns exec $PID ifconfig eth0 0.0.0.0 promisc up",
        shell=True, check=True
    )
    subprocess.run(
        "sudo tc qdisc add dev tap-emu3 ingress && "
        "sudo tc filter add dev tap-emu3 parent ffff: protocol all u32 match u32 0 0 "
        "action mirred egress redirect dev si-emu3",
        shell=True, check=True
    )
    LOGGER.info("IDS mirroring configured.")


# ----------------------------- Primary Ops -----------------------------------
def create_environment() -> None:
    LOGGER.info("Creating environment...")
    os.makedirs(PIDS_DIR, exist_ok=True)

    if os.listdir(PIDS_DIR):
        running_count = max_node_index_in_pids()
        if running_count != 0:
            LOGGER.error("There are %d node(s) running. Use 'destroy' first.", running_count)
            return

    ensure_results_dir()
    set_env_ns3_home()
    ensure_sudo()

    build_images_and_ns3()
    start_role_containers()
    setup_ns3_taps_and_bridges()
    setup_ids_mirroring()

    # Point user to logs when not streaming
    if not PRINT_CHILD_OUTPUT:
        LOGGER.info("Detailed step logs saved under: %s", LOG_DIR)
    LOGGER.info("Create: Done.")


def run_ns3(return_proc: bool = False):
    verify_expected_node_count()
    ensure_sudo()

    rc = subprocess.run('[ -d "$NS3_HOME" ]', shell=True).returncode
    if rc != 0:
        LOGGER.error("Unable to find ns-3 at %s ; ensure install.sh was run.", os.environ.get("NS3_HOME", ""))
        sys.exit(2)

    existing_pid = read_pidfile("ns3")
    if existing_pid and pid_exists(existing_pid):
        LOGGER.info("ns-3 is still running with pid = %d", existing_pid)
        return None if not return_proc else None

    LOGGER.info("About to start ns-3 with total emulation time of %s", EMULATION_TIME_SEC)

    # docker run --cap-add=NET_ADMIN \
    #   -v /path/to/videos:/data \
    #  -e SERVER_IP=10.0.0.1 \
    #  -e BW_RERANDOMIZE=true -e BW_RERANDOMIZE_MINUTES=10
    #  -e PAUSE_BETWEEN_FILES=true -e PAUSE_MAX_SECS=3
    #  -e APP_CMD=run_ffmpeg #(or run_curl_http, run_curl_ftp)

    base = "cd $NS3_HOME && "
    if NETWORK_TYPE == "wifi":
        ns3_cmd = (
            base + f'./ns3 run -j {BUILD_JOBS} '
            f'"scratch/tap-vm --NumNodes={NUM_NODES} --TotalTime={EMULATION_TIME_SEC} '
            f'--TapBaseName={CONTAINER_BASENAME} --DiskDistance={SCENARIO_SIZE_METERS} '
            f'--Churn={CHURN_MODE} --FileLog={NS3_FILE_LOG_MODE} '
            f'--WriteDirectory={RESULTS_DIR} --NoneDevsNodes={NUM_INFRA_NODES}"'
        )
    else:
        ns3_cmd = (
            base + f'./ns3 run -j {BUILD_JOBS} '
            f'"scratch/tap-vm --NumNodes={NUM_NODES} --TotalTime={EMULATION_TIME_SEC} '
            f'--Churn={CHURN_MODE} --FileLog={NS3_FILE_LOG_MODE} '
            f'--TapBaseName={CONTAINER_BASENAME} --WriteDirectory={RESULTS_DIR} '
            f'--NoneDevsNodes={NUM_INFRA_NODES} --AnimationOn=false"'
        )

    if PRINT_CHILD_OUTPUT:
        print(f"NS3_HOME={os.environ['NS3_HOME'].strip()} && {ns3_cmd}")

    proc = subprocess.Popen(ns3_cmd, shell=True)
    time.sleep(10)
    proc.poll()
    input("\nPress the Enter key to continue...")

    LOGGER.info("ns-3 proc pid = %s", proc.pid)
    write_pidfile("ns3", proc.pid)
    LOGGER.info("Running ns-3 in the background | %s", datetime.datetime.now())

    return proc if return_proc else None


def run_emulation() -> None:
    LOGGER.info("Starting emulation...")
    verify_expected_node_count()
    ensure_sudo()

    existing_pid = read_pidfile("ns3")
    proc = None
    proc_started = False
    if existing_pid and pid_exists(existing_pid):
        LOGGER.info("ns-3 is still running with pid = %d", existing_pid)
    else:
        LOGGER.info("ns-3 is NOT running")
        proc = run_ns3(return_proc=True)
        proc_started = True
        time.sleep(5)

    LOGGER.info("Restarting containers")
    acc = 0
    for i in range(1, NUM_NODES + 1):
        acc += run(f"docker restart -t 0 {CONTAINER_NAMES[i]}", check=False, label=f"docker_restart_{i}").returncode

    # Clean old netns and refresh PID files
    rc = 0
    for i in range(1, NUM_NODES + 1):
        pidfile = os.path.join(PIDS_DIR, CONTAINER_NAMES[i])
        if os.path.exists(pidfile):
            with open(pidfile, "rt", encoding="utf-8") as f:
                text = f.read().strip()
            rc += run(f"sudo rm -rf /var/run/netns/{text}", check=False, label="netns_rm", force_capture=False).returncode

        pid = get_container_pid(CONTAINER_NAMES[i])
        if pid:
            write_pidfile(CONTAINER_NAMES[i], pid)

    # Recreate container side bridges
    acc = 0
    for i in range(1, NUM_NODES + 1):
        acc += run(f"{_conn_env_prefix()} bash connections/container.sh {CONTAINER_NAMES[i]} {i}{_conn_verbose_flag()}",
                   check=False, label=f"container_br_{i}").returncode

    LOGGER.info("Emulation running | %s", datetime.datetime.now())
    LOGGER.info("Letting the simulation run for %s", EMULATION_TIME_SEC)

    if proc_started and proc is not None:
        proc.communicate()
    else:
        while True:
            existing_pid = read_pidfile("ns3")
            if not (existing_pid and pid_exists(existing_pid)):
                break
            time.sleep(5)

    LOGGER.info("Emulation finished | %s", datetime.datetime.now())


def destroy_environment() -> None:
    LOGGER.info("Destroying environment...")
    ensure_sudo()

    ns3_pid = read_pidfile("ns3")
    if ns3_pid and os.path.exists(f"/proc/{ns3_pid}"):
        LOGGER.info("ns-3 is running ... killing the ns-3 process")
        try:
            os.killpg(os.getpgid(ns3_pid), signal.SIGTERM)
            LOGGER.info("Killed ns-3 process")
        except Exception as ex:
            LOGGER.warning("Failed to kill ns-3 process: %s", ex)
        try:
            os.remove(os.path.join(PIDS_DIR, "ns3"))
        except Exception:
            pass
        subprocess.run("sudo modprobe -r ifb", shell=True)

    scope = CONFIG.get("destroy_scope", "project")
    project_filter = f"--filter label={LABEL_PROJECT_KEY}={CONFIG['project_label']}"
    run_filter = f"--filter label={LABEL_RUN_KEY}={RUN_ID}"

    filters = project_filter
    if scope == "run":
        filters += f" {run_filter}"

    cp = subprocess.run(f"docker ps -a -q {filters}", shell=True, stdout=subprocess.PIPE, text=True)
    ids = (cp.stdout or "").strip().replace("\n", " ")
    if ids:
        run(f"docker stop {ids}", check=False, label="docker_stop")
        run(f"docker rm {ids}", check=False, label="docker_rm")
        LOGGER.info("Stopped and removed containers with %s", filters)
    else:
        LOGGER.info("No labeled containers found to remove (%s)", filters)

    rc = 0
    for i in range(1, NUM_NODES + 1):
        rc += run(f"{_conn_env_prefix()} bash connections/singleDestroy.sh {CONTAINER_NAMES[i]}{_conn_verbose_flag()}",
                  check=False, label=f"single_destroy_{i}").returncode

    rc2 = 0
    for i in range(1, NUM_NODES + 1):
        pidfile = os.path.join(PIDS_DIR, CONTAINER_NAMES[i])
        if os.path.exists(pidfile):
            with open(pidfile, "rt", encoding="utf-8") as f:
                text = f.read().strip()
            rc2 += run(f"sudo rm -rf /var/run/netns/{text}", check=False, label="netns_rm", force_capture=False).returncode

    for i in range(1, NUM_NODES + 1):
        pidfile = os.path.join(PIDS_DIR, CONTAINER_NAMES[i])
        if os.path.exists(pidfile):
            try:
                os.remove(pidfile)
            except Exception:
                pass

    if os.path.exists(PIDS_DIR):
        try:
            shutil.rmtree(PIDS_DIR)
        except Exception:
            pass

    LOGGER.info("Destroy complete")


# --------------------------------- CLI ---------------------------------------
def parse_args():
    epilog = """
Examples:
  {prog} create          # build images, set up taps/bridges, start containers
  {prog} ns3             # run only the ns-3 side (waits for Enter once ready)
  {prog} emulation       # restart containers, reconnect taps, and run end-to-end
  {prog} destroy         # stop and remove labeled DDoSim containers and taps

Tips:
  • Default verbosity is 'quiet' (clean console). Use -V verbose or -V debug to stream all outputs.
  • Config file: ddosim.yaml (or set DDOSIM_CONFIG=/path/to/file).
  • Colors: --color auto|always|never.
""".format(prog=os.path.basename(sys.argv[0]))
    parser = DDoSimArgumentParser(
        description=_c("DDoSim Orchestrator (Docker + ns-3)", _Ansi.BOLD) if ENABLE_COLOR else "DDoSim Orchestrator (Docker + ns-3)",
        add_help=True,
        formatter_class=ColorHelpFormatter,
        epilog=epilog
    )
    parser.add_argument("operation", type=str,
                        choices=["create", "ns3", "emulation", "destroy"],
                        help="Operation to perform: create, ns3, emulation, destroy")

    # Backwards-compatible flags + friendlier long names
    parser.add_argument("-d", "--devs", "--dev-count", dest="devs", type=int, help="Number of Devs in the simulation")
    parser.add_argument("-t", "--time", "--sim-time", dest="time", type=int, help="NS3 simulation time in seconds")
    parser.add_argument("-n", "--network", "--net-type", dest="network", type=str, choices=["csma", "wifi"],
                        help="Network type")
    parser.add_argument("-c", "--churn", "--churn-mode", dest="churn", type=str, choices=["0", "1", "2"],
                        help="Nodes churn: 0=no churn, 1=static, 2=dynamic")
    parser.add_argument("-l", "--log", "--ns3-file-log", dest="log", type=str, choices=["0", "1", "2"],
                        help="NS3 log to files: 0=off, 1=pcap only, 2=pcap+stats")
    parser.add_argument("-s", "--size", "--scenario-size", dest="size", help="Scenario size (meters) for wifi network")
    parser.add_argument("-j", "--jobs", "--build-jobs", dest="jobs", type=int, help="Number of parallel build jobs")
    parser.add_argument("--destroy-scope", choices=["project", "run", "all"],
                        help="Destroy only current run's containers, all project containers, or every ddosim container")
    parser.add_argument("-V", "--verbosity", choices=["quiet", "info", "verbose", "debug"],
                        help="Console output verbosity level (default: quiet)")
    parser.add_argument("--color", choices=["auto","always","never"], default="auto",
                        help="Colorize console output (default: auto)")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 3.2")
        # If invoked without arguments, show help.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(2)
    return parser.parse_args()


def main():
    global NUM_DEVS, EMULATION_TIME_SEC, CHURN_MODE, NS3_FILE_LOG_MODE
    global NETWORK_TYPE, SCENARIO_SIZE_METERS, BUILD_JOBS, NUM_NODES, CONTAINER_NAMES
    global CONTAINER_BASENAME

    # Configure logging early; adjust with verbosity next
    configure_logging()
    load_config()

    # Signals
    def _sig_handler(signum, frame):
        LOGGER.warning("Interrupt signal received.")
        destroy_environment()
        LOGGER.info("Exiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)   # Ctrl+C
    signal.signal(signal.SIGTSTP, _sig_handler)  # Ctrl+Z
    signal.signal(signal.SIGQUIT, _sig_handler)  # Ctrl+\

    args = parse_args()

    # Apply color, then verbosity (verbosity configures formatter)
    set_color_mode(args.color)
    set_verbosity(args.verbosity)

    # Apply config, then CLI overrides
    if args.devs is not None:
        CONFIG["num_devs"] = max(1, int(args.devs))
    if args.time is not None:
        CONFIG["emulation_time_sec"] = int(args.time)
    if args.network is not None:
        CONFIG["network_type"] = args.network
    if args.churn is not None:
        CONFIG["churn_mode"] = args.churn
    if args.log is not None:
        CONFIG["ns3_file_log_mode"] = args.log
    if args.size is not None:
        CONFIG["scenario_size_meters"] = args.size
    if args.jobs is not None:
        CONFIG["build_jobs"] = max(1, int(args.jobs))
    if args.destroy_scope is not None:
        CONFIG["destroy_scope"] = args.destroy_scope

    # Sync globals from CONFIG
    NUM_DEVS = CONFIG["num_devs"]
    EMULATION_TIME_SEC = CONFIG["emulation_time_sec"]
    CHURN_MODE = CONFIG["churn_mode"]
    NS3_FILE_LOG_MODE = CONFIG["ns3_file_log_mode"]
    SCENARIO_SIZE_METERS = CONFIG["scenario_size_meters"]
    NETWORK_TYPE = CONFIG["network_type"]
    BUILD_JOBS = CONFIG["build_jobs"]

    if NUM_DEVS < 1:
        print("Number of Devs should be 1 or more")
        sys.exit(2)

    CONTAINER_BASENAME = CONFIG["container_basename"]
    NUM_NODES = NUM_INFRA_NODES + NUM_DEVS
    CONTAINER_NAMES = [f"{CONTAINER_BASENAME}{i}" for i in range(0, NUM_NODES + 1)]

    ensure_results_dir()
    set_env_ns3_home()

    print_run_context(args.operation)

    op = args.operation
    if op == "create":
        create_environment()
    elif op == "destroy":
        destroy_environment()
    elif op == "ns3":
        run_ns3()
    elif op == "emulation":
        run_emulation()
    else:
        print("Nothing to be done ...")


if __name__ == "__main__":
    main()