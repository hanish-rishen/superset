"""Operator-reviewed Docker recipe runner. No arbitrary URL, shell or model tool.

The first adapter consumes Jest JSON. A component result is never a full-browser
reproduction. Project setup and tests execute inside Docker, not this host process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

MAX_LOG = 8 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
SENSITIVE_NAMES = ("GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "OPENROUTER_API_KEY", "CLOUDFLARE_API_TOKEN", "PATCHWORK_GITHUB_TOKEN")


class RunnerError(Exception):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", value):
        raise RunnerError("Invalid recipe path")
    if ".." in PurePosixPath(value).parts or PurePosixPath(value).is_absolute():
        raise RunnerError("Recipe path escapes its root")
    return value


def local_file(root: Path, name: str) -> Path:
    target = root / relative(name)
    if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()) or not target.is_file():
        raise RunnerError("Recipe file is missing or escapes its root")
    return target.resolve()


def load_recipe(path: Path, expected_digest: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_digest) or digest(path) != expected_digest:
        raise RunnerError("Recipe digest mismatch")
    if path.stat().st_size > 65536:
        raise RunnerError("Recipe too large")
    recipe = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schema_version", "case_id", "repository", "base_sha", "reference_sha", "docker_target", "workdir", "test_file", "runtime_file", "original_file", "oracle_file", "reference_file", "regression_name", "expected", "hashes", "limits", "scope"}
    if not isinstance(recipe, dict) or set(recipe) != fields or recipe["schema_version"] != 1 or recipe["scope"] != "component_regression":
        raise RunnerError("Unsupported recipe schema or scope")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", recipe["repository"]):
        raise RunnerError("Invalid repository identity")
    for name in ("base_sha", "reference_sha"):
        if not re.fullmatch(r"[a-f0-9]{40}", recipe[name]):
            raise RunnerError("Invalid source revision")
    for name in ("test_file", "runtime_file", "original_file", "oracle_file", "reference_file"):
        relative(recipe[name])
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", recipe["docker_target"]):
        raise RunnerError("Invalid Docker target")
    if not re.fullmatch(r"/app/[A-Za-z0-9_/-]+", recipe["workdir"]) or ".." in PurePosixPath(recipe["workdir"]).parts:
        raise RunnerError("Invalid container workdir")
    limits = recipe["limits"]
    bounds = {"build_seconds": (1, 1800), "test_seconds": (1, 600), "memory_gib": (2, 12), "cpus": (1, 3), "pids": (64, 512)}
    if set(limits) != set(bounds):
        raise RunnerError("Invalid resource limits")
    for name, (low, high) in bounds.items():
        if type(limits[name]) is not int or not low <= limits[name] <= high:
            raise RunnerError("Recipe exceeds resource limits")
    for field in ("original_file", "oracle_file", "reference_file"):
        file = local_file(path.parent, recipe[field])
        if digest(file) != recipe["hashes"].get(field):
            raise RunnerError("Recipe input digest mismatch")
    return recipe


def docker_run(recipe: dict, image: str, name: str, oracle: Path, evidence: Path, reference: Path | None = None) -> list[str]:
    if any("," in str(path) for path in (oracle, evidence, reference) if path):
        raise RunnerError("Mount path contains unsupported delimiter")
    limits = recipe["limits"]
    command = ["docker", "run", "--name", name, "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", str(limits["pids"]),
               "--cpus", str(limits["cpus"]), "--memory", f"{limits['memory_gib']}g", "--memory-swap", f"{limits['memory_gib']}g", "--ulimit", "fsize=67108864:67108864",
               "--workdir", recipe["workdir"], "--env", "CI=true", "--env", "FORCE_COLOR=0",
               "--mount", f"type=bind,src={oracle},dst={recipe['workdir']}/{recipe['test_file']},readonly",
               "--mount", f"type=bind,src={evidence},dst=/evidence"]
    if reference:
        command += ["--mount", f"type=bind,src={reference},dst={recipe['workdir']}/{recipe['runtime_file']},readonly"]
    return command + ["--entrypoint", "npm", image, "run", "test", "--", "--runInBand", "--coverage=false", "--watch=false", "--runTestsByPath", recipe["test_file"], "--json", "--outputFile=/evidence/jest.json"]


def jest_result(document: dict, exit_code: int, recipe: dict, baseline: bool) -> dict:
    if not isinstance(document, dict) or not isinstance(document.get("testResults"), list):
        raise RunnerError("Missing Jest result")
    assertions = []
    for suite in document["testResults"]:
        if suite.get("testExecError") or not isinstance(suite.get("assertionResults"), list):
            raise RunnerError("Test environment failed")
        assertions += suite["assertionResults"]
    names = [item.get("fullName") for item in assertions]
    if not names or any(not isinstance(name, str) for name in names) or len(set(names)) != len(names):
        raise RunnerError("Missing or duplicate assertions")
    if any(item.get("status") not in ("passed", "failed") for item in assertions):
        raise RunnerError("Skipped/incomplete assertions cannot verify a change")
    passed = sum(item["status"] == "passed" for item in assertions)
    failed = len(assertions) - passed
    for key, expected in (("numTotalTests", len(assertions)), ("numPassedTests", passed), ("numFailedTests", failed), ("numPendingTests", 0), ("numTodoTests", 0)):
        if type(document.get(key)) is not int or document[key] != expected:
            raise RunnerError("Jest aggregate counts do not match executed assertions")
    target = [item for item in assertions if item["fullName"] == recipe["regression_name"]]
    if len(target) != 1:
        raise RunnerError("Registered regression did not execute")
    if baseline:
        if exit_code != 1 or failed != 1 or target[0]["status"] != "failed" or document.get("success") is not False:
            raise RunnerError("Expected original regression failure was not isolated")
        messages = re.sub(r"\x1b\[[0-9;]*m", "", "\n".join(target[0].get("failureMessages", [])))
        if not all(fragment in messages for fragment in recipe["expected"]["failure_fragments"]):
            raise RunnerError("The baseline failed for a different reason")
    elif exit_code != 0 or failed or document.get("success") is not True:
        raise RunnerError("Patched selected checks did not pass")
    return {"passed": passed, "failed": failed, "total": len(assertions), "assertions": sorted(names), "regression": target[0]["status"]}


def compare_checks(before: dict, after: dict) -> dict:
    if before["assertions"] != after["assertions"]:
        raise RunnerError("The selected test identities changed between runs")
    return {"verdict": "component_regression_verified", "full_browser_reproduction": "not_attempted", "scope": "Same immutable component regression fails before and passes after; all other selected assertions pass."}


class Sampler:
    def __init__(self, root: Path):
        self.root = root
        self.stop = threading.Event()
        self.values = {"host_memory_used_peak_bytes": 0, "host_disk_used_peak_bytes": 0, "host_available_memory_min_bytes": None}
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def loop(self):
        while not self.stop.is_set():
            self.values["host_disk_used_peak_bytes"] = max(self.values["host_disk_used_peak_bytes"], shutil.disk_usage(self.root).used)
            try:
                mem = {name: int(value) * 1024 for name, value in re.findall(r"^(MemTotal|MemAvailable):\s+(\d+) kB", Path("/proc/meminfo").read_text(), re.M)}
                self.values["host_memory_used_peak_bytes"] = max(self.values["host_memory_used_peak_bytes"], mem["MemTotal"] - mem["MemAvailable"])
                previous = self.values["host_available_memory_min_bytes"]
                self.values["host_available_memory_min_bytes"] = min(previous, mem["MemAvailable"]) if previous is not None else mem["MemAvailable"]
            except (OSError, KeyError):
                pass
            self.stop.wait(1)


def execute(command: list[str], log: Path, timeout: int) -> dict:
    start = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    overflow = threading.Event()

    def copy():
        count = 0
        with log.open("wb") as target:
            while chunk := process.stdout.read(8192):
                remaining = max(0, MAX_LOG - count)
                target.write(chunk[:remaining])
                count += len(chunk)
                if count > MAX_LOG:
                    overflow.set()
                    process.terminate()
                    break

    reader = threading.Thread(target=copy, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RunnerError("Command exceeded its registered time budget") from None
    finally:
        reader.join(timeout=5)
    if reader.is_alive() or overflow.is_set():
        raise RunnerError("Command output exceeded its registered limit")
    return {"exit_code": code, "seconds": round(time.monotonic() - start, 3), "log_sha256": digest(log), "log_bytes": log.stat().st_size}


def read_result(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise RunnerError("Missing, unsafe or oversized test report")
    return json.loads(path.read_text(encoding="utf-8"))


def isolation_probe(command: list[str], log: Path) -> dict:
    image_index = command.index("--entrypoint")
    image = command[image_index + 2]
    prefix = command[:image_index]
    script = """const fs=require('fs');
const forbidden=['GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','OPENROUTER_API_KEY','CLOUDFLARE_API_TOKEN','PATCHWORK_GITHUB_TOKEN','PATCHWORK_CANARY'];
if(forbidden.some(k=>process.env[k]))throw Error('credential present');
if(fs.existsSync('/var/run/docker.sock'))throw Error('Docker socket exposed');
let denied=false;try{fs.appendFileSync(process.argv[1],'\\n// forbidden mutation');}catch(e){denied=['EROFS','EACCES','EPERM'].includes(e.code);}
if(!denied)throw Error('oracle writable');console.log('ISOLATION_PROBE_PASS');"""
    target = next(value for value in command if value.startswith("type=bind") and ",readonly" in value).split(",dst=", 1)[1].removesuffix(",readonly")
    previous = os.environ.get("PATCHWORK_CANARY")
    os.environ["PATCHWORK_CANARY"] = "non-secret-host-only-sentinel"
    try:
        result = execute(prefix + ["--entrypoint", "node", image, "-e", script, target], log, 60)
    finally:
        if previous is None:
            os.environ.pop("PATCHWORK_CANARY", None)
        else:
            os.environ["PATCHWORK_CANARY"] = previous
    if result["exit_code"] != 0 or b"ISOLATION_PROBE_PASS" not in log.read_bytes():
        raise RunnerError("Container isolation smoke check failed")
    return {"status": "pass", "checks": ["host environment canary not inherited", "no listed credentials in environment", "no Docker socket", "oracle mount rejects writes", "network disabled by runner arguments"], "limits": "Configuration and smoke checks, not a container-escape audit."}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema_version": 1, "control_commit": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"), "status": "setup_failed", "stage": "preflight", "steps": []}
    names: list[str] = []
    sampler = None
    output_created = False
    image = "patchwork-proof:" + uuid.uuid4().hex
    output = args.output.resolve()
    try:
        if sys.platform != "linux":
            raise RunnerError("This executor requires a Linux CI host; it never starts Docker on the development laptop")
        recipe_path = args.recipe.resolve()
        recipe = load_recipe(recipe_path, args.expected_manifest_sha)
        source = args.source.resolve()
        output.mkdir(parents=True, exist_ok=False)
        output_created = True
        if shutil.disk_usage(source).free < 10 * 1024**3:
            raise RunnerError("Less than 10 GiB free disk; cold environment not attempted")
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        origin = subprocess.check_output(["git", "-C", str(source), "remote", "get-url", "origin"], text=True).strip().removesuffix(".git")
        if revision != recipe["base_sha"] or origin != "https://github.com/" + recipe["repository"]:
            raise RunnerError("Checkout repository/revision mismatch")
        runtime = local_file(source, recipe["workdir"].removeprefix("/app/") + "/" + recipe["runtime_file"])
        if digest(runtime) != recipe["hashes"]["original_file"]:
            raise RunnerError("Checked-out runtime file does not match registered original")
        oracle = local_file(recipe_path.parent, recipe["oracle_file"])
        reference = local_file(recipe_path.parent, recipe["reference_file"])
        report.update({"repository": recipe["repository"], "base_sha": revision, "reference_sha": recipe["reference_sha"], "manifest_sha256": args.expected_manifest_sha,
                       "oracle_sha256": digest(oracle), "reference_file_sha256": digest(reference), "scope": recipe["scope"], "host_cpu_count": os.cpu_count(), "limits": recipe["limits"]})
        sampler = Sampler(source)
        sampler.thread.start()
        print("PATCHWORK_STAGE=building_pinned_environment", flush=True)
        report["stage"] = "build"
        build = execute(["docker", "build", "--target", recipe["docker_target"], "--tag", image, "--progress=plain", str(source)], output / "build.log", recipe["limits"]["build_seconds"])
        report["steps"].append({"name": "build", **build})
        if build["exit_code"]:
            raise RunnerError("Environment build failed")
        report["image_id"] = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
        checks = {}
        for phase in ("baseline", "reference"):
            directory = output / phase
            directory.mkdir()
            directory.chmod(0o777)
            name = "patchwork-" + phase + "-" + uuid.uuid4().hex[:12]
            names.append(name)
            command = docker_run(recipe, image, name, oracle, directory, reference if phase == "reference" else None)
            if phase == "baseline":
                report["stage"] = "isolation"
                probe_command = command.copy()
                probe_name = "patchwork-isolation-" + uuid.uuid4().hex[:12]
                names.append(probe_name)
                probe_command[probe_command.index("--name") + 1] = probe_name
                report["isolation"] = isolation_probe(probe_command, output / "isolation.log")
            print("PATCHWORK_STAGE=" + phase, flush=True)
            report["stage"] = phase
            result = execute(command, output / (phase + ".log"), recipe["limits"]["test_seconds"])
            state = json.loads(subprocess.check_output(["docker", "inspect", name, "--format", "{{json .State}}"], text=True))
            result["oom_killed"] = state.get("OOMKilled")
            report["steps"].append({"name": phase, **result})
            if state.get("OOMKilled"):
                raise RunnerError("Test container exceeded its memory budget")
            checks[phase] = jest_result(read_result(directory / "jest.json"), result["exit_code"], recipe, phase == "baseline")
            if digest(oracle) != report["oracle_sha256"] or digest(reference) != report["reference_file_sha256"]:
                raise RunnerError("Protected inputs changed")
        report.update(compare_checks(checks["baseline"], checks["reference"]))
        report["checks"] = checks
        report["status"] = "completed"
    except (RunnerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["status"] = "setup_failed" if report["stage"] in ("preflight", "build", "isolation") else "inconclusive"
        report["error"] = str(error) if isinstance(error, RunnerError) else "Local executor failure: " + type(error).__name__
        report["verdict"] = "inconclusive"
    finally:
        if sampler:
            sampler.stop.set()
            sampler.thread.join(timeout=3)
            report["resources"] = {**sampler.values, "scope": "One-second sampled whole-host metrics, including Docker/runner overhead; not process-specific RAM peaks."}
        cleanup = []
        for name in names:
            try:
                cleanup.append(subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=20).returncode == 0)
            except (OSError, subprocess.SubprocessError):
                cleanup.append(False)
        if sys.platform == "linux":
            try:
                subprocess.run(["docker", "image", "rm", "--force", image], capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                report["image_cleanup"] = "unconfirmed"
        report["containers_removed"] = all(cleanup)
        if output_created:
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        # Prefix untrusted logs so repository output cannot issue Actions commands.
        for name in ("build.log", "isolation.log", "baseline.log", "reference.log"):
            log = output / name
            if output_created and log.exists():
                for line in log.read_text(encoding="utf-8", errors="replace")[-18000:].splitlines():
                    print("project | " + line, flush=True)
        print("PATCHWORK_REPORT_JSON=" + json.dumps(report, separators=(",", ":")), flush=True)
    return 0 if report.get("verdict") == "component_regression_verified" and report["containers_removed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
