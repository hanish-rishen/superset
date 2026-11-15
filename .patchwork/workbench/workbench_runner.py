"""Trusted finite job harness; project setup/tests run only in Docker.

No model/provider keys, arbitrary host commands, PR publishing or terminal API.
The recipe registry and this file belong to the reviewed controller checkout.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

try:
    from sandbox import execute, Sampler, RunnerError, digest, read_result, isolation_probe
except ModuleNotFoundError:
    from packages.remote_runner.runner import execute, Sampler, RunnerError, digest, read_result, isolation_probe

LIMITS = {"build_seconds": 1500, "test_seconds": 300, "memory_gib": 10, "cpus": 3, "pids": 256}


def path_value(value):
    if not isinstance(value, str) or len(value) > 240 or not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_./@+ -]*", value) or any(p in ("", ".", "..", ".git") for p in value.split("/")):
        raise RunnerError("Unsupported repository path")
    return value


def tracked(source: Path, path: str, blob: str | None = None) -> Path:
    path_value(path)
    target = source
    for part in path.split("/"):
        target = target / part
        if target.is_symlink():
            raise RunnerError("Symlinked source paths are not supported")
    if not target.is_file() or not target.resolve().is_relative_to(source.resolve()):
        raise RunnerError("Expected a regular source file")
    entry = subprocess.check_output(["git", "-C", str(source), "ls-tree", "HEAD", "--", path], text=True).strip()
    fields = entry.split(None, 3)
    if len(fields) != 4 or fields[0] not in ("100644", "100755") or fields[1] != "blob" or (blob and fields[2] != blob):
        raise RunnerError("Tracked source identity mismatch")
    return target


def load_request(path: Path):
    if path.is_symlink() or path.stat().st_size > 131072:
        raise RunnerError("Execution request exceeds its size limit")
    raw = path.read_bytes()
    job = json.loads(raw)
    if set(job) != {"schemaVersion", "jobId", "kind", "repository", "baseSha", "recipeId", "oracle", "files", "patchSha256"} or job["schemaVersion"] != 1:
        raise RunnerError("Unsupported execution request")
    if not re.fullmatch(r"[a-f0-9]{32}", job["jobId"]) or not re.fullmatch(r"[a-f0-9]{40}", job["baseSha"]) or job["kind"] not in ("reproduction", "validation"):
        raise RunnerError("Invalid execution identity")
    recipes = json.loads(Path(__file__).with_name("recipes.json").read_text())
    candidates = [r for r in recipes if r["id"] == job["recipeId"] and r["repository"] == job["repository"]]
    if len(candidates) != 1 or os.environ.get("GITHUB_REPOSITORY", candidates[0]["executor"]) != candidates[0]["executor"]:
        raise RunnerError("This recipe/fork is not enabled")
    recipe = candidates[0]
    oracle = job["oracle"]
    if set(oracle) != {"path", "blob", "append", "sha256", "regressionName", "failureFragments"}:
        raise RunnerError("Invalid protected regression")
    path_value(oracle["path"])
    if not oracle["path"].startswith(recipe["directory"] + "/") or not isinstance(oracle["append"], str) or not 30 <= len(oracle["append"]) <= 16000 or not isinstance(oracle["regressionName"], str) or not 8 <= len(oracle["regressionName"]) <= 240:
        raise RunnerError("Invalid regression path or assertion")
    for field in ("blob", "sha256"):
        if not re.fullmatch(r"[a-f0-9]{" + ("40" if field == "blob" else "64") + "}", oracle[field]):
            raise RunnerError("Invalid oracle digest")
    if not isinstance(oracle["failureFragments"], list) or not 1 <= len(oracle["failureFragments"]) <= 3 or any(not isinstance(v, str) or not 1 <= len(v) <= 160 for v in oracle["failureFragments"]):
        raise RunnerError("Missing assertion failure signature")
    files = job["files"]
    if not isinstance(files, list) or len(files) > 8 or (job["kind"] == "validation") != bool(files):
        raise RunnerError("Invalid changed file set")
    paths = set()
    for edit in files:
        if set(edit) != {"path", "blob", "content"}:
            raise RunnerError("Invalid file overlay")
        path_value(edit["path"])
        if edit["path"] in paths or not edit["path"].startswith(recipe["directory"] + "/") or edit["path"] == oracle["path"] or not re.fullmatch(r"[a-f0-9]{40}", edit["blob"]) or not isinstance(edit["content"], str) or len(edit["content"]) > 32768 or "\0" in edit["content"]:
            raise RunnerError("Invalid or protected file overlay")
        if re.search(r"(^|/)(\.github|node_modules|\.git|__pycache__)(/|$)", edit["path"]) or re.search(r"(^|/)(Dockerfile|package(-lock)?\.json|[a-z-]+\.lock|pyproject\.toml|setup\.(py|cfg)|requirements[^/]*\.txt|\.env[^/]*)$", edit["path"]):
            raise RunnerError("Setup and credential paths cannot be edited")
        paths.add(edit["path"])
    # JS JSON.stringify uses compact UTF-8 without ASCII escaping. Dict order is
    # preserved from the immutable request; a mismatch never gets normalized.
    patch = json.dumps(files, ensure_ascii=False, separators=(",", ":")).encode()
    if hashlib.sha256(patch).hexdigest() != job["patchSha256"]:
        raise RunnerError("Submitted edit digest mismatch")
    return job, recipe, hashlib.sha256(raw).hexdigest()


def container(recipe, image, name, oracle, evidence, overlays=()):
    root = "/app/" + recipe["directory"]
    args = ["docker", "run", "--name", name, "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", "256", "--cpus", "3", "--memory", "10g", "--memory-swap", "10g", "--ulimit", "fsize=67108864:67108864", "--workdir", root, "--env", "CI=true", "--env", "FORCE_COLOR=0"]
    for source, target, readonly in [(oracle["host"], "/app/" + oracle["path"], True), (evidence, "/evidence", False), *overlays]:
        if "," in str(source) or "," in target:
            raise RunnerError("Unsupported mount delimiter")
        args += ["--mount", f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")]
    test = oracle["path"][len(recipe["directory"]) + 1:]
    if recipe["engine"] == "jest":
        return args + ["--entrypoint", "npm", image, "run", "test", "--", "--runInBand", "--coverage=false", "--watch=false", "--runTestsByPath", test, "--json", "--outputFile=/evidence/jest.json"]
    if recipe["engine"] == "pytest":
        return args + ["--entrypoint", "python", image, "-m", "pytest", test, "--junitxml=/evidence/junit.xml", "-q"]
    raise RunnerError("Unsupported test engine")


def results(directory, recipe, oracle, exit_code):
    if recipe["engine"] == "jest":
        data = read_result(directory / "jest.json")
        assertions = []
        for suite in data.get("testResults", []):
            if suite.get("testExecError"):
                raise RunnerError("The test environment failed before an assertion")
            assertions.extend(suite.get("assertionResults", []))
        items = [(v.get("fullName"), v.get("status"), "\n".join(v.get("failureMessages", []))) for v in assertions]
        for key, count in (("numTotalTests", len(items)), ("numPassedTests", sum(s == "passed" for _, s, _ in items)), ("numFailedTests", sum(s == "failed" for _, s, _ in items)), ("numPendingTests", 0), ("numTodoTests", 0)):
            if type(data.get(key)) is not int or data[key] != count:
                raise RunnerError("Test aggregate counts are inconsistent")
    else:
        path = directory / "junit.xml"
        if path.is_symlink() or path.stat().st_size > 2 * 1024**2:
            raise RunnerError("Invalid pytest evidence")
        root = ET.fromstring(path.read_text())
        if root.findall(".//error"):
            raise RunnerError("The pytest environment failed")
        items = [(case.attrib.get("name"), "failed" if case.find("failure") is not None else "skipped" if case.find("skipped") is not None else "passed", ET.tostring(case, encoding="unicode")) for case in root.findall(".//testcase")]
    names = [n for n, _, _ in items]
    if len(names) < 2 or len(set(names)) != len(names) or any(not isinstance(n, str) for n in names) or any(s not in ("passed", "failed") for _, s, _ in items):
        raise RunnerError("Missing, skipped or duplicate selected assertions")
    target = [(s, m) for n, s, m in items if n == oracle["regressionName"]]
    failed = sum(s == "failed" for _, s, _ in items)
    if len(target) != 1 or exit_code not in (0, 1) or (exit_code == 0) != (failed == 0):
        raise RunnerError("The registered regression did not execute consistently")
    if target[0][0] == "failed" and not all(fragment in re.sub(r"\x1b\[[0-9;]*m", "", target[0][1]) for fragment in oracle["failureFragments"]):
        raise RunnerError("The regression failed for a different reason")
    return {"total": len(names), "passed": len(names) - failed, "failed": failed, "assertions": sorted(names), "regression": target[0][0]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    job, recipe, request_sha = load_request(args.request)
    if args.describe:
        print("repository=" + job["repository"])
        print("base_sha=" + job["baseSha"])
        return 0
    report = {"job_id": job["jobId"], "source_repository": job["repository"], "base_sha": job["baseSha"], "control_commit": os.environ.get("GITHUB_SHA"), "request_sha256": request_sha, "oracle_sha256": job["oracle"]["sha256"], "patch_sha256": job["patchSha256"], "scope": "generated_component_regression", "status": "setup_failed", "stage": "preflight", "steps": []}
    names, sampler, output_created = [], None, False
    image = "patchwork-workbench:" + uuid.uuid4().hex
    output = args.output.resolve() if args.output else None
    try:
        if sys.platform != "linux" or output is None or args.source is None:
            raise RunnerError("Execution requires the bounded Linux CI host")
        source = args.source.resolve()
        output.mkdir(parents=True, exist_ok=False)
        output_created = True
        if shutil.disk_usage(source).free < 10 * 1024**3:
            raise RunnerError("Less than 10 GiB free disk")
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        origin = subprocess.check_output(["git", "-C", str(source), "remote", "get-url", "origin"], text=True).strip().removesuffix(".git")
        if revision != job["baseSha"] or origin != "https://github.com/" + job["repository"]:
            raise RunnerError("Pinned checkout identity mismatch")
        for path, blob in recipe["fingerprints"].items():
            tracked(source, path, blob)
        original = tracked(source, job["oracle"]["path"], job["oracle"]["blob"])
        if original.stat().st_size > 32768:
            raise RunnerError("Source test exceeds its text budget")
        oracle = {**job["oracle"], "host": output / "protected-test"}
        oracle["host"].write_text(original.read_bytes().decode("utf-8") + oracle["append"], encoding="utf-8")
        if digest(oracle["host"]) != oracle["sha256"]:
            raise RunnerError("Protected regression digest mismatch")
        overlays = []
        for index, edit in enumerate(job["files"]):
            tracked(source, edit["path"], edit["blob"])
            file = output / ("edit-" + str(index))
            file.write_text(edit["content"], encoding="utf-8")
            overlays.append((file, "/app/" + edit["path"], True))
        sampler = Sampler(source)
        sampler.thread.start()
        report["stage"] = "build"
        report["steps"].append({"name": "build", **execute(["docker", "build", "--target", recipe["dockerTarget"], "--tag", image, "--progress=plain", str(source)], output / "build.log", 1500)})
        if report["steps"][-1]["exit_code"]:
            raise RunnerError("The reviewed environment could not be built")
        checks = {}
        for phase in ("baseline", "patched") if job["kind"] == "validation" else ("baseline",):
            report["stage"] = phase
            directory = output / phase
            directory.mkdir()
            directory.chmod(0o777)
            name = "patchwork-" + phase + "-" + uuid.uuid4().hex[:12]
            names.append(name)
            command = container(recipe, image, name, oracle, directory, overlays if phase == "patched" else ())
            if phase == "baseline":
                report["stage"] = "isolation"
                probe = command.copy()
                probe_name = "patchwork-isolation-" + uuid.uuid4().hex[:12]
                names.append(probe_name)
                probe[probe.index("--name") + 1] = probe_name
                report["isolation"] = isolation_probe(probe, output / "isolation.log")
                report["stage"] = phase
            result = execute(command, output / (phase + ".log"), 300)
            state = json.loads(subprocess.check_output(["docker", "inspect", name, "--format", "{{json .State}}"], text=True))
            report["steps"].append({"name": phase, **result, "oom_killed": state.get("OOMKilled")})
            if state.get("OOMKilled"):
                raise RunnerError("The test exceeded its memory budget")
            checks[phase] = results(directory, recipe, oracle, result["exit_code"])
            report["checks"] = checks
            if digest(oracle["host"]) != oracle["sha256"]:
                raise RunnerError("The protected regression changed")
            if phase == "baseline" and not (checks[phase]["failed"] == 1 and checks[phase]["regression"] == "failed"):
                report["status"] = "not_reproduced" if checks[phase]["failed"] == 0 else "inconclusive"
                break
        else:
            report["status"] = "reproduced"
            if job["kind"] == "validation":
                if checks["baseline"]["assertions"] != checks["patched"]["assertions"]:
                    raise RunnerError("The selected assertion identities changed")
                report["status"] = "verified" if checks["patched"]["failed"] == 0 else "not_fixed"
    except (RunnerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ET.ParseError) as error:
        report["status"] = "setup_failed" if report["stage"] in ("preflight", "build", "isolation") else "inconclusive"
        report["reason"] = str(error) if isinstance(error, RunnerError) else "Executor error: " + type(error).__name__
    finally:
        if sampler:
            sampler.stop.set(); sampler.thread.join(timeout=3)
            report["resources"] = {**sampler.values, "scope": "One-second sampled whole-host metrics, including Docker/runner overhead."}
        removed = []
        for name in names:
            try: removed.append(subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=20).returncode == 0)
            except (OSError, subprocess.SubprocessError): removed.append(False)
        report["containers_removed"] = all(removed)
        if sys.platform == "linux":
            try: subprocess.run(["docker", "image", "rm", "--force", image], capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError): report["image_cleanup"] = "unconfirmed"
        if output_created:
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            for name in ("build.log", "isolation.log", "baseline.log", "patched.log"):
                file = output / name
                if file.exists():
                    for line in file.read_text(errors="replace")[-10000:].splitlines(): print("project | " + line, flush=True)
        print("PATCHWORK_RESULT=" + json.dumps(report, separators=(",", ":")), flush=True)
    return 0 if report["status"] in ("reproduced", "verified", "not_fixed", "not_reproduced") and report["containers_removed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
