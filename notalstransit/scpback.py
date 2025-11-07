#!/usr/bin/env python3
"""
scpback.py

Helpers to resolve or obtain a remote file path from the local machine when the file lives on a remote host
accessed via SSH. Provides three complementary strategies:

1. resolve    - run a simple remote command (realpath/stat) over ssh to resolve a candidate path
2. find       - run remote find to search for files matching a pattern
3. request    - if you have an interactive SSH session (PTY), try to request the remote side using
               an OSC-1337-style in-band request (compatible with rzsz1337modem's XFER-REQUEST)

Usage examples
---------------
# resolve a candidate path on remote
./scpback.py --ssh user@host --resolve ./relative/path

# find files by name
./scpback.py --ssh user@host --find "*.log" --dir /var/log --max 20

# send an OSC 1337 XFER-REQUEST into an interactive ssh PTY
./scpback.py --ssh user@host --request /path/to/target

Notes
-----
- The module favors simple, auditable remote commands (realpath, stat, find).
- The OSC-1337 request mode attempts to open an interactive PTY and write an escape
  sequence that looks like: ESC ] 1337;XFER-REQUEST={"path":"..."}\x07
  This will only work if the remote side or an intermediary (like rzsz1337modem) is watching
  terminal output for those sequences.

"""

import argparse
import subprocess
import shlex
import sys
import os
import pty
import time

OSC_REQUEST_TMPL = b"\x1b]1337;XFER-REQUEST={payload}\x07"


def run_ssh_command(ssh_target, remote_cmd, timeout=None):
    """Run a one-shot SSH command and return (returncode, stdout, stderr)."""
    cmd = ["ssh", ssh_target, remote_cmd]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return proc.returncode or 124, out.decode(errors='replace'), err.decode(errors='replace')
    return proc.returncode, out.decode(errors='replace'), err.decode(errors='replace')


def resolve_remote(ssh_target, candidate):
    """Resolve a candidate path on remote using realpath/stat. Returns resolved path or raises.

    Attempts realpath; if not available, falls back to `readlink -f` or `python -c`.
    """
    # Prefer realpath
    safe = shlex.quote(candidate)
    for cmd in (f"realpath {safe}", f"readlink -f {safe}",
                f"python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' {safe}"):
        rc, out, err = run_ssh_command(ssh_target, cmd, timeout=10)
        if rc == 0 and out.strip():
            return out.strip()
    raise RuntimeError(f"Could not resolve path {candidate!r} on {ssh_target}: last err: {err.strip()}")


def find_remote(ssh_target, pattern, start_dir='.', max_results=50):
    """Run a remote find to locate files. Returns a list of paths."""
    safe_dir = shlex.quote(start_dir)
    safe_pat = shlex.quote(pattern)
    # Use -mount and -type f to avoid crossing filesystems unless explicitly desired
    cmd = f"find {safe_dir} -type f -name {safe_pat} -print | head -n {int(max_results)}"
    rc, out, err = run_ssh_command(ssh_target, cmd, timeout=20)
    if rc not in (0,1):
        raise RuntimeError(f"find failed on remote {ssh_target}: {err.strip()}")
    lines = [l for l in (out.splitlines()) if l.strip()]
    return lines


def request_via_pty(ssh_args, path, timeout=5):
    """Open an interactive ssh PTY and write an OSC 1337 XFER-REQUEST for `path`.

    Returns True if the sequence was written; this does not guarantee the remote acted on it.
    """
    # Build argv: ssh -tt <ssh_args...>
    argv = ["ssh", "-tt"] + ssh_args

    pid, fd = pty.fork()
    if pid == 0:
        # child: exec ssh
        try:
            os.execvp("ssh", argv)
        except Exception:
            sys.exit(1)
    else:
        try:
            payload = shlex.quote(path)
            # Build JSON-ish payload without adding extra shell quoting problems
            # We'll construct the raw OSC sequence and write it to the PTY
            payload_bytes = (b'{"path":' + shlex.quote(path).encode('utf-8') + b'}')
            seq = b"\x1b]1337;XFER-REQUEST=" + payload_bytes + b"\x07"
            os.write(fd, seq)
            # give remote a moment to process
            time.sleep(0.1)
            # optionally read whatever came back for a short time
            end = time.time() + timeout
            got = bytearray()
            while time.time() < end:
                try:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    got.extend(data)
                except OSError:
                    break
            # leave the session open for interactive use; we won't close ssh for them
            return True, got.decode(errors='replace')
        finally:
            # do not kill the child — we deliberately leave ssh running so the user stays in session
            pass


def main():
    ap = argparse.ArgumentParser(prog="scpback")
ap.add_argument("--mode", choices=["auto","scp","osc"], default="auto", help="Transfer mode preference (default: auto)")
    ap.add_argument("--ssh", required=True, nargs='+',
                    help="SSH target split into argv form: user@host (or pass through multiple args)"
                    )
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--pull", help="Pull a file from remote (auto-detect transfer mode)")
    grp.add_argument("--resolve", help="Resolve candidate path on remote")
    grp.add_argument("--find", help="Find remote files matching pattern")
    grp.add_argument("--request", help="Write an OSC-1337 XFER-REQUEST into an ssh PTY")
    ap.add_argument("--mode", choices=["auto","scp","osc"], default="auto", help="Transfer mode for --pull (default: auto)")
    ap.add_argument("--dir", default='.', help="Start directory for find (default: .)")
    ap.add_argument("--max", type=int, default=50, help="Max results for find")
    ap.add_argument("--timeout", type=int, default=5, help="Timeout seconds for PTY readback")

    args = ap.parse_args()

    ssh_target = args.ssh[0] if len(args.ssh) == 1 else None

    # If a singlessh token passed (user@host), use run_ssh_command API which accepts that form.
    if args.pull:
        # unified pull logic
        target = args.pull
        mode = args.mode
        # auto-detect: tty + TERM indicates OSC support
        if mode == "auto":
            if sys.stdout.isatty() and os.environ.get("TERM","" ).lower() in ("xterm-256color","wezterm","iterm2","kitty","xterm-kitty"):
                mode = "osc"
            else:
                mode = "scp"
        if mode == "scp":
            if not ssh_target:
                print("pull (scp mode) requires a single ssh target like user@host", file=sys.stderr)
                sys.exit(2)
            try:
                resolved = resolve_remote(ssh_target, target)
                subprocess.run(["scp", f"{ssh_target}:{resolved}", "."], check=True)
                print(f"Copied to ./`basename {target}`")
            except Exception as e:
                print(f"ERROR (scp pull): {e}", file=sys.stderr)
                sys.exit(1)
        else:  # osc
            ok, out = request_via_pty(args.ssh, target, timeout=args.timeout)
            if ok:
                print("OSC request sent; remote side must perform the transfer.", file=sys.stderr)
                sys.exit(0)
            else:
                print("OSC request failed.", file=sys.stderr)
                sys.exit(1)

    if args.pull:
        target = args.pull
        mode = args.mode
        ssh_target = args.ssh[0] if len(args.ssh) == 1 else None
        if not ssh_target:
            print("pull mode requires a single ssh target like user@host", file=sys.stderr)
            sys.exit(2)
        # Resolve remote path
        try:
            resolved = resolve_remote(ssh_target, target)
        except Exception as e:
            print(f"ERROR resolving path: {e}", file=sys.stderr)
            sys.exit(1)
        # Detect OSC-capable terminal (very simple heuristic)
        osc_ok = False
        if mode == "osc" or (mode == "auto" and sys.stdout.isatty() and os.environ.get("TERM", "").lower() in ("xterm-256color", "wezterm", "iTerm2", "kitty")):
            osc_ok = True
        # Prefer OSC if selected/available
        if osc_ok:
            ok, out = request_via_pty(args.ssh, resolved, timeout=args.timeout)
            if ok:
                print(f"Requested remote file via OSC: {resolved}", file=sys.stderr)
                sys.exit(0)
            # fallback to scp
        # SCP fallback or mode=scp
        rc = subprocess.call(["scp", f"{ssh_target}:{resolved}", "."])
        sys.exit(rc)

    if args.resolve:
        if not ssh_target:
            print("resolve mode requires a single ssh target like user@host", file=sys.stderr)
            sys.exit(2)
        try:
            r = resolve_remote(ssh_target, args.resolve)
            print(r)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.find:
        if not ssh_target:
            print("find mode requires a single ssh target like user@host", file=sys.stderr)
            sys.exit(2)
        try:
            hits = find_remote(ssh_target, args.find, start_dir=args.dir, max_results=args.max)
            for h in hits:
                print(h)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.request:
        # request expects arbitrary ssh argv so we pass the whole list
        ok, out = request_via_pty(args.ssh, args.request, timeout=args.timeout)
        if ok:
            print("WROTE XFER-REQUEST into PTY. Partial readback (may be empty):\n", file=sys.stderr)
            sys.stderr.write(out)
            sys.exit(0)
        else:
            print("Failed to write request into PTY", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()

