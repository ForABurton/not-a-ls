#!/usr/bin/env python3
"""
rzsz1337modem.py:  OSC 1337 sz/rz analog with IHAZ / IHAZBELLY handshake.


Example:
./rzsz1337modem.py --test | ./rzsz1337modem.py --receive --dry
TERM=xterm-256color ./rzsz1337modem.py --ssh pi@puesto --verbose

./rzsz1337modem.py --send long.log
./rzsz1337modem.py --request testo.txt --verbose

"""

import sys, os, json, base64, argparse, time, re, tempfile
import pty, select, tty, termios, signal, fcntl, struct

MAX_FILE_SIZE = 512 * 1024 * 1024

OSC_PATTERN = re.compile(
    rb'\x1b]1337;(XFER-(START|CHUNK|END|REQUEST|IHAZ|IHAZBELLY))=?([^ \x1b\x07]*)(?:\x07|\x1b\\)'
)

from datetime import datetime

def log(_):
    # Default: do nothing unless verbose is enabled inside SSH mode.
    pass


# ------------------- Emit -------------------

def _emit(write, b):
    write(b)

def emit_start(meta, write):
    write(b'\x1b]1337;XFER-START=' +
          json.dumps(meta,separators=(',',':')).encode() +
          b'\x07')

def emit_chunk(data, write, size=60000):
    for i in range(0, len(data), size):
        write(b'\x1b]1337;XFER-CHUNK=' +
              base64.b64encode(data[i:i+size]) +
              b'\x07')

def emit_end(write):
    write(b'\x1b]1337;XFER-END\x07')


def emit_ihaz(path, write):
    msg = json.dumps({"path": path}, separators=(',',':')).encode()
    write(b'\x1b]1337;XFER-IHAZ=' + msg + b'\x07')

def emit_ihazbelly(path, write):
    msg = json.dumps({"path": path}, separators=(',',':')).encode()
    write(b'\x1b]1337;XFER-IHAZBELLY=' + msg + b'\x07')





# ------------------- Send -------------------

def send_file(path, dry, write):
    if dry:
        print(f"[dry-run] Would send: {path}", file=sys.stderr); return
    st = os.stat(path)
    meta = {"path": os.path.basename(path), "size": st.st_size, "mtime": int(st.st_mtime)}
    with open(path, "rb") as f: data = f.read()
    emit_start(meta, write)
    emit_chunk(data, write) 
    emit_end(write)


# ------------------- Receive Core -------------------

def _receive_stream_from(src, dry):
    buf=bytearray()
    state=None; meta=None; temp=None; received=0

    while True:
        chunk=src.read(4096)
        if not chunk: break
        buf.extend(chunk)

        while True:
            m=OSC_PATTERN.search(buf)
            if not m:
                if len(buf)>2048:
                    sys.stdout.buffer.write(buf[:-2048])
                    del buf[:-2048]
                break

            start,end=m.span()
            sys.stdout.buffer.write(buf[:start])
            seq=m.group(1).decode()
            content=m.group(3)
            del buf[:end]

            if seq=="XFER-START":
                meta=json.loads(content.decode())
                received=0
                if dry:
                    print(f"[dry-run] Would receive {meta}", file=sys.stderr)
                    state="receiving"; temp=None
                else:
                    fd,temp=tempfile.mkstemp(prefix="rzsz1337-"); os.close(fd)
                    state="receiving"

            elif seq=="XFER-CHUNK" and state=="receiving":
                raw=base64.b64decode(content)
                received+=len(raw)
                if received>MAX_FILE_SIZE:
                    print("[abort] exceeds max size", file=sys.stderr)
                    if temp and os.path.exists(temp): os.remove(temp)
                    state=None; meta=None; temp=None; received=0
                    continue
                if not dry:
                    with open(temp,"ab") as f: f.write(raw)

            elif seq=="XFER-END" and state=="receiving":
                if not dry and temp:
                    final=meta.get("path","received")
                    if os.path.exists(final):
                        final+="."+str(int(time.time()))
                    os.rename(temp,final)
                    os.utime(final,(time.time(),meta.get("mtime",time.time())))
                    print(f"[receive] Saved {final} ({received} bytes)", file=sys.stderr)
                state=None; meta=None; temp=None; received=0

        sys.stdout.buffer.flush()

def receive_stream(dry):
    _receive_stream_from(sys.stdin.buffer,dry)

def receive_from_tty(dry):
    with open("/dev/tty","rb",buffering=0) as t: _receive_stream_from(t,dry)

# ------------------- Interactive SSH -------------------

def run_ssh_interactive(args):


    verbose = args.verbose

    from datetime import datetime
    def log(msg):
        if verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}",
                  file=sys.stderr, flush=True)




    orig = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())

    # These must be declared *here* so handle() can nonlocal them:
    state = None
    meta = None
    temp = None
    received = 0
    
    # args: has .verbose and (optionally) .bridge
    bridge_mode = getattr(args, "bridge", False)

    def handle(data):
        nonlocal state, meta, temp, received
        out = bytearray()
        i = 0
        while True:
            m = OSC_PATTERN.search(data, i)
            if not m:
                out.extend(data[i:])
                return bytes(out)

            start, end = m.span()
            # everything before the OSC match is passthrough
            if start > i:
                passthru_len = start - i
                out.extend(data[i:start])
                log(f"[passthru] wrote {passthru_len} bytes to terminal")

            seq = m.group(1).decode('ascii', errors='ignore')
            content = m.group(3) or b''


            log(f"[osc] seq={seq} span=({start},{end}) content_len={len(content)}")

            # REQUEST: remote is asking US to send them a file
            if seq == "XFER-REQUEST":
                try:
                    req = json.loads(content.decode())
                    p = req.get("path")
                except:
                    i = end
                    continue

                # Resolve file path locally (absolute or relative)
                if p:
                    cand = p
                    if not os.path.isabs(cand):
                        cand = os.path.join(os.getcwd(), cand)

                    if os.path.exists(cand):
                        emit_ihaz(cand, pty_write)
                        log(f"[IHAZ] offering {cand!r} to remote")
                    else:
                        log(f"[IHAZ-NOPE] remote asked for missing file {p!r}")

                i = end
                continue



            # IHAZ: remote confirms it *has* the requested file and intends to send it
            if seq == "XFER-IHAZ":
                try:
                    info = json.loads(content.decode())
                    p = info.get("path")
                except:
                    i = end
                    continue

                # we are receiver-to-be → prepare receiving area
                # reply with belly signal
                emit_ihazbelly(p, pty_write)
                i = end
                continue


            # IHAZBELLY: receiver says "belly open, commence feeding"
            if seq == "XFER-IHAZBELLY":
                try:
                    info = json.loads(content.decode())
                    p = info.get("path")
                except:
                    i = end
                    continue

                # we are the sender now → send now
                # If the IHAZ path is not absolute, try to resolve it in cwd
                send_path = p if p and os.path.isabs(p) else (os.path.join(os.getcwd(), p) if p else p)
                send_file(send_path, args.dry, pty_write)
                i = end
                continue


            # START receiving
            if seq == "XFER-START":
                try:
                    meta = json.loads(content.decode())
                except Exception as e:
                    log(f"[start] JSON decode error: {e}; raw={content[:80]!r}")
                    i = end
                    continue

                try:
                    fd, temp = tempfile.mkstemp(prefix="rzsz1337-")
                    os.close(fd)
                    received = 0
                    state = "receiving"
                    log(f"[start] meta={meta} temp={temp}")
                except Exception as e:
                    log(f"[start] temp file error: {e!r}")
                    state = None
                    temp = None
                i = end
                continue

            # CHUNK receive
            if seq == "XFER-CHUNK" and state == "receiving":
                try:
                    raw = base64.b64decode(content)
                except Exception as e:
                    log(f"[chunk] base64 decode error: {e!r}; b64_len={len(content)}")
                    i = end
                    continue

                received += len(raw)
                log(f"[chunk] got {len(raw)} bytes (total={received}) -> {temp}")
                try:
                    with open(temp, "ab") as f:
                        f.write(raw)
                except Exception as e:
                    log(f"[chunk] write error: {e!r} (temp={temp})")
                    state = None
                    temp = None
                    received = 0
                i = end
                continue

            # END receive
            if seq == "XFER-END" and state == "receiving":
                final = meta.get("path", "received") if meta else "received"
                if os.path.exists(final):
                    final += "." + str(int(time.time()))
                try:
                    os.rename(temp, final)
                    os.utime(final, (time.time(), meta.get("mtime", time.time()) if meta else time.time()))
                    log(f"[end] saved {final} ({received} bytes)")
                except Exception as e:
                    log(f"[end] finalize error: {e!r} temp={temp} final={final}")

                state = None
                meta = None
                temp = None
                received = 0
                i = end
                continue

            # Unknown OSC subtype (pass through silently, but log)
            log(f"[osc] unhandled seq={seq}; passing through without action")
            i = end
            continue


    # fork + ssh PTY setup is unchanged below this line
    pid, fd = pty.fork()
    
    def pty_write(data: bytes):
        os.write(fd, data)


    if pid == 0:
        os.execvp("ssh", ["ssh", "-tt"] + args.ssh)
        sys.exit(1)

    def resize(*_):
        try:
            rows, cols = os.popen("stty size").read().split()
            fcntl.ioctl(fd, tty.TIOCSWINSZ, struct.pack("HHHH", int(rows), int(cols), 0, 0))
        except:
            pass
    signal.signal(signal.SIGWINCH, resize)
    resize()


    try:
        while True:
            r, _, _ = select.select([fd, sys.stdin], [], [])
            if fd in r:
                try:
                    d = os.read(fd, 4096)
                except OSError:
                    break
                if not d:
                    break
                sys.stdout.buffer.write(handle(d))
                sys.stdout.buffer.flush()
            local_inbuf = bytearray()

            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 4096)
                if not d:
                    continue

                if bridge_mode:
                    # Add new input to the buffer first
                    local_inbuf.extend(d)

                    # Look for a newline to know when the user finished a command
                    nl_pos = None
                    for sep in (b'\n', b'\r'):
                        p = local_inbuf.find(sep)
                        if p != -1 and (nl_pos is None or p < nl_pos):
                            nl_pos = p

                    # If no newline yet → user might be typing password or partial command
                    if nl_pos is None:
                        # In password mode, we always forward keystrokes immediately:
                        try:
                            os.write(fd, d)
                        except:
                            pass

                        # prevent buffer growing out of control
                        if len(local_inbuf) > 4096:
                            local_inbuf.clear()

                        continue

                    # We *do* have a full line now
                    line = bytes(local_inbuf[:nl_pos + 1])
                    del local_inbuf[:nl_pos + 1]

                    text = line.decode(errors="ignore").rstrip("\r\n")

                    # ----------- INTERCEPT COMMAND HERE -----------
                    if text.startswith("/request "):
                        req_path = text.split(" ", 1)[1]
                        if verbose:
                            print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [bridge] requesting {req_path!r}",
                                  file=sys.stderr, flush=True)

                        req = json.dumps({"path": req_path}, separators=(',',':')).encode()
                        pty_write(b'\x1b]1337;XFER-REQUEST=' + req + b'\x07')
                        # DO NOT FORWARD THIS LINE TO REMOTE
                        continue
                    # -----------------------------------------------

                    # Normal line → forward exactly once
                    try:
                        os.write(fd, line)
                    except:
                        pass

                else:
                    # Normal mode passthrough
                    os.write(fd, d)





    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, orig)


# ------------------- CLI -------------------

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--send")
    ap.add_argument("--receive",action="store_true")
    ap.add_argument("--ssh",nargs="+")
    ap.add_argument("--request")
    ap.add_argument("--dry",action="store_true")
    ap.add_argument("--test",action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--bridge", action="store_true")


    args=ap.parse_args()

    if args.test:
        d = b"hello\n" * 4
        emit_start({"path": "test.txt", "size": len(d), "mtime": int(time.time())}, sys.stdout.buffer.write)
        emit_chunk(d, sys.stdout.buffer.write)
        emit_end(sys.stdout.buffer.write)
        return



    if args.request:
        import threading, io

        verbose = args.verbose

        from datetime import datetime
        def dbg(*a):
            print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] [request-mode-puller]",
                  *a, file=sys.stderr, flush=True)

        stop_flag = False

        def pre_receive():
            dbg("pre-receive thread started (waiting for XFER-READY / START / CHUNK / END)")
            buffer = bytearray()
            while not stop_flag:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if sys.stdin in r:
                    chunk = sys.stdin.buffer.read1(4096)
                    if not chunk:
                        dbg("pre-receive: stdin closed")
                        return
                    buffer.extend(chunk)

                    while True:
                        m = OSC_PATTERN.search(buffer)
                        if not m:
                            break

                        seq = m.group(1).decode(errors="replace")
                        content = m.group(3)
                        start_i, end_i = m.span()
                        del buffer[:end_i]

                        dbg(f"caught early seq={seq}")

                        # READY means: remote wants us to send
                        if seq == "XFER-IHAZ":
                            try:
                                p = json.loads(content.decode()).get("path")
                            except:
                                p = None
                            dbg(f"→ EARLY IHAZ detected, we are receiver → replying with IHAZBELLY for {p!r}")
                            emit_ihazbelly(p, sys.stdout.buffer.write)
                            dbg("sent IHAZBELLY, switching to full receive mode")
                            return

                        elif seq == "XFER-IHAZBELLY":
                            try:
                                p = json.loads(content.decode()).get("path")
                            except:
                                p = None
                            dbg(f"→ EARLY IHAZBELLY detected, we are sender → sending file now: {p!r}")
                            send_file(p, args.dry, sys.stdout.buffer.write)
                            dbg("send complete, switching to full receive mode")
                            return


            dbg("pre-receive thread exiting")

        dbg("Trying to start requester recv thread")
        recv_thread = threading.Thread(target=pre_receive, daemon=True)
        dbg("Thread constructed")
        recv_thread.start()

        # --------------------------------------------------------------
        # **NOW** we emit the request — listener is already up
        # --------------------------------------------------------------
        dbg(f"sending XFER-REQUEST for {args.request!r}")
        req = json.dumps({"path": args.request}, separators=(',',':')).encode()
        sys.stdout.buffer.write(b'\x1b]1337;XFER-REQUEST=' + req + b'\x07')
        sys.stdout.buffer.flush()
        dbg("request sent, entering main receive loop")

        # --------------------------------------------------------------
        # Main receive loop continues normally (foreground)
        # --------------------------------------------------------------
        try:
            receive_stream(args.dry)
        finally:
            dbg("shutting down pre-receive thread")
            stop_flag = True
            recv_thread.join(timeout=0.2)
            dbg("pre-receive stopped cleanly")

        return



    if args.ssh: return run_ssh_interactive(args)
    if args.send:
        return send_file(args.send, args.dry, sys.stdout.buffer.write)
    if args.receive:
        return receive_stream(args.dry)


    ap.print_help()

if __name__=="__main__":
    main()

