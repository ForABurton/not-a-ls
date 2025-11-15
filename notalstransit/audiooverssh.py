#!/usr/bin/env python3
import sys, os, re, pty, select, tty, termios, fcntl, struct, subprocess, signal, queue, threading, time, json, base64
import argparse
import opuslib
import pyaudio
import wave

OSC = b"\x1b]1791;"
BEL = b"\x07"

SAMPLE_RATE = 48000
FRAME_SIZE = 960
CHANNELS = 1
BITRATE = 32000

# Per-channel stereo gain map
PAN = {
    "voice": (1.0, 1.0),
}

OSC_AUDIO_PATTERN = re.compile(
    rb"\x1b\]1791;AUDIO-FRAME=([^ \x1b\x07]+)(?:\x07|\x1b\\)"
)

def make_encoder():
    enc = opuslib.Encoder(SAMPLE_RATE, CHANNELS, opuslib.APPLICATION_AUDIO)
    enc.bitrate = BITRATE
    return enc

def make_decoder():
    return opuslib.Decoder(SAMPLE_RATE, CHANNELS)

def mic_capture_thread(send_queue):
    pa = pyaudio.PyAudio()
    enc = make_encoder()
    stream = pa.open(format=pyaudio.paInt16, channels=1, rate=SAMPLE_RATE, input=True, frames_per_buffer=FRAME_SIZE)
    while True:
        data = stream.read(FRAME_SIZE, exception_on_overflow=False)
        try:
            send_queue.put(("voice", enc.encode(data, FRAME_SIZE)))
        except:
            pass

def play_file_thread(send_queue, path):
    if not os.path.exists(path):
        return
    enc = make_encoder()
    try:
        w = wave.open(path, 'rb')
    except:
        return
    while True:
        raw = w.readframes(FRAME_SIZE)
        if not raw:
            break
        try:
            pkt = enc.encode(raw, FRAME_SIZE)
        except:
            pkt = b""
        send_queue.put(("voice", pkt))
        time.sleep(0.02)

def audio_output_thread(recv_queue):
    pa = pyaudio.PyAudio()
    stream = pa.open(format=pyaudio.paInt16, channels=2, rate=SAMPLE_RATE, output=True)
    dec_map = {}

    while True:
        mix_l = [0]*FRAME_SIZE
        mix_r = [0]*FRAME_SIZE

        try:
            while True:
                ch, packet = recv_queue.get_nowait()
                if ch not in dec_map:
                    dec_map[ch] = make_decoder()
                try:
                    pcm = dec_map[ch].decode(packet, FRAME_SIZE)
                except:
                    pcm = b"\x00" * (FRAME_SIZE * 2)

                samples = memoryview(pcm).cast('h')
                lg, rg = PAN.get(ch, (1.0, 1.0))

                for i in range(FRAME_SIZE):
                    s = samples[i]
                    mix_l[i] += int(s * lg)
                    mix_r[i] += int(s * rg)

        except queue.Empty:
            pass

        out = bytearray(FRAME_SIZE*4)
        vi = memoryview(out).cast('h')

        for i in range(FRAME_SIZE):
            vi[2*i]   = max(-32768, min(32767, mix_l[i]))
            vi[2*i+1] = max(-32768, min(32767, mix_r[i]))

        stream.write(out)

def emit_audio_frame(ch, data, write):
    payload = json.dumps({
        "ch": ch,
        "b": base64.b64encode(data).decode()
    }, separators=(",", ":")).encode()

    write(OSC + b"AUDIO-FRAME=" + payload + BEL)

def parse_incoming(data, recv_queue):
    i = 0
    out = bytearray()
    while True:
        m = OSC_AUDIO_PATTERN.search(data, i)
        if not m:
            out.extend(data[i:])
            return bytes(out)

        start, end = m.span()
        out.extend(data[i:start])

        try:
            obj = json.loads(m.group(1).decode())
            recv_queue.put((obj["ch"], base64.b64decode(obj["b"])))
        except:
            pass

        i = end

def run_ssh(args, enable_mic, passthru):
    recv_queue = queue.Queue()
    send_queue = queue.Queue()

    if enable_mic:
        threading.Thread(target=mic_capture_thread, args=(send_queue,), daemon=True).start()

    threading.Thread(target=audio_output_thread, args=(recv_queue,), daemon=True).start()

    if passthru:
        fd = sys.stdin.fileno()
        pid = None
    else:
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("ssh", ["ssh", "-tt"] + args)
            sys.exit(1)

    orig = termios.tcgetattr(sys.stdin)
    tty.setraw(sys.stdin.fileno())

    def term_write(b):
        if passthru:
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()
        else:
            os.write(fd, b)

    def resize(*_):
        if not passthru:
            try:
                r, c = os.popen("stty size").read().split()
                fcntl.ioctl(fd, tty.TIOCSWINSZ, struct.pack("HHHH", int(r), int(c), 0, 0))
            except:
                pass

    if not passthru:
        signal.signal(signal.SIGWINCH, resize)
        resize()

    try:
        while True:
            try:
                ch, pkt = send_queue.get_nowait()
                emit_audio_frame(ch, pkt, term_write)
            except queue.Empty:
                pass

            r, _, _ = select.select([fd, sys.stdin], [], [], 0.01)

            if fd in r:
                d = os.read(fd, 4096)
                if not d:
                    break
                sys.stdout.buffer.write(parse_incoming(d, recv_queue))
                sys.stdout.buffer.flush()

            if sys.stdin in r:
                d = os.read(sys.stdin.fileno(), 4096)
                if not d:
                    continue

                # Play command
                if d.startswith(b"/play "):
                    path = d.strip().split(b" ", 1)[1].decode()
                    threading.Thread(target=play_file_thread, args=(send_queue, path), daemon=True).start()
                    continue

                # Mixer command: /pan channel L R
                if d.startswith(b"/pan "):
                    try:
                        _, ch, l, r = d.decode().strip().split()
                        PAN[ch] = (float(l), float(r))
                    except:
                        pass
                    continue

                term_write(d)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, orig)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mic", action="store_true", help="Enable microphone streaming")
    ap.add_argument("--sshwrapperpassthru", action="store_true",
                    help="Do not spawn SSH; wrap existing stream for chaining")
    ap.add_argument("ssh", nargs="*", help="SSH target and arguments (ignored in passthru mode)")
    args = ap.parse_args()

    run_ssh(args.ssh, enable_mic=args.mic, passthru=args.sshwrapperpassthru)

