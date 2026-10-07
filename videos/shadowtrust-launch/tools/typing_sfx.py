"""Builds a soft typing-sound track for one scene from logged keystroke times.

usage: python3 typing_sfx.py <key sample (any audio)> <out.wav> <duration s> <t1> <t2> ...

Each time is a keystroke, in seconds from the start of the scene. One key sample is placed at each
time with a small, repeatable change of pitch and level so it does not sound like a machine gun.
The result is low-passed and its peak set to PEAK_DB, so it sits quietly under the music.
"""
import math, struct, subprocess, sys, wave

RATE = 44100
PEAK_DB = -11.0   # soft: about 10 dB under the music's peaks
LOWPASS_HZ = 5200


def load(sample):
    raw = subprocess.run(["ffmpeg", "-v", "error", "-i", sample, "-ac", "1", "-ar", str(RATE), "-f", "s16le", "-"],
                         capture_output=True, check=True).stdout
    s = [x / 32768.0 for x in struct.unpack("<%dh" % (len(raw) // 2), raw)]
    # start at the click itself, not at leading silence
    peak = max(abs(x) for x in s)
    first = next(i for i, x in enumerate(s) if abs(x) > peak * 0.05)
    return s[max(0, first - 40):]


def resample(s, factor):
    """Play the sample `factor` times faster (higher pitch), linear interpolation."""
    n = int(len(s) / factor)
    out = []
    for i in range(n):
        p = i * factor
        j = int(p)
        f = p - j
        a = s[j]
        b = s[j + 1] if j + 1 < len(s) else 0.0
        out.append(a + (b - a) * f)
    return out


def build(sample_path, duration, times):
    key = load(sample_path)
    buf = [0.0] * int(duration * RATE + RATE // 2)
    for i, t in enumerate(times):
        if t < 0 or t >= duration:
            continue
        # repeatable variation from the key's index (golden-ratio sequence)
        u = (i * 0.618034) % 1.0
        v = (i * 0.381966 + 0.3) % 1.0
        pitch = 0.94 + 0.12 * u
        level = 0.68 + 0.32 * v
        k = resample(key, pitch)
        start = int(t * RATE)
        for j, x in enumerate(k):
            if start + j < len(buf):
                buf[start + j] += x * level
    # one-pole low-pass to take the edge off
    a = math.exp(-2 * math.pi * LOWPASS_HZ / RATE)
    y = 0.0
    for i, x in enumerate(buf):
        y = (1 - a) * x + a * y
        buf[i] = y
    peak = max((abs(x) for x in buf), default=0.0)
    gain = (10 ** (PEAK_DB / 20)) / peak if peak > 0 else 0.0
    return [x * gain for x in buf[:int(duration * RATE)]]


def main():
    sample, out, duration = sys.argv[1], sys.argv[2], float(sys.argv[3])
    times = [float(x) for x in sys.argv[4:]]
    pcm = build(sample, duration, times)
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(b"".join(struct.pack("<h", max(-32767, min(32767, int(x * 32767)))) for x in pcm))
    kept = sum(1 for t in times if 0 <= t < duration)
    print(f"{out}: {kept} keys over {duration:.2f}s, peak {PEAK_DB} dBFS")


def selfcheck():
    """Two keys in a 1s track: silence before the first, a click at each time, peak at PEAK_DB."""
    key = [0.0] * 30 + [0.9, -0.7, 0.4, -0.2, 0.1] + [0.0] * 200
    global load
    real = load
    load = lambda _p: key
    try:
        pcm = build("unused", 1.0, [0.25, 0.75])
    finally:
        load = real
    assert len(pcm) == RATE
    assert max(abs(x) for x in pcm[:int(0.24 * RATE)]) < 1e-6, "sound before the first key"
    for t in (0.25, 0.75):
        seg = pcm[int(t * RATE):int(t * RATE) + 400]
        assert max(abs(x) for x in seg) > 0.05, f"no click at {t}"
    assert abs(20 * math.log10(max(abs(x) for x in pcm)) - PEAK_DB) < 0.2, "peak level off"
    print("typing_sfx self-check ok")


if __name__ == "__main__":
    selfcheck() if len(sys.argv) == 1 else main()
