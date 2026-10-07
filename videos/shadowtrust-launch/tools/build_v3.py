"""Builds the third cut from the camera recordings: trims the clips, makes the typing-sound tracks,
rewrites the storyboard durations, regenerates the frames, extends the music bed and writes
audio_meta.json. Run from the project root:  python3 tools/build_v3.py
Then: assemble-index.mjs, transitions.mjs inject, npx hyperframes check, render."""
import json, os, re, subprocess, sys

ROOT = os.getcwd()
RAW = os.path.join(ROOT, "capture", "raw3")
VID = os.path.join(ROOT, "capture", "assets", "videos")
SFX = os.path.join(ROOT, "assets", "sfx")
KEY_SAMPLE = os.path.expanduser("~/.claude/skills/media-use/audio/assets/sfx/key-press.mp3")

# frame id, class prefix, recording, trim start, trim end (None = its 'end' mark), label, descriptor
SCENES = [
    ("02-live-attack", "f02", "live", 0.35, None, "Event log", "A brute force arrives. A case opens."),
    ("03-investigations", "f03", "investigate", 0.35, None, "Investigations", "Open the case. Read what happened."),
    ("04-attack-matrix", "f04", "mitre", 0.35, None, "MITRE ATT&amp;CK", "Techniques seen, by tactic."),
    ("05-geo", "f05", "geo", 0.3, None, "Geo intelligence", "Where it comes from."),
    ("06-credential-vault", "f06", "creds", 0.35, None, "Credential vault", "Every password they tried."),
    ("07-url-scanner", "f07", "urlscan", 0.35, None, "URL scanner", "A real scan, start to verdict."),
    ("08-analysis-lab", "f08", "lab", 0.3, None, "Analysis lab", "Commands profiled as they run."),
    ("09-reports", "f09", "reports", 0.35, None, "Reports", "Generate. Preview. Download."),
    ("10-wallboard", "f10", "wall", 0.3, None, "Wallboard", "For the big screen."),
]
OPENER, SIGNOFF = 4.5, 6.0
SIGNOFF_KEYS = [3.4 + i * 0.11 for i in range(10)]  # "./setup.sh" as typed in frame 11


def run(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout


def main():
    os.makedirs(VID, exist_ok=True); os.makedirs(SFX, exist_ok=True)
    clips, sfx = [], []
    for n, (fid, p, rec, a, b, label, desc) in enumerate(SCENES, start=2):
        meta = json.load(open(os.path.join(RAW, rec + ".json")))
        end = b if b is not None else dict((l, t) for t, l in meta["marks"])["end"] - 0.05
        d = round((end - a) * 30) / 30  # whole frames
        clip = f"clip3-{rec}.mp4"
        print(run(os.path.join(ROOT, "tools", "cut3.sh"), os.path.join(RAW, rec + ".mp4"), str(a), str(a + d), os.path.join(VID, clip)).strip())
        clips.append({"id": fid, "p": p, "clip": clip, "dur": round(d, 3), "label": label, "desc": desc})
        keys = [round(t - a, 3) for t in meta.get("keys", []) if 0 <= t - a < d]
        if keys:
            out = os.path.join(SFX, f"typing-{rec}.wav")
            print(run(sys.executable, os.path.join(ROOT, "tools", "typing_sfx.py"), KEY_SAMPLE, out, str(d), *map(str, keys)).strip())
            sfx.append({"frame": n, "file": f"assets/sfx/typing-{rec}.wav", "offset_s": 0, "duration_s": round(d, 3), "volume": 1})
    out = os.path.join(SFX, "typing-signoff.wav")
    print(run(sys.executable, os.path.join(ROOT, "tools", "typing_sfx.py"), KEY_SAMPLE, out, str(SIGNOFF), *map(str, SIGNOFF_KEYS)).strip())
    sfx.append({"frame": 11, "file": "assets/sfx/typing-signoff.wav", "offset_s": 0, "duration_s": SIGNOFF, "volume": 1})
    json.dump(clips, open(os.path.join(ROOT, "tools", "clips3.json"), "w"), indent=1)

    total = round(OPENER + sum(c["dur"] for c in clips) + SIGNOFF, 3)

    # storyboard: durations, clip names and the scene description of each footage frame
    sb = open(os.path.join(ROOT, "STORYBOARD.md")).read()
    for n, c in enumerate(clips, start=2):
        m = re.search(r"(## Frame %d — .*?)(?=\n## Frame |\Z)" % n, sb, flags=re.S)
        blk = m.group(1)
        new = re.sub(r"- duration: [\d.]+s", f"- duration: {c['dur']:g}s", blk, count=1)
        new = re.sub(r"clip3?-[a-z]+\.mp4", c["clip"], new)
        new = re.sub(r"clip3?-[a-z]+ = cutout", c["clip"][:-4] + " = cutout", new)
        new = re.sub(r"real screen recording, [\d.]+s, 1664x936, silent", f"real screen recording with a camera that follows the pointer, {c['dur']:g}s, 1664x936", new)
        new = re.sub(r"Scene 1 \(0\.0–[\d.]+s\): the recording plays at real speed", f"Scene 1 (0.0–{c['dur']:g}s): the recording plays at real speed", new)
        sb = sb.replace(blk, new)
    sb = re.sub(r"(?m)^duration: \d+s$", f"duration: {round(total)}s", sb, count=1)
    open(os.path.join(ROOT, "STORYBOARD.md"), "w").write(sb)

    # music bed: 120 bpm, 16s phrases. 0-48, then 16-48 as often as needed, then the 48s outro, fading at the end
    src = os.path.join(ROOT, "assets", "bgm", "track.mp3")
    parts, t = [(0, 48)], 48
    while total - t > 16:
        parts.append((16, 48)); t += 32
        if total - t <= 16: break
    if total - t > 16:  # never happens with 32s steps, kept for safety
        parts.append((32, 48)); t += 16
    parts.append((48, 48 + max(4, total - t) + 0.2))
    fc, labels = [], []
    for i, (a, b) in enumerate(parts):
        fc.append(f"[0]atrim={a}:{b},asetpts=N/SR/TB[p{i}]"); labels.append(f"[p{i}]")
    chain = labels[0]
    for i in range(1, len(labels)):
        fc.append(f"{chain}{labels[i]}acrossfade=d=0.03:c1=tri:c2=tri[x{i}]"); chain = f"[x{i}]"
    fc.append(f"{chain}atrim=0:{total},afade=t=in:st=0:d=0.15,afade=t=out:st={total - 3.5}:d=3.5[out]")
    bed = os.path.join(ROOT, "assets", "bgm", "bed.mp3")
    run("ffmpeg", "-v", "error", "-y", "-i", src, "-filter_complex", ";".join(fc), "-map", "[out]", "-ar", "44100", "-ac", "2", "-c:a", "libmp3lame", "-b:a", "192k", bed)
    print("music bed:", " + ".join(f"{a}-{b:g}s" for a, b in parts), "->", total, "s")

    meta = {"bgm": {"path": "assets/bgm/bed.mp3", "volume": 0.9, "duration_s": total,
                    "note": "library track (68s, 120 bpm) extended on the beat: " + ", ".join(f"{a}-{b:g}s" for a, b in parts)},
            "bgm_pending": False, "voices": [], "sfx": sfx}
    json.dump(meta, open(os.path.join(ROOT, "audio_meta.json"), "w"), indent=2)
    print("total", total, "s;", len(clips), "clips;", len(sfx), "typing tracks")


if __name__ == "__main__":
    main()
