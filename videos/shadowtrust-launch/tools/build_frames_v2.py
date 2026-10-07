"""Writes the seven frame sub-compositions of the ShadowTrust launch video.
usage: python build_frames.py <project dir>
Each file is one bare <template> fragment, as the frame-worker contract asks."""
import sys, os

OUT = os.path.join(sys.argv[1], "compositions", "frames")
os.makedirs(OUT, exist_ok=True)

GSAP = '<script src="https://cdn.jsdelivr.net/npm/gsap@3.14.2/dist/gsap.min.js"></script>'

FONTS = """
    @font-face { font-family: 'Inter'; font-style: normal; font-weight: 300; src: url("assets/fonts/Inter-Light.woff2") format("woff2"); }
    @font-face { font-family: 'Inter'; font-style: normal; font-weight: 400; src: url("assets/fonts/Inter-Regular.woff2") format("woff2"); }
    @font-face { font-family: 'Inter'; font-style: normal; font-weight: 500; src: url("assets/fonts/Inter-Medium.woff2") format("woff2"); }
    @font-face { font-family: 'Inter'; font-style: normal; font-weight: 600; src: url("assets/fonts/Inter-SemiBold.woff2") format("woff2"); }
    @font-face { font-family: 'Source Code Pro'; font-style: normal; font-weight: 400; src: url("assets/fonts/SourceCodePro-400.woff2") format("woff2"); }
    @font-face { font-family: 'Source Code Pro'; font-style: normal; font-weight: 500; src: url("assets/fonts/SourceCodePro-500.woff2") format("woff2"); }
    #root { position: absolute; inset: 0; width: 1920px; height: 1080px; overflow: hidden; font-family: 'Inter', sans-serif; color: #061B31; }
"""

# the ShadowTrust eye mark (assets/logo-950db3e1.svg), inlined so its two colours can be set
MARK = ('<svg viewBox="0 0 28 28" fill="none"><path d="M2.500 14c3-5.300 7-8 11.500-8s8.500 2.700 11.500 8c-3 5.300-7 8-11.500 8S5.500 19.300 2.500 14Z" '
        'stroke="#061B31" stroke-width="2.400" stroke-linejoin="round"></path><circle cx="14" cy="14" r="4.200" fill="#533AFD"></circle></svg>')

# shared helpers, repeated in every frame because each sub-composition is self-contained
JS_HEAD = """
      const root = document.querySelector('[data-composition-id="%(id)s"]');
      const $ = (sel) => root.querySelector(sel);
      const tl = gsap.timeline({ paused: true });
      // split a line into word spans so each word can land on its own beat
      function words(el) {
        const parts = el.textContent.trim().split(' ');
        el.textContent = '';
        return parts.map((w, i) => {
          const s = document.createElement('span');
          s.textContent = w;
          s.style.display = 'inline-block';
          el.appendChild(s);
          if (i < parts.length - 1) el.appendChild(document.createTextNode(' '));
          return s;
        });
      }
      // per-word staggered reveal: start times are computed once from the word list
      function reveal(el, at, step, rise) {
        words(el).forEach((w, i) => {
          tl.fromTo(w, { opacity: 0, y: rise }, { opacity: 1, y: 0, duration: 0.8, ease: 'power3.out' }, at + i * step);
        });
      }
"""
JS_TAIL = """
      window.__timelines = window.__timelines || {};
      window.__timelines["%(id)s"] = tl;
"""


def frame(fid, dur, css, body, js):
    k = {"id": fid}
    html = f"""<template>
  <style>{FONTS}{css}
  </style>

  <div id="root" data-composition-id="{fid}" data-width="1920" data-height="1080">
{body}
  </div>

  {GSAP}
  <script>
    (function () {{{JS_HEAD % k}{js}{JS_TAIL % k}    }})();
  </script>
</template>
"""
    open(os.path.join(OUT, fid + ".html"), "w").write(html)
    print("wrote", fid, f"{dur}s", len(html), "bytes")


def clips(prefix, dur, inner, fid):
    # stable ids give Studio an edit target for each timeline clip; they start with a letter so plain #id selectors work
    return f"""    <div id="{prefix}-ground" class="clip {prefix}-ground" data-start="0" data-duration="{dur}" data-track-index="0"></div>
    <div id="{prefix}-stage" class="clip {prefix}-stage" data-start="0" data-duration="{dur}" data-track-index="1">
{inner}
    </div>"""


BASE = lambda p: f"""
    .{p}-ground {{ position: absolute; inset: 0; background: #FFFFFF; }}
    .{p}-stage {{ position: absolute; inset: 0; }}"""

# ---------------------------------------------------------------- 01 Let them in
frame("01-let-them-in", 4.5, BASE("f01") + """
    .f01-ribbon { position: absolute; left: 240px; top: -60px; width: 1920px; height: 1080px; transform-origin: 100% 0%; }
    .f01-brand { position: absolute; left: 150px; top: 92px; display: flex; align-items: center; gap: 14px; font-size: 38px; font-weight: 600; letter-spacing: -0.03em; transform-origin: 0% 50%; }
    .f01-brand svg { width: 50px; height: 50px; }
    .f01-line { position: absolute; left: 150px; font-size: 164px; font-weight: 300; letter-spacing: -0.04em; line-height: 1; white-space: nowrap; }
    .f01-l1 { top: 262px; }
    .f01-l2 { top: 446px; color: #50617A; }""",
      clips("f01", 4.5, f"""      <img class="f01-ribbon" src="assets/ribbon.png" alt="">
      <div class="f01-brand">{MARK}<span>ShadowTrust</span></div>
      <div class="f01-line f01-l1" data-layout-allow-overlap>Let them in.</div>
      <div class="f01-line f01-l2" data-layout-allow-overlap>Watch every move.</div>""", "01-let-them-in"),
      """
      // Scene 1 (0.0 to 1.5s): the first line lands alone, word by word
      reveal($('.f01-l1'), 0.1, 0.16, 44);

      // Scene 2 (1.5 to 3.1s): the ribbon grows out of the top right corner, the second line follows
      tl.fromTo($('.f01-ribbon'), { scale: 0, opacity: 0 }, { scale: 1, opacity: 1, duration: 1.5, ease: 'power3.out' }, 1.5);
      reveal($('.f01-l2'), 1.8, 0.16, 44);

      // Scene 3 (3.1 to 4.5s): the mark and name settle, then everything holds
      tl.fromTo($('.f01-brand'), { scale: 0, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.6, ease: 'power3.out' }, 3.1);
""")

# ---------------------------------------------------------------- 02 to 10: real screen recordings
# One layout for every recording: the clip in a hairline window, one label line under it.
# The <video> is declared as an approved frame video; assemble-index.mjs hoists it to the host root.
FOOTAGE = [
    ("02-live-attack", "f02", "clip-live.mp4", 11.5, "Event log", "A brute force arrives. A case opens."),
    ("03-investigations", "f03", "clip-investigate.mp4", 11.3, "Investigations", "Open the case. Read what happened."),
    ("04-attack-matrix", "f04", "clip-mitre.mp4", 5.6, "MITRE ATT&amp;CK", "Techniques seen, by tactic."),
    ("05-geo", "f05", "clip-geo.mp4", 8.5, "Geo intelligence", "Where it comes from."),
    ("06-credential-vault", "f06", "clip-creds.mp4", 5.6, "Credential vault", "Every password they tried."),
    ("07-url-scanner", "f07", "clip-urlscan.mp4", 9.5, "URL scanner", "A real scan, start to verdict."),
    ("08-analysis-lab", "f08", "clip-lab.mp4", 10.5, "Analysis lab", "Commands profiled as they run."),
    ("09-reports", "f09", "clip-reports.mp4", 12, "Reports", "Generate. Preview. Download."),
    ("10-wallboard", "f10", "clip-wall.mp4", 6, "Wallboard", "For the big screen."),
]
for fid, p, clip, dur, name, desc in FOOTAGE:
    frame(fid, dur, BASE(p) + f"""
    .{p}-window {{ position: absolute; left: 126.5px; top: 34.5px; width: 1667px; height: 939px; border: 1.5px solid rgba(83, 58, 253, 0.2); background: #FFFFFF; }}
    .{p}-band {{ position: absolute; left: 128px; top: 992px; width: 1664px; height: 60px; display: flex; align-items: center; gap: 18px; }}
    .{p}-dot {{ flex: none; width: 14px; height: 14px; border-radius: 50%; background: #533AFD; }}
    .{p}-name {{ font-size: 32px; font-weight: 500; letter-spacing: -0.02em; white-space: nowrap; }}
    .{p}-desc {{ font-size: 30px; font-weight: 400; letter-spacing: -0.01em; color: #50617A; white-space: nowrap; }}
    .{p}-brand {{ margin-left: auto; display: flex; align-items: center; gap: 10px; font-size: 26px; font-weight: 600; letter-spacing: -0.03em; }}
    .{p}-brand svg {{ width: 32px; height: 32px; }}""",
          clips(p, dur, f"""      <div class="{p}-window"></div>
      <div class="{p}-band">
        <i class="{p}-dot"></i><span class="{p}-name">{name}</span><span class="{p}-desc">{desc}</span>
        <div class="{p}-brand">{MARK}<span>ShadowTrust</span></div>
      </div>""", fid) + f"""
    <video data-frame-video="approved" id="{p}-clip" src="assets/{clip}" muted playsinline data-start="0" data-duration="{dur}" data-track-index="2" data-frame-video-x="128" data-frame-video-y="36" data-frame-video-width="1664" data-frame-video-height="936" data-frame-video-fit="fill"></video>""",
          f"""
      // Scene 1: the recording plays for the whole frame (it is mounted at the host root by the assembler).
      // Scene 2 (0.2 to 1.2s): the label line arrives under the window, then holds still.
      tl.fromTo($('.{p}-dot'), {{ scale: 0, opacity: 0 }}, {{ scale: 1, opacity: 1, duration: 0.45, ease: 'power3.out' }}, 0.2);
      tl.fromTo($('.{p}-name'), {{ opacity: 0, y: 16 }}, {{ opacity: 1, y: 0, duration: 0.6, ease: 'power3.out' }}, 0.28);
      tl.fromTo($('.{p}-desc'), {{ opacity: 0, y: 16 }}, {{ opacity: 1, y: 0, duration: 0.6, ease: 'power3.out' }}, 0.5);
""")

# ---------------------------------------------------------------- 11 Sign-off
frame("11-sign-off", 6, BASE("f11") + """
    .f11-ribbon { position: absolute; left: 240px; top: -60px; width: 1920px; height: 1080px; transform-origin: 100% 0%; }
    .f11-lock { position: absolute; left: 0; top: 268px; width: 1920px; display: flex; align-items: center; justify-content: center; gap: 30px; font-size: 132px; font-weight: 600; letter-spacing: -0.03em; line-height: 1; }
    .f11-lock svg { width: 150px; height: 150px; }
    .f11-line { position: absolute; left: 0; top: 468px; width: 1920px; text-align: center; font-size: 44px; font-weight: 300; letter-spacing: -0.02em; color: #50617A; }
    .f11-cmdrow { position: absolute; left: 0; top: 584px; width: 1920px; display: flex; justify-content: center; }
    .f11-cmd { display: flex; align-items: baseline; gap: 16px; padding: 20px 44px; border-radius: 100px; background: rgba(83, 58, 253, 0.08); font-family: 'Source Code Pro', monospace; font-size: 40px; font-weight: 500; white-space: pre; }
    .f11-prompt { color: #7D8BA4; }
    .f11-wrap { display: inline-flex; align-items: baseline; min-width: 264px; white-space: pre; }
    .f11-text { white-space: pre; color: #061B31; }
    .f11-cursor { display: inline-block; width: 14px; height: 38px; margin-left: 4px; background: #7D8BA4; vertical-align: -6px; }
    .f11-note { position: absolute; left: 0; top: 706px; width: 1920px; text-align: center; font-size: 30px; font-weight: 400; color: #50617A; }""",
      clips("f11", 6, f"""      <img class="f11-ribbon" src="assets/ribbon.png" alt="">
      <div class="f11-lock">{MARK}<span>ShadowTrust</span></div>
      <div class="f11-line">Deception and security operations, self-hosted.</div>
      <div class="f11-cmdrow"><div class="f11-cmd"><span class="f11-prompt">$</span><span class="f11-wrap"><span class="f11-text"></span><span class="f11-cursor"></span></span></div></div>
      <div class="f11-note">One Docker Compose stack</div>""", "11-sign-off"),
      """
      const DURATION = 6;

      // Scene 1 (0.0 to 1.4s): the mark and name settle as one centred lockup
      tl.fromTo($('.f11-lock'), { scale: 0, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.7, ease: 'power3.out' }, 0.05);

      // Scene 2 (1.4 to 3.0s): the line, word by word, while the ribbon echo grows out of the top right corner
      reveal($('.f11-line'), 1.4, 0.1, 26);
      tl.fromTo($('.f11-ribbon'), { scale: 0, opacity: 0 }, { scale: 1, opacity: 0.9, duration: 1.4, ease: 'power3.out' }, 1.6);

      // Scene 3 (3.0 to 5.2s): the command pill appears and the command types on behind a caret
      tl.fromTo($('.f11-cmd'), { scale: 0, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.5, ease: 'power3.out' }, 3.0);
      const COMMAND = './setup.sh';
      const SEQUENCE = [{ t: 0, text: '', color: '#7D8BA4' }];
      for (let i = 1; i <= COMMAND.length; i++) SEQUENCE.push({ t: 3.4 + (i - 1) * 0.11, text: COMMAND.slice(0, i), color: '#533AFD' });
      function entryAt(time) {
        for (let i = SEQUENCE.length - 1; i >= 0; i--) if (time >= SEQUENCE[i].t) return SEQUENCE[i];
        return SEQUENCE[0];
      }
      const textEl = $('.f11-text');
      const cursorEl = $('.f11-cursor');
      const driver = { t: 0 };
      let lastText = null;
      tl.to(driver, { t: DURATION, duration: DURATION, ease: 'none', onUpdate: () => {
        const entry = entryAt(driver.t);
        if (entry.text !== lastText) { textEl.textContent = entry.text; cursorEl.style.background = entry.color; lastText = entry.text; }
      } }, 0);
      // caret blink: a timeline-driven square wave, a whole number of cycles over the frame
      const blink = { p: 0 };
      tl.to(blink, { p: Math.PI * 2 * 8, duration: DURATION, ease: 'none', onUpdate: () => { cursorEl.style.opacity = Math.sin(blink.p) >= 0 ? '1' : '0'; } }, 0);
      tl.fromTo($('.f11-note'), { opacity: 0, y: 16 }, { opacity: 1, y: 0, duration: 0.6, ease: 'power3.out' }, 4.7);

      // Scene 4 (5.2 to 6.0s): hold, then the only exit in the video, a fade to the white ground
      tl.to($('.f11-stage'), { opacity: 0, duration: 0.55, ease: 'power2.in' }, 5.45);
""")
