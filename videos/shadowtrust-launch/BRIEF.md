---
workflow: product-launch-video
flow: automation
storyboard: no
message: "ShadowTrust lets attackers in on purpose and turns everything they do into a case you can close."
destination: desktop-presentation
aspect: 1920x1080
language: en
audience: "People seeing the project for the first time: reviewers, recruiters, security engineers"
length: 125s
angle: "Follow one attack from the first packet to the final report"
narration: no
---

## Intent

A launch video for ShadowTrust, a self-hosted honeypot and security operations
platform. The user asked for: "30 to 45 second video of the product built from
the real pages; a separate file". It is for showing the project to other people,
next to the link preview card and the public site.

Concept (chosen by the internal pitch gate, the run is autonomous): "Let them in.
Watch every move." One attacker's visit is followed from the first packet to the
final report, on a bright white canvas. Each step is proved by a real captured
screen of the product. The telling is calm bookkeeping, not a hacker movie.

The typical direction left behind on purpose: a page-by-page product tour with a
feature bullet list, and the dark green-on-black "hacker" look most security
videos use.

## Customizations

- Market the product (a promo), but feature the site's own captured screens as
  the video's assets. No invented interface.
- Capture the signed-in console pages too (overview, investigations, geo
  intelligence, reports), not only the public landing page. They are served at
  http://127.0.0.1:5500 and need the local test token.
- No voice-over. On-screen text carries the message so it works with sound off.
- A music bed if a provider is available without sign-in, otherwise silent.

## Notes

- Brand: light theme. Violet #533afd, navy text #061b31, body grey #50617a,
  hairlines #e5edf5, accents ruby #ea2261, magenta #f44bcc, orange #ff6118,
  lemon #f9b900, sky #4a8cff. Inter (weight 300 headings) and Source Code Pro.
  The ribbon gradient is the signature motif.
- No em dashes anywhere in on-screen text.
- No fake numbers or unsupported claims. Any figure on screen must come from a
  captured real screen or from the repository (6 detection rules, 3 sensors,
  7 ports, 8 report types, 12 core containers).
- Addresses shown in drawn elements use documentation ranges.
- Stripe is a style reference only: no Stripe text, images, logo or font.
- The final MP4 is also copied to deliverables/ in the repository root.
- Decided during the run (2026-10-06): the video is silent. The tool was not signed in to HeyGen and the local voice and music engines were not installed, so there was no provider for a music bed. To add one later, sign in with `npx hyperframes auth login`, set a `music:` mood in STORYBOARD.md and re-run the audio step.
- Fonts: the page capture missed the basic Latin subsets of Inter and Source Code Pro, so the frames use the font files already bundled with the report engine (backend/app/services/reporting/templates/fonts, SIL OFL, licence files copied to assets/fonts).
- frame.md: two muted text tones were corrected by hand to the site's own values (#50617A and #7D8BA4). The preset was chosen by the run, not by the user, so it was not recorded as a preference.
- Extra real assets beyond the page capture are listed at the end of capture/extracted/asset-descriptions.md (signed-in console pages, the ribbon, real PDF pages).
- After editing a frame in compositions/frames/, re-run assemble-index.mjs and transitions.mjs inject before rendering: the injector extends the outgoing frame's clips for the overlap.
- Rendered without a review pause because the request was for the file. Contact sheet: snapshots/contact-sheet.jpg. Frame ids: 01-let-them-in, 02-the-trap, 03-every-move, 04-the-case, 05-who-is-knocking, 06-final-report, 07-sign-off.
- Second cut, 2026-10-07. The user's words after seeing the first cut: "video looks sexy , can we increase the video length and maybe show features working on video ? rather than yapping anything else and put that video on landing page front page somewhere". Then: "npx hyperframes auth login done as well". So: about 90 seconds, nine real screen recordings of features working at real speed, text reduced to one label line per scene, a music bed from the signed-in library, still no voice-over. The first cut is kept as deliverables/ShadowTrust_Launch_Video_v1_39s.mp4 and its project files are in .backup/pre-video-v2-20261007/.
- The Binary analysis page is left out of the recordings because its history shows a file named after a person.
- Raw recordings are in capture/raw/, the trimmed clips in capture/assets/videos/. The recorder scripts were in the session scratch folder (rec.js, scenes.js, cut.sh).
- Second cut delivered 2026-10-07: renders/video.mp4 (91.0s, 1920x1080, H.264 + AAC, 45.8 MB), copied to deliverables/ShadowTrust_Launch_Video.mp4. A web copy (13.3 MB) and poster are in frontend/media/ and play on the landing page (section #film). The project was moved from hyperframes 0.8.137 to 0.8.139 and still passed the check.
- Music: one track retrieved from the signed-in HeyGen library (assets/bgm/track.mp3, 68s, 120 bpm), extended on the beat to 91s as assets/bgm/bed.mp3 (0 to 48s, then 16 to 59s again, fade out from 87.5s). audio_meta.json points at bed.mp3.
- Rebuild order for this cut: python3 tools/build_frames_v2.py . → assemble-index.mjs → transitions.mjs inject → npx hyperframes check → render. The assembler removes each approved <video> from its frame file when it hoists it, so the frames must be regenerated before every assemble.
- tools/ holds the recorder (rec.js, scenes.js), the trimmer (cut.sh) and the frame generator. rec.js reads a test admin JWT from ../token.txt relative to itself and needs puppeteer-core next to it; the stack must be running. Recording fires real traffic at the lab through /api/v1/admin/diagnostics/trigger/*.
- Left out on purpose: the Overview recording (the Dionaea and Honeytrap sensors were not ingesting, so its feed did not move) and Binary analysis (personal file name in its history).
- Third cut, 2026-10-07. The user's words on the second cut: "i didn't like the new video which you made everything is fine but Like closeup shots in some icons and stuff whereever the cursor goes you need to be closeup short if typing addd typing shound soft and zoom out and in in phases or scenes wherever needed". So the content and order stay, and the nine recordings were made again with a camera: it closes in on whatever the pointer touches (a field while it is typed in, a button as it is clicked, the alert, the scores), and pulls back between actions. Soft key sounds follow every typed character.
- How the camera works: tools/rec3.js applies a CSS transform to the page body and animates it in the page, at 2x pixel density, so a close-up is re-drawn sharp by the browser rather than enlarged afterwards. Recordings are 1664x936 (the window size), so nothing is scaled later. Scene scripts: tools/scenes3.js. Raw takes: capture/raw3/.
- Typing sound: tools/typing_sfx.py places the bundled key-press sample (media-use library, Pixabay licence) at each logged keystroke time with small changes of pitch and level, low-passed, peak -11 dBFS. One track per typing scene, mounted through audio_meta.json sfx.
- Build order for this cut: python3 tools/build_v3.py (trims, typing tracks, storyboard durations, music bed, audio_meta) → python3 tools/build_frames_v3.py . → stage-assets → assemble-index → transitions inject → npx hyperframes check → render.
- The alert in the Event log scene needs three things at once, learned the hard way: no open case for the source address (resolve it first), a new 10-minute detection bucket (the brute-force rule is deduplicated per 10 minutes), and the Docker clock in step with the Mac (the alert is only shown for cases under 3 minutes old; the clock lagged after the Mac idled, so keep it awake with caffeinate).
- Delivered: renders/video.mp4 (124.7s, 1920x1080, 97 MB), deliverables/ShadowTrust_Launch_Video.mp4. Second cut kept as deliverables/ShadowTrust_Launch_Video_v2_91s.mp4 and renders/video-v2-91s.mp4. Landing page copy and web video updated (frontend/media, 23.8 MB).
- Landing page, later on 2026-10-07: at the user's request the film now sits right under the hero and grows to fill the window as the page scrolls (modelled on antigravity.google). The web copy in frontend/media is the render with the 4.5s opener trimmed (ffmpeg -ss 4.75), because the opener repeats the hero title directly above it; its poster is that copy's first frame. Re-make both after any new render.

