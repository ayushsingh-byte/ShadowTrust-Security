---
format: 1920x1080
duration: 125s
message: "ShadowTrust lets attackers in on purpose and turns everything they do into a case you can close."
arc: Demo loop (invitation → a real attack arrives → the case → what was seen, where from, with what → the tools → the report → the wall → sign-off)
audience: "People seeing the project for the first time: reviewers, recruiters, security engineers"
mode: autonomous
music: confident minimal electronic underscore with a steady pulse, bright and modern, no vocals
---

## Video direction

- second cut (2026-10-07): the user asked for a longer video that shows the features working, with less text. Nine of the eleven frames are now real screen recordings at real speed. Only the first and last frames are type.
- palette system: from frame.md. `bg` white is the ground of every frame. `text` navy carries headlines and labels. `text-muted` carries the second half of a headline and the label's descriptor. `primary` violet is the one accent: the mark's pupil, the label dot, the caret. The ribbon image and the real recordings bring the wider brand hues. The Wallboard recording is dark because that page is dark: it sits inside the same white frame.
- type: display role at weight 300 for the two type frames, body role for labels (name at weight 500, descriptor in the muted tone), mono role for the command. Sentence case. No em dashes.
- footage frames: one layout for all nine. The recording sits in a 1664x936 window at x 128, y 36 with a hairline border. Under it, one label line: a violet dot, the feature name, a short descriptor, and the small mark and name at the right. There are no captions in this video, so the label line deliberately uses the bottom band that captions would use.
- motion grammar and reveal model: long-tail settles only (power3 feel, no overshoot). In footage frames the recording is the motion: the label arrives in the first second and then holds still. Nothing floats, nothing breathes, no camera move is added on top of a recording.
- cuts: every footage clip dips through white for 0.2s at its head and tail (baked into the clips), so all cuts are plain cuts and read the same way.
- third cut (2026-10-07): each recording now has a camera that closes in on what the pointer touches and pulls back between actions, and typed characters have soft key sounds. The camera is part of the recording itself (a live page zoom), not a move added over it.
- honesty: recordings play at real speed. Nothing inside a recording is redrawn or typed over. The only thing added during recording is a drawn cursor and click ring so the viewer can follow.
- negative list: no dark "hacker" look, no glitch or scanline effects, no lock or shield icons, no stock imagery, no invented interface, no numbers that are not on a real screen or in the repository, no sped-up footage, no breathing loops, no slow drifting push, no front-load-then-freeze in the type frames.

## Frame 1 — Let them in

- scene: Two short lines land alone on a white canvas while the ribbon sweeps in from the corner
- voiceover:
- duration: 4.5s
- transition_in: cut
- status: animated
- src: compositions/frames/01-let-them-in.html
- type: hook
- persuasion: Negative contrast (a security product that invites the attacker in)
- beat: intrigue
- blueprint: compose
- focal: assets/ribbon.png
- roles: ribbon = background (full strength, top right) · logo-950db3e1 = supporting
- asset_candidates: assets/ribbon.png — the brand ribbon on a transparent ground; assets/logo-950db3e1.svg — the ShadowTrust eye mark

narrativeRole: Opens on the counterintuitive invitation, in the viewer's language, with no product and no feature named yet.
keyMessage: Let them in. Watch every move.

Compose: kinetic type on a bare canvas, two lines, each landing alone.
Scene 1 (0.0–1.5s): white ground, nothing else. "Let them in." enters by per-word staggered reveal (`dynamic-content-sequencing`), display role, very large, left aligned on the left third, vertically a little above centre. Lone line, about 45% of frame width.
Scene 2 (1.5–3.1s): the ribbon image slides in from the top right on a long-tail settle and comes to rest filling the right 45% (`spring-pop-entrance`, smooth register). As it settles, the second line "Watch every move." reveals per word under the first, same size, in the muted tone (`dynamic-content-sequencing`). Asymmetric 55/45, two depth layers plus ground.
Scene 3 (3.1–4.5s): the eye mark and the name "ShadowTrust" settle small in the top left corner (`spring-pop-entrance`, smooth register). Everything holds still to the cut.

## Frame 2 — Live attack

- scene: The real Event log takes a real brute force: rows arrive, a new incident is announced, then the intruder logs in
- voiceover:
- duration: 13.333s
- transition_in: cut
- status: animated
- src: compositions/frames/02-live-attack.html
- type: feature_showcase
- persuasion: Statistical proof turned into live proof: nothing is described, the product is seen reacting.
- beat: tension + control
- blueprint: compose
- focal: assets/clip3-live.mp4
- roles: clip3-live = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-live.mp4 — [video] real screen recording with a camera that follows the pointer, 20.4s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: Every move shows up the moment it happens.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–13.333s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Event log" slides up at the left with a violet dot, weight 500, followed by the muted line "A brute force arrives. A case opens." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 3 — Investigations

- scene: The case that just opened is found, opened and read: why it fired, its timeline, the rules behind it
- voiceover:
- duration: 15.567s
- transition_in: cut
- status: animated
- src: compositions/frames/03-investigations.html
- type: feature_showcase
- persuasion: Friction reduction
- beat: relief + control
- blueprint: compose
- focal: assets/clip3-investigate.mp4
- roles: clip3-investigate = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-investigate.mp4 — [video] real screen recording with a camera that follows the pointer, 15.5s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: The case is already written when the analyst arrives.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–15.567s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Investigations" slides up at the left with a violet dot, weight 500, followed by the muted line "Open the case. Read what happened." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 4 — ATT&CK board

- scene: The live ATT&CK board, the cursor passing over the techniques the sensors have seen
- voiceover:
- duration: 9.833s
- transition_in: cut
- status: animated
- src: compositions/frames/04-attack-matrix.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: clarity
- blueprint: compose
- focal: assets/clip3-mitre.mp4
- roles: clip3-mitre = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-mitre.mp4 — [video] real screen recording with a camera that follows the pointer, 9.833s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: What was seen is already mapped.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–9.833s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "MITRE ATT&CK" slides up at the left with a violet dot, weight 500, followed by the muted line "Techniques seen, by tactic." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 5 — Geo intelligence

- scene: The globe is turned by hand, then switched to the map
- voiceover:
- duration: 14.7s
- transition_in: cut
- status: animated
- src: compositions/frames/05-geo.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: awe
- blueprint: compose
- focal: assets/clip3-geo.mp4
- roles: clip3-geo = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-geo.mp4 — [video] real screen recording with a camera that follows the pointer, 14.7s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: Sources resolve to places.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–14.7s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Geo intelligence" slides up at the left with a violet dot, weight 500, followed by the muted line "Where it comes from." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 6 — Credential vault

- scene: A search narrows the list of captured usernames and passwords
- voiceover:
- duration: 7.2s
- transition_in: cut
- status: animated
- src: compositions/frames/06-credential-vault.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: curiosity
- blueprint: compose
- focal: assets/clip3-creds.mp4
- roles: clip3-creds = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-creds.mp4 — [video] real screen recording with a camera that follows the pointer, 7.2s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: Everything they typed was kept.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–7.2s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Credential vault" slides up at the left with a violet dot, weight 500, followed by the muted line "Every password they tried." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 7 — URL scanner

- scene: A URL is typed and scanned, and the verdict and intelligence fill in
- voiceover:
- duration: 13.9s
- transition_in: cut
- status: animated
- src: compositions/frames/07-url-scanner.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: confidence
- blueprint: compose
- focal: assets/clip3-urlscan.mp4
- roles: clip3-urlscan = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-urlscan.mp4 — [video] real screen recording with a camera that follows the pointer, 13.9s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: Tools for what attackers leave behind are in the same console.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–13.9s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "URL scanner" slides up at the left with a violet dot, weight 500, followed by the muted line "A real scan, start to verdict." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 8 — Analysis lab

- scene: Commands typed in the sandbox build a behaviour graph and trip a rule
- voiceover:
- duration: 14.4s
- transition_in: cut
- status: animated
- src: compositions/frames/08-analysis-lab.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: control
- blueprint: compose
- focal: assets/clip3-lab.mp4
- roles: clip3-lab = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-lab.mp4 — [video] real screen recording with a camera that follows the pointer, 14.4s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: Behaviour is profiled as it happens.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–14.4s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Analysis lab" slides up at the left with a violet dot, weight 500, followed by the muted line "Commands profiled as they run." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 9 — Reports

- scene: A report is generated and read in the preview panel
- voiceover:
- duration: 17.267s
- transition_in: cut
- status: animated
- src: compositions/frames/09-reports.html
- type: feature_showcase
- persuasion: Value stacking
- beat: confidence
- blueprint: compose
- focal: assets/clip3-reports.mp4
- roles: clip3-reports = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-reports.mp4 — [video] real screen recording with a camera that follows the pointer, 17.267s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: The same activity ends as a document.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–17.267s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Reports" slides up at the left with a violet dot, weight 500, followed by the muted line "Generate. Preview. Download." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 10 — Wallboard

- scene: The dark full-screen view, with the feed still taking events
- voiceover:
- duration: 8.033s
- transition_in: cut
- status: animated
- src: compositions/frames/10-wallboard.html
- type: feature_showcase
- persuasion: Show-don't-tell proof
- beat: awe
- blueprint: compose
- focal: assets/clip3-wall.mp4
- roles: clip3-wall = cutout (the real screen recording, in a hairline window)
- asset_candidates: assets/clip3-wall.mp4 — [video] real screen recording with a camera that follows the pointer, 8.033s, 1664x936

narrativeRole: Evidence beat. The feature is shown working, not described.
keyMessage: The whole picture, on one wall.

Compose: footage in a window, one label line under it.
Scene 1 (0.0–8.033s): the recording plays at real speed in a 1664x936 window with a hairline border, set at x 128, y 36. It dips in from white over its first 0.2s and out to white over its last 0.2s (baked into the clip), so no other transition is needed.
Scene 2 (0.2–1.2s): in the band under the window, the label "Wallboard" slides up at the left with a violet dot, weight 500, followed by the muted line "For the big screen." (`dynamic-content-sequencing`). The small mark and name sit at the right end of the band from the start. The label band then holds still for the rest of the frame: the motion belongs to the recording.

## Frame 11 — Sign-off

- scene: The mark and name settle in the centre, the self-hosted line follows, a setup command types under it
- voiceover:
- duration: 6s
- transition_in: cut
- status: animated
- src: compositions/frames/11-sign-off.html
- type: cta
- persuasion: Friction reduction (one command)
- beat: inevitability
- blueprint: compose
- focal: assets/logo-950db3e1.svg
- roles: logo-950db3e1 = cutout (centre lockup) · ribbon = background (top right, reduced)
- asset_candidates: assets/logo-950db3e1.svg — the ShadowTrust eye mark; assets/ribbon.png — the brand ribbon on a transparent ground

narrativeRole: Names the product once more and gives the next step: it is self-hosted and starts with one command.
keyMessage: ShadowTrust. Self-hosted. One command to start.

Compose: a held lockup with one typed line.
Scene 1 (0.0–1.4s): white ground. The eye mark and the name "ShadowTrust" settle as one large centred lockup, slightly above centre (`spring-pop-entrance`, smooth register).
Scene 2 (1.4–3.0s): under the lockup the line "Deception and security operations, self-hosted." reveals per word in the muted tone (`dynamic-content-sequencing`). The ribbon image eases in at the top right corner, small and partly off canvas, as a quiet echo of Frame 1.
Scene 3 (3.0–5.2s): a command pill appears under the line and the command "./setup.sh" types on behind a violet caret, mono role (`discrete-text-sequence` with `context-sensitive-cursor`). When the command is complete, the small note "One Docker Compose stack" fades up under it.
Scene 4 (5.2–6.0s): everything holds, then the whole frame fades to white as the only exit in the video.
