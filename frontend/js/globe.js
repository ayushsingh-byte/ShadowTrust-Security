/* The dotted globe. Holds the land mask the landing page's drawing uses, and the interactive
   globe on the console's Geo intelligence page: land as dots, each real source location as a
   spike whose height follows its event count. Drag to turn it; left alone, it drifts.
   Needs js/ribbon.js (window.STCanvas) to be loaded first. */
(function () {
    'use strict';

    // 2-degree land mask (180 x 90 bits, row-major from 90N 180W), rasterised from
    // Natural Earth 1:110m land, which is public domain.
    var LAND = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf4AP/AAAAAAAAAAAAAAAAAAAAAAAAX/z///+AAAAAAAABAAAAAAAAAAAAAYd8P///wAA+AAAAAA8AAAAAAAAAAAwAnw////4AAIAAAAAAGAAAAAAAAAAADivwAf//wAAAAADAAf/wAHYAAAAAADoi3sAP//gAAAAAMAD///sAAAAgBgACfwz/AD/+gAAAwAEHf///////+AP//////////////4A//EgAAAAAAAgH///////////////gAFAAgAAAAAAAAz///////////////BhQAAAAAAAAAAAAP/////4A0B4AAAD5/////////////Af3////gHgA4AAAH5///////////LwAHgH///gHkAAAAAH4/////////+CIAABAB///4D+AAAAGCx/////////4A8AAIAAf///n/gAAAOCD/////////wA4AAAAAf///n/wAAAbP///////////AgAAAAAP/////wAAADf//////////9AAAAAAAF////0YAAAB///////////9AAAAAAAD////8EAAAB///////////5AAAAAAAD////2AAAAB/f5fP//////wAAAAAAAD////gAAAAfxnwPP//////jAAAAAAAD////AAAAAPCb3/n/////+CAAAAAAAD///8AAAAAfALf/n////+ECAAAAAAAB///8AAAAAGHQP/n/////mMAAAAAAAA///8AAAAAH+Ai///////E8AAAAAAAAf//wAAAAAP/AA///////BgAAAAAAAAP//gAAAAAf/73///////gAAAAAAAAAD/AQAAAAAf////f/////gAAAAAAAAAF+AQAAAAB///+/n/////AAAAAAAAAAC+AAAAAAB///+f0H////AAAAAAAAAAAeAwAAAAD////f/B///8gAAAAAAAAAAeGEAAAAH////v+B/z/AAAAAAAAAAAAPMAgAAAD////n+A/B+gAAAAAAAAAAAD8AAAAAD////n4AeB/AgAAAAAAAAAAAPAAAAAH////3gAcAfAgAAAAAAAAAAADAAAAAD////6AAcAfggAAAAAAAAAAABDwAAAD////8wAMATAIAAAAAAAAAAAAr/AAAB/////gAKASAAAAAAAAAAAAAAH/gAAA/////gACAAAIAAAAAAAAAAAAH/8AAAaH///AAAAsGAAAAAAAAAAAAAH/+AAAAB//+AAAAUOAAAAAAAAAAAAAP/+AAAAB//8AAAAYegAAAAAAAAAAAAP//gAAAD//4AAAAMeBgAAAAAAAAAAAP//8AAAB//wAAAAGdiuAAAAAAAAAAAf///AAAA//wAAAACAQHgAAAAAAAAAAP///gAAA//wAAAABwAHwgAAAAAAAAAH///AAAA//wAAAAACIDQIAAAAAAAAAH//+AAAAf/wAAAAAAAAAAAAAAAAAAAD//+AAAA//wgAAAAABxAAAAAAAAAAAD//+AAAA//wgAAAAAPxgBAAAAAAAAAA//8AAAA//jgAAAAAf5gAAAAAAAAAAAf/8AAAA//DgAAAAAf/gAAAAAAAAAAAf/8AAAAf/DAAAAAD//4CAAAAAAAAAAf/wAAAAf/DAAAAAH//4AAAAAAAAAAAf/AAAAAf+CAAAAAH//8AAAAAAAAAAAf/AAAAAP8AAAAAAH//+AAAAAAAAAAA/+AAAAAP8AAAAAAH//+AAAAAAAAAAA/+AAAAAH4AAAAAAD//+AAAAAAAAAAA/8AAAAAHwAAAAAADwf8AAAAAAAAAAA/gAAAAAAAAAAAAACAH4AIAAAAAAAAB/wAAAAAAAAAAAAAAAD4AEAAAAAAAAB+AAAAAAAAAAAAAAAAAAAGAAAAAAAAB6AAAAAAAAAAAAAAAAAwAMAAAAAAAAA8AAAAAAAAAAAAAAAAAQAYAAAAAAAAB4AAAAAAAAAAAAAAAAAAAwAAAAAAAAB4AAAAAAAAAAAAAAAAAAAAAAAAAAAADwAAAAAAAAAACAAAAAAAAAAAAAAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAeAAIP+f/gAAAAAAAAAAAMAAAAAAABP/+H//////AAAAAAAAAAA+AAAAAf////8////////AAAAAAAOEAPAAAB///////////////gAAAP//T//8AAAH//////////////+AAAH/////4AAAH///////////////8AAE//////4ABw////////////////8AAAD//////gCA////////////////wAAAf/////////////////////////+AAH/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    var RAD = Math.PI / 180;
    var bits = null;

    function isLand(lat, lon) {
        if (!bits) bits = atob(LAND);
        var n = Math.min(89, Math.floor((90 - lat) / 2)) * 180 + Math.min(179, Math.floor((lon + 180) / 2));
        return (bits.charCodeAt(n >> 3) >> (7 - (n & 7))) & 1;
    }
    // Globe space: y is north, longitude 0 faces +z, east is +x.
    function vec(lat, lon) {
        var c = Math.cos(lat * RAD);
        return [Math.sin(lon * RAD) * c, Math.sin(lat * RAD), Math.cos(lon * RAD) * c];
    }
    // An even spread of points over the sphere (golden-angle spiral), keeping the ones on land.
    function landDots(count) {
        var out = [];
        var GA = Math.PI * (3 - Math.sqrt(5));
        for (var i = 0; i < count; i++) {
            var y = 1 - (i + 0.5) * 2 / count, r = Math.sqrt(1 - y * y), th = i * GA;
            var x = Math.cos(th) * r, z = Math.sin(th) * r;
            if (isLand(Math.asin(y) / RAD, Math.atan2(x, z) / RAD)) out.push([x, y, z]);
        }
        return out;
    }

    window.STGlobe = { LAND: LAND, vec: vec, landDots: landDots, create: create };

    var PALETTE = [[255, 110, 40], [255, 96, 130], [244, 75, 204], [176, 110, 250], [124, 104, 255], [83, 58, 253]];
    var RUBY = [234, 34, 97], ORANGE = [255, 97, 24];

    /* create(canvas, { tip: element for the hover label })
       returns { setPoints([{ lat, lon, hits, ip, location }]), pulse(ip) } */
    function create(cv, opts) {
        var C = window.STCanvas;
        if (!C || !cv || !cv.getContext) return null;
        opts = opts || {};
        var rgba = C.rgba, clamp01 = C.clamp01, easeOut = C.easeOut;
        var DOTS = landDots(16000);
        var points = [];
        var yaw = -20 * RAD, tilt = 22 * RAD, spin = 0;
        var dragging = false, lastX = 0, lastY = 0, pointer = null, hover = null, lastT = 0;
        var cs = 1, sn = 0, ct = 1, st = 0;
        var P = [0, 0, 0];
        var buckets = [];
        for (var b = 0; b < PALETTE.length * 3; b++) buckets.push([]);

        function turn(v, k) {
            var x = v[0] * cs - v[2] * sn, z = v[0] * sn + v[2] * cs;
            P[0] = x * k;
            P[1] = (v[1] * ct - z * st) * k;
            P[2] = (v[1] * st + z * ct) * k;
            return P;
        }
        function dark() {
            return document.documentElement.getAttribute('data-theme') === 'dark';
        }

        var view = C.stage(cv, function (ctx, w, h, t) {
            var dt = lastT ? Math.min(0.1, t - lastT) : 0;
            lastT = t;
            if (!dragging) {
                // drift on its own, slower while something is being read
                yaw += (hover ? 0 : 0.05) * dt + spin * dt;
                spin *= Math.pow(0.04, dt);
            }
            cs = Math.cos(yaw); sn = Math.sin(yaw); ct = Math.cos(tilt); st = Math.sin(tilt);
            var R = Math.min(w * 0.42, h * 0.44);
            var cx = w / 2, cy = h / 2 + R * 0.04;
            var night = dark();
            var i, k, p;

            // glow behind the sphere, then its body
            var g = ctx.createRadialGradient(cx, cy, R * 0.8, cx, cy, R * 1.5);
            g.addColorStop(0, night ? 'rgba(102,94,253,0.34)' : 'rgba(154,154,254,0.30)');
            g.addColorStop(0.45, night ? 'rgba(244,75,204,0.10)' : 'rgba(244,75,204,0.09)');
            g.addColorStop(1, 'rgba(255,255,255,0)');
            ctx.fillStyle = g;
            ctx.fillRect(0, 0, w, h);
            g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.45, R * 0.1, cx, cy, R);
            g.addColorStop(0, night ? '#1d2c63' : '#ffffff');
            g.addColorStop(1, night ? '#111c45' : '#eceeff');
            ctx.fillStyle = g;
            ctx.beginPath();
            ctx.arc(cx, cy, R, 0, 6.2832);
            ctx.fill();

            for (k = 0; k < buckets.length; k++) buckets[k].length = 0;
            for (i = 0; i < DOTS.length; i++) {
                p = turn(DOTS[i], 1);
                if (p[2] <= 0.02) continue;
                var q = clamp01(0.5 - p[0] * 0.42 - p[1] * 0.42);
                var ci = Math.min(PALETTE.length - 1, Math.floor(q * PALETTE.length));
                var di = p[2] > 0.66 ? 2 : p[2] > 0.33 ? 1 : 0;
                buckets[ci * 3 + di].push(cx + p[0] * R, cy - p[1] * R);
            }
            var rad = Math.max(0.9, R / 290);
            for (k = 0; k < buckets.length; k++) {
                var list = buckets[k];
                if (!list.length) continue;
                ctx.globalAlpha = [0.3, 0.6, 0.92][k % 3] * (night ? 0.9 : 1);
                ctx.fillStyle = rgba(PALETTE[(k / 3) | 0]);
                ctx.beginPath();
                for (i = 0; i < list.length; i += 2) {
                    ctx.moveTo(list[i] + rad, list[i + 1]);
                    ctx.arc(list[i], list[i + 1], rad, 0, 6.2832);
                }
                ctx.fill();
            }
            ctx.globalAlpha = 1;

            // sources: a spike per location, as tall as its share of events
            var best = null, bestD = 18 * 18;
            ctx.lineCap = 'round';
            for (i = 0; i < points.length; i++) {
                var pt = points[i];
                p = turn(pt.v, 1);
                pt.front = p[2] > 0.05;
                if (!pt.front) continue;
                var bx = cx + p[0] * R, by = cy - p[1] * R, depth = p[2];
                p = turn(pt.v, 1 + 0.05 + 0.3 * pt.weight);
                var tx = cx + p[0] * R, ty = cy - p[1] * R;
                pt.x = tx; pt.y = ty;
                var a = 0.35 + 0.65 * depth;

                if (!C.reduced) {
                    var ph = (t * 0.45 + i * 0.37) % 1;
                    ctx.strokeStyle = rgba(RUBY, 0.5 * (1 - ph) * a);
                    ctx.lineWidth = 1.2;
                    ctx.beginPath();
                    ctx.arc(bx, by, 2.5 + 9 * ph, 0, 6.2832);
                    ctx.stroke();
                }
                if (pt.flash != null) {
                    var age = (t - pt.flash) / 1.4;
                    if (age > 1 || age < 0) pt.flash = null;
                    else {
                        ctx.strokeStyle = rgba(ORANGE, 0.9 * (1 - age));
                        ctx.lineWidth = 2;
                        ctx.beginPath();
                        ctx.arc(bx, by, 4 + 30 * easeOut(age), 0, 6.2832);
                        ctx.stroke();
                    }
                }
                var lg = ctx.createLinearGradient(bx, by, tx, ty);
                lg.addColorStop(0, rgba(RUBY, 0.25 * a));
                lg.addColorStop(1, rgba(ORANGE, a));
                ctx.strokeStyle = lg;
                ctx.lineWidth = pt === hover ? 2.6 : 1.5;
                ctx.beginPath();
                ctx.moveTo(bx, by);
                ctx.lineTo(tx, ty);
                ctx.stroke();
                ctx.fillStyle = rgba(RUBY, a);
                ctx.beginPath();
                ctx.arc(bx, by, 2.2, 0, 6.2832);
                ctx.fill();
                ctx.fillStyle = rgba(ORANGE, a);
                ctx.beginPath();
                ctx.arc(tx, ty, pt === hover ? 4.2 : 2.6, 0, 6.2832);
                ctx.fill();

                if (pointer) {
                    var dx = pointer[0] - tx, dy = pointer[1] - ty, d2 = dx * dx + dy * dy;
                    var ex = pointer[0] - bx, ey = pointer[1] - by, e2 = ex * ex + ey * ey;
                    var near = Math.min(d2, e2);
                    if (near < bestD) { bestD = near; best = pt; }
                }
            }
            if (!dragging && best !== hover) {
                hover = best;
                label();
            }
        });

        var tip = opts.tip || null;
        function label() {
            cv.style.cursor = dragging ? 'grabbing' : hover ? 'pointer' : 'grab';
            if (!tip) return;
            if (!hover) { tip.hidden = true; return; }
            tip.textContent = '';
            var b = document.createElement('b');
            b.textContent = hover.ip || 'source';
            tip.appendChild(b);
            if (hover.location) {
                var l = document.createElement('span');
                l.textContent = hover.location;
                tip.appendChild(l);
            }
            var n = document.createElement('span');
            n.textContent = hover.hits.toLocaleString() + (hover.hits === 1 ? ' event' : ' events');
            tip.appendChild(n);
            tip.hidden = false;
            tip.style.left = Math.round(hover.x) + 'px';
            tip.style.top = Math.round(hover.y) + 'px';
        }

        function at(e) {
            var r = cv.getBoundingClientRect();
            return [e.clientX - r.left, e.clientY - r.top];
        }
        cv.style.cursor = 'grab';
        cv.style.touchAction = 'pan-y';
        cv.addEventListener('pointerdown', function (e) {
            dragging = true;
            lastX = e.clientX; lastY = e.clientY;
            spin = 0;
            hover = null;
            label();
            try { cv.setPointerCapture(e.pointerId); } catch (_) { /* not capturable */ }
        });
        cv.addEventListener('pointermove', function (e) {
            pointer = at(e);
            if (dragging) {
                var dx = e.clientX - lastX, dy = e.clientY - lastY;
                lastX = e.clientX; lastY = e.clientY;
                yaw -= dx * 0.006;
                if (e.pointerType !== 'touch') tilt = Math.max(-1.1, Math.min(1.1, tilt + dy * 0.005));
                spin = -dx * 0.12;
            }
            if (C.reduced) view.paint();
        });
        var release = function () {
            if (!dragging) return;
            dragging = false;
            label();
        };
        cv.addEventListener('pointerup', release);
        cv.addEventListener('pointercancel', release);
        cv.addEventListener('pointerleave', function () {
            pointer = null;
            if (!dragging && hover) { hover = null; label(); }
            if (C.reduced) view.paint();
        });
        document.addEventListener('st-themechange', function () { view.paint(); });

        return {
            setPoints: function (list) {
                var max = 1;
                (list || []).forEach(function (m) { if (m.hits > max) max = m.hits; });
                var old = {};
                points.forEach(function (p) { old[p.ip] = p; });
                points = (list || []).filter(function (m) {
                    return typeof m.lat === 'number' && typeof m.lon === 'number' && !(m.lat === 0 && m.lon === 0);
                }).map(function (m) {
                    var hits = Number(m.hits) || 0;
                    return {
                        ip: m.ip, location: m.location || '', hits: hits,
                        v: vec(m.lat, m.lon),
                        // log scale: one very loud source should not flatten the rest
                        weight: Math.log(1 + hits) / Math.log(1 + max),
                        flash: old[m.ip] ? old[m.ip].flash : null,
                        x: 0, y: 0, front: false,
                    };
                });
                hover = null;
                label();
                view.paint();
            },
            // a live event from this address just arrived
            pulse: function (ip) {
                for (var i = 0; i < points.length; i++) {
                    if (points[i].ip === ip) { points[i].flash = performance.now() / 1000; return true; }
                }
                return false;
            },
            paint: function () { view.paint(); },
        };
    }
})();
