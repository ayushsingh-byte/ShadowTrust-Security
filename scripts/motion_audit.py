"""Motion audit: put every interface transition and one-shot animation on the three speeds and the
shared eases from css/tokens.css.  usage: python3 motion_audit.py <frontend dir> [--apply]

What it changes, inside .css files and <style> blocks only:
  - the duration of each transition / one-shot animation: up to 180ms -> --st-dur-1, up to 380ms -> --st-dur-2,
    up to 700ms -> --st-dur-3. Longer ones are deliberate (draw-ins, counters) and stay.
  - ease-out and the look-alike curves -> --st-ease-out; ease-in-out and the material curve -> --st-ease-in-out.
What it leaves alone: delays, anything under 100ms, endless animations (their period is a rhythm, not a
response time), values that are already tokens or calc(), `ease`, `linear`, `steps()`.
"""
import glob, os, re, sys

TIME = re.compile(r'(?<![\w.#-])(\d*\.?\d+)(ms|s)\b')
OUT_CURVES = {'cubic-bezier(0.16,1,0.3,1)', 'cubic-bezier(0.22,1,0.36,1)', 'cubic-bezier(0.2,0.8,0.2,1)'}
INOUT_CURVES = {'cubic-bezier(0.4,0,0.2,1)', 'cubic-bezier(0.65,0,0.35,1)'}


def speed(ms):
    if ms < 100 or ms > 700:
        return None
    return 'var(--st-dur-1)' if ms <= 180 else 'var(--st-dur-2)' if ms <= 380 else 'var(--st-dur-3)'


def fix_part(part, is_duration_only=False):
    """One comma-separated item of a transition/animation value."""
    if 'infinite' in part:
        return part
    # protect functions so their numbers are not read as times
    held = []
    def hold(m):
        held.append(m.group(0)); return f'\x00{len(held) - 1}\x00'
    work = re.sub(r'(?:cubic-bezier|steps|calc|var)\([^()]*(?:\([^()]*\)[^()]*)*\)', hold, part)
    m = TIME.search(work)  # the first time is the duration; a second one is a delay
    if m and not any('--st-dur-' in h for h in held):  # already on a token: what is left is a delay
        ms = float(m.group(1)) * (1000 if m.group(2) == 's' else 1)
        tok = speed(ms)
        if tok:
            work = work[:m.start()] + tok + work[m.end():]
    if not is_duration_only:
        work = re.sub(r'(?<![\w-])ease-in-out(?![\w-])', 'var(--st-ease-in-out)', work)
        work = re.sub(r'(?<![\w-])ease-out(?![\w-])', 'var(--st-ease-out)', work)
    def back(m):
        v = held[int(m.group(1))]
        if is_duration_only:
            return v
        flat = re.sub(r'\s+', '', v)
        flat = re.sub(r'(?<=[(,])\.', '0.', flat)
        return 'var(--st-ease-out)' if flat in OUT_CURVES else 'var(--st-ease-in-out)' if flat in INOUT_CURVES else v
    return re.sub(r'\x00(\d+)\x00', back, work)


def fix_value(prop, value):
    if prop in ('transition-delay', 'animation-delay'):
        return value
    only_dur = prop.endswith('-duration')
    parts = re.split(r',(?![^()]*\))', value)
    return ','.join(fix_part(p, only_dur) for p in parts)


DECL = re.compile(r'(?<![\w-])(transition|animation)(-duration|-timing-function|-delay)?(\s*:\s*)([^;{}]+)')


def fix_css(css):
    n = [0]
    def one(m):
        prop = m.group(1) + (m.group(2) or '')
        if prop.endswith('-timing-function'):
            new = fix_part(m.group(4))
        else:
            new = fix_value(prop, m.group(4))
        if new != m.group(4):
            n[0] += 1
        return m.group(1) + (m.group(2) or '') + m.group(3) + new
    # comments are kept as they are
    out, pos = [], 0
    for c in re.finditer(r'/\*.*?\*/', css, flags=re.S):
        out.append(DECL.sub(one, css[pos:c.start()])); out.append(c.group(0)); pos = c.end()
    out.append(DECL.sub(one, css[pos:]))
    return ''.join(out), n[0]


def selfcheck():
    f = lambda v: fix_value('transition', v)
    assert f('opacity 0.2s ease') == 'opacity var(--st-dur-2) ease'
    assert f('transform .15s ease-out, color 150ms') == 'transform var(--st-dur-1) var(--st-ease-out), color var(--st-dur-1)'
    assert f('width 0.5s cubic-bezier(.16, 1, .3, 1) 0.3s') == 'width var(--st-dur-3) var(--st-ease-out) 0.3s'      # the delay stays
    assert f('transform 90ms ease-in') == 'transform 90ms ease-in'                                                # too short to touch
    assert f('opacity 1.2s ease') == 'opacity 1.2s ease'                                                          # deliberate, long
    assert f('transform var(--st-dur-2) var(--st-ease-out)') == 'transform var(--st-dur-2) var(--st-ease-out)'
    assert fix_value('animation', 'spin 0.7s linear infinite') == 'spin 0.7s linear infinite'
    assert fix_value('animation', 'up 0.28s both') == 'up var(--st-dur-2) both'
    assert fix_value('animation', 'bob 3.5s cubic-bezier(0.37, 0, 0.63, 1) calc(var(--i) * -0.5s) infinite alternate paused').startswith('bob 3.5s cubic-bezier(0.37')
    assert fix_value('transition-delay', '0.2s') == '0.2s'
    assert fix_value('animation', 'up var(--st-dur-3) .1s both') == 'up var(--st-dur-3) .1s both'               # running twice changes nothing
    assert fix_value('animation-duration', '0.2s') == 'var(--st-dur-2)'
    css, n = fix_css('a{transition:all .3s ease-in-out}/* transition: 0.3s */b{animation:x 400ms cubic-bezier(0.4,0,0.2,1) forwards}')
    assert css == 'a{transition:all var(--st-dur-2) var(--st-ease-in-out)}/* transition: 0.3s */b{animation:x var(--st-dur-3) var(--st-ease-in-out) forwards}' and n == 2, css
    print('motion audit self-check ok')


def main():
    root = sys.argv[1]; apply = '--apply' in sys.argv
    skip = set()
    total = 0
    for path in sorted(glob.glob(os.path.join(root, 'css', '*.css')) + glob.glob(os.path.join(root, '*.html'))):
        name = os.path.basename(path)
        if name in skip or name == 'tokens.css':
            continue
        s = open(path).read()
        if path.endswith('.css'):
            new, n = fix_css(s)
        else:
            n = 0
            def style(m):
                nonlocal n
                body, k = fix_css(m.group(2)); n += k
                return m.group(1) + body + m.group(3)
            new = re.sub(r'(<style[^>]*>)(.*?)(</style>)', style, s, flags=re.S)
        if n:
            total += n
            print(f'{name:26s} {n:3d} declarations')
            if apply:
                open(path, 'w').write(new)
    print('total', total, '(applied)' if apply else '(dry run)')


if __name__ == '__main__':
    selfcheck() if len(sys.argv) == 1 else main()
