#!/usr/bin/env python3
"""Build the hosted copy of the public site (landing, features, architecture, use cases, docs).

The hosted copy has no backend behind it, so links into the console and to the live status page
are pointed at the GitHub releases and repository instead. Output: dist-site/ (not tracked).

    python3 scripts/build_site.py                       # build
    SITE_URL=https://example.com python3 scripts/build_site.py   # also make link-preview images absolute
"""
import os, re, shutil, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / 'frontend', ROOT / 'dist-site'
REPO = 'https://github.com/ayushsingh-byte/ShadowTrust-Security'
RELEASES = REPO + '/releases/latest'
PAGES = ['index.html', 'features.html', 'architecture.html', 'usecases.html', 'docs.html']
FILES = ['css/tokens.css', 'css/site.css', 'manifest.json', 'og.png',
         'js/art.js', 'js/explainers.js', 'js/globe.js', 'js/home.js', 'js/ribbon.js', 'js/site.js']
DIRS = ['js/vendor', 'media', 'icons']
ARR = ' <span class="arr">→</span>'


def rewrite(html):
    # navigation and footer entries that only make sense next to a running backend
    html = re.sub(r'<li><a href="status\.html">[^<]*</a></li>', '', html)
    html = re.sub(r'<li><a href="(?:register|admin_login)\.html">[^<]*</a></li>', '', html)
    html = html.replace('<a href="status.html">Check live system status' + ARR + '</a>',
                        '<a href="' + REPO + '">View the source on GitHub' + ARR + '</a>')
    # the two tiles about live status become the way to get the product
    html = html.replace('<h3>Check live status</h3>', '<h3>Get the release</h3>')
    html = html.replace('<p>Services, sensors and the telemetry pipeline of this deployment, measured in your browser.</p>',
                        '<p>Download the latest version, then run the setup script on a machine with Docker.</p>')
    html = html.replace('<a class="link-arrow" href="status.html">System status' + ARR + '</a>',
                        '<a class="link-arrow" href="' + RELEASES + '">Releases' + ARR + '</a>')
    html = html.replace('<div class="tile-copy"><h3>System status</h3><p>Check the health of the backend services.</p></div>',
                        '<div class="tile-copy"><h3>Releases</h3><p>Download the latest version.</p></div>')
    html = html.replace('<a class="card tile plain c6" href="status.html">', '<a class="card tile plain c6" href="' + RELEASES + '">')
    # calls to action: there is no console to open here, so they lead to the download
    html = re.sub(r'(<a [^>]*href=")login\.html("[^>]*>)Sign in</a>', r'\g<1>' + REPO + r'\g<2>GitHub</a>', html)
    html = re.sub(r'(<a [^>]*href=")login\.html("[^>]*>)Open (?:the )?console', r'\g<1>' + RELEASES + r'\g<2>Get ShadowTrust', html)
    html = html.replace('href="login.html" aria-label="Open the console"', 'href="' + RELEASES + '" aria-label="Get ShadowTrust"')
    html = html.replace('class="index-item" href="login.html"', 'class="index-item" href="features.html"')
    html = html.replace('href="status.html"', 'href="docs.html"')  # the hero's live line
    site = os.environ.get('SITE_URL', '').rstrip('/')
    if site:
        html = re.sub(r'(<meta (?:property="og:image"|name="twitter:image") content=")(?!https?:)', r'\g<1>' + site + '/', html)
    return html


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir()
    for d in DIRS:
        shutil.copytree(SRC / d, OUT / d)
    for f in FILES:
        (OUT / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SRC / f, OUT / f)
    for p in PAGES:
        (OUT / p).write_text(rewrite((SRC / p).read_text()))
    left = [(p, m) for p in PAGES for m in re.findall(r'href="((?:login|register|admin_login|status)\.html[^"]*)"', (OUT / p).read_text())]
    assert not left, 'links into the console are left: %r' % left[:5]   # the check: no dead links ship
    (OUT / 'vercel.json').write_text('{ "cleanUrls": true }\n')
    size = sum(f.stat().st_size for f in OUT.rglob('*') if f.is_file())
    print('dist-site: %d files, %.1f MB' % (sum(1 for f in OUT.rglob('*') if f.is_file()), size / 1048576))


if __name__ == '__main__':
    main()
