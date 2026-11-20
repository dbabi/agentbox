#!/usr/bin/env python3
"""Copy docs/wiki/ into a checkout of the GitHub wiki, rewriting links for the wiki.

docs/wiki/ is the source of truth. README.md becomes Home; links between pages drop .md; links to other repo
files become github.com URLs (images: raw URLs). Exits non-zero if any relative link survives.
Usage: wiki-sync.py <docs/wiki dir> <wiki checkout dir> [owner/repo]
"""
import os, re, sys

ORDER = ["Home", "Getting-Started", "Installing-on-Real-Hardware", "Encryption-and-Recovery", "Generations-and-Updates",
         "Release-Pipeline", "Architecture", "Security-Model", "Testing-and-Gates", "Roadmap", "Contributing", "FAQ"]
LINK = re.compile(r'(!?)\[([^\]]*)\]\(([^)\s]+)\)')

def page(name):
    return "Home" if name == "README" else name

def convert(text, src, repo):
    def fix(m):
        img, label, target = m.groups()
        if re.match(r'(https?:|mailto:|#)', target):
            return m.group(0)
        path, _, anchor = target.partition('#')
        anchor = '#' + anchor if anchor else ''
        full = os.path.normpath(os.path.join(src, path))
        if os.path.dirname(full) == os.path.normpath(src) and full.endswith('.md'):
            return '%s[%s](%s%s)' % (img, label, page(os.path.basename(full)[:-3]), anchor)
        rel = os.path.relpath(full, os.path.join(src, '..', '..'))
        if img:
            url = 'https://raw.githubusercontent.com/%s/main/%s' % (repo, rel)
        else:
            url = 'https://github.com/%s/%s/main/%s' % (repo, 'tree' if os.path.isdir(full) else 'blob', rel)
        return '%s[%s](%s%s)' % (img, label, url, anchor)
    return LINK.sub(fix, text)

def main(src, dst, repo):
    names = sorted(f[:-3] for f in os.listdir(src) if f.endswith('.md'))
    for f in os.listdir(dst):  # the wiki mirrors docs/wiki exactly; .git stays
        if f.endswith('.md'):
            os.remove(os.path.join(dst, f))
    for n in names:
        out = convert(open(os.path.join(src, n + '.md')).read(), src, repo)
        left = [t for _, _, t in LINK.findall(out) if not re.match(r'(https?:|mailto:|#)', t) and page(t.split('#')[0]) not in map(page, names)]
        assert not left, '%s: unconverted links %s' % (n, left)
        open(os.path.join(dst, page(n) + '.md'), 'w').write(out)
    pages = [p for p in ORDER if p in map(page, names)] + sorted(set(map(page, names)) - set(ORDER))
    open(os.path.join(dst, '_Sidebar.md'), 'w').write(''.join('- [%s](%s)\n' % (p.replace('-', ' '), p) for p in pages))
    open(os.path.join(dst, '_Footer.md'), 'w').write(
        'Synced from [`docs/wiki/`](https://github.com/%s/tree/main/docs/wiki). Edit the files there, not here.\n' % repo)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else 'dbabi/agentbox')
