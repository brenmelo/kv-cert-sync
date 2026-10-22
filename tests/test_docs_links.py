"""Every relative link in the repository's Markdown files points at a file or folder that exists, and every #anchor points at
a heading that exists (GitHub's slug rules).  A broken cross-reference between the runbook, the test report and the operations
guide is a documentation defect that nothing else catches.

External links (http, https, mailto) are not followed.  This test never touches the network.
"""
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKIP_DIRS = {".git", ".terraform", ".scratch", "__pycache__", ".build", ".venv", "node_modules"}

FENCE = re.compile(r"^(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")


def markdown_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.lower().endswith(".md"):
                yield os.path.join(base, name)


def lines_outside_fences(path):
    in_fence = False
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, start=1):
            if FENCE.match(line.strip()):
                in_fence = not in_fence
                continue
            if not in_fence:
                yield n, line.rstrip("\n")


def slug(heading):
    """GitHub's anchor for a heading: formatting removed, lower case, punctuation dropped, spaces turned into hyphens."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # a link keeps its text
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors(path):
    seen, out = {}, set()
    for _, line in lines_outside_fences(path):
        m = HEADING.match(line)
        if not m:
            continue
        base = slug(m.group(2))
        count = seen.get(base, 0)
        seen[base] = count + 1
        out.add(base if count == 0 else f"{base}-{count}")
    return out


class SlugTests(unittest.TestCase):
    def test_slug_rules(self):
        self.assertEqual(slug("4.1 Two migration cases: adopting a certificate"), "41-two-migration-cases-adopting-a-certificate")
        self.assertEqual(slug("Cost"), "cost")
        self.assertEqual(slug("What `kvsync` does *now*"), "what-kvsync-does-now")
        self.assertEqual(slug("E-mail receivers"), "e-mail-receivers")
        self.assertEqual(slug("A [link](x.md) here"), "a-link-here")


class DocLinkTests(unittest.TestCase):
    def test_every_relative_link_resolves(self):
        cache = {}
        checked = 0
        for path in markdown_files():
            for n, line in lines_outside_fences(path):
                for target in LINK.findall(line):
                    if re.match(r"^(https?:|mailto:|tel:)", target, re.IGNORECASE):
                        continue
                    where = f"{os.path.relpath(path, ROOT)}:{n} -> {target}"
                    file_part, _, frag = target.partition("#")
                    dest = path if not file_part else os.path.normpath(os.path.join(os.path.dirname(path), file_part))
                    with self.subTest(where):
                        self.assertTrue(os.path.exists(dest), f"{where}: no such file or folder")
                        if frag and os.path.isfile(dest) and dest.lower().endswith(".md"):
                            if dest not in cache:
                                cache[dest] = anchors(dest)
                            self.assertIn(frag.lower(), cache[dest], f"{where}: no heading with that anchor")
                    checked += 1
        self.assertGreater(checked, 20, "found suspiciously few links to check")


if __name__ == "__main__":
    unittest.main()
