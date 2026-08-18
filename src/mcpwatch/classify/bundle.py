"""Portable rating bundles — how a second rater participates at all.

Cohen's κ needs two people labelling the same 200 items blind to each other,
and until now the only way to record a label was ``classify adjudicate`` on the
collection host: an interactive terminal, beside the corpus, on a shared box
holding the one irreplaceable asset in the project. That makes "find a second
rater" mean "give someone shell on production", which is why the κ gate has sat
unmet with the machinery finished.

A bundle is the whole rating task in one self-contained HTML file: the diffs,
the rule hits as evidence, and the taxonomy definitions quoted verbatim from
:mod:`~mcpwatch.classify.taxonomy` so both raters and the model work from
identical wording. It carries **no labels of any kind** — not the rules', not
the model's, not the other rater's — so blindness holds by construction rather
than by remembering not to pass ``--show-llm``.

**Server identity is pseudonymized, and the guarantee is narrower than it
sounds.** The registry key is replaced everywhere it appears — including inside
the diff, because a manifest declares its own name in ``serverInfo`` and
pseudonymizing only the identity field leaves the key sitting in the evidence.
The pseudonym derives from the change_id, itself
``sha256(server_key|from_obs|to_obs)`` truncated, so the mapping back lives only
in the corpus.

What that does **not** buy is anonymity of the publisher. Tool names, URLs and
prose are the evidence a rater has to read, and a publisher's brand is often all
through them; scrubbing that would leave nothing to judge. So a bundle is safe
to hand to a collaborator and is not a publishable artifact — the disclosure
rules in ``FRAMING.md`` govern what gets published, and this is not that.

The point that survives in full is the anchoring one: one publisher owns 689
servers in this population, and a rater who recognises the fleet from its
registry key is no longer judging the diff in front of them.
"""

import html
import json
from dataclasses import dataclass
from typing import Any

from mcpwatch.diff import ChangeSet

from .taxonomy import Label, definition

__all__ = [
    "BUNDLE_FORMAT",
    "BundleItem",
    "build_bundle",
    "parse_labels",
    "pseudonym",
    "render_html",
]

BUNDLE_FORMAT = 1
"""Bumped if the on-disk shape changes in a way an importer must notice."""


def pseudonym(change_id: str) -> str:
    """A stable, non-reversible stand-in for a server's identity."""
    return f"server-{change_id[:6]}"


@dataclass(frozen=True, slots=True)
class BundleItem:
    """One ChangeSet as a rater sees it."""

    change_id: str
    layer: str
    pseudonym: str
    gap_days: float | None
    verdict: str
    changes: list[dict[str, Any]]
    evidence: list[str]

    def as_json(self) -> dict[str, Any]:
        """Render for the bundle file."""
        return {
            "change_id": self.change_id,
            "layer": self.layer,
            "server": self.pseudonym,
            "gap_days": self.gap_days,
            "verdict": self.verdict,
            "changes": self.changes,
            "evidence": self.evidence,
        }


def _redact(text: str, server_key: str, alias: str) -> str:
    """Replace the server's registry key with its pseudonym inside diff content.

    A manifest declares its own name — ``serverInfo.name`` is literally the
    registry key — so pseudonymizing the identity field alone leaves the key
    sitting in the evidence. Substituting rather than deleting keeps the change
    readable: an endpoint moving away from the server's own host still reads as
    a move, and the destination it moved *to* is untouched, which is the half
    that matters for `exfiltration_addition`.
    """
    if not server_key:
        return text
    return text.replace(server_key, alias)


def _summarize(changeset: ChangeSet, limit: int = 25) -> list[dict[str, Any]]:
    """Flatten a ChangeSet's changes into something renderable and stable."""
    out: list[dict[str, Any]] = []
    alias = pseudonym(changeset.change_id)
    key = changeset.server_key

    def clean(value: str) -> str:
        return _redact(value, key, alias)

    for change in changeset.changes[:limit]:
        entry: dict[str, Any] = {"kind": str(change.kind), "path": clean(change.path)}
        if change.text is not None and change.text.added:
            entry["added"] = clean(" ".join(change.text.added))[:1500]
            if change.text.removed:
                entry["removed"] = clean(" ".join(change.text.removed))[:800]
        else:
            if change.before is not None:
                entry["before"] = clean(json.dumps(change.before, ensure_ascii=False))[:800]
            entry["after"] = clean(json.dumps(change.after, ensure_ascii=False))[:800]
        out.append(entry)
    if len(changeset.changes) > limit:
        out.append({"kind": "elided", "path": f"... {len(changeset.changes) - limit} more changes"})
    return out


def build_bundle(
    changesets: list[ChangeSet],
    evidence: dict[str, list[str]],
    *,
    frame: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the rating bundle. Contains no labels, by design."""
    items = [
        BundleItem(
            change_id=c.change_id,
            layer=str(c.layer),
            pseudonym=pseudonym(c.change_id),
            gap_days=c.gap_days,
            verdict=str(c.verdict),
            changes=_summarize(c),
            evidence=evidence.get(c.change_id, []),
        ).as_json()
        for c in changesets
    ]
    return {
        "format": BUNDLE_FORMAT,
        "frame": frame or {},
        "definitions": {str(label): definition(label) for label in Label},
        "items": items,
    }


def parse_labels(payload: object) -> dict[str, dict[str, Any]]:
    """Read a rater's returned file into ``{change_id: {label, notes, seconds}}``.

    Deliberately strict about the label vocabulary: a typo importing silently as
    an unknown class would corrupt κ in a way nobody would spot, because the
    confusion matrix would simply grow a row.

    Raises:
        ValueError: If the payload is not a labels file, or names a label
            outside the taxonomy.
    """
    if not isinstance(payload, dict):
        msg = "labels file must be a JSON object"
        raise ValueError(msg)
    raw = payload.get("labels")
    if not isinstance(raw, dict):
        msg = "labels file has no 'labels' object"
        raise ValueError(msg)

    known = {str(label) for label in Label}
    out: dict[str, dict[str, Any]] = {}
    for change_id, value in raw.items():
        entry = {"label": value} if isinstance(value, str) else value
        if not isinstance(entry, dict):
            msg = f"{change_id}: expected a label or an object, got {type(value).__name__}"
            raise ValueError(msg)
        label = entry.get("label")
        if label is None:
            continue  # a skipped item, not an error
        if label not in known:
            msg = f"{change_id}: {label!r} is not in the taxonomy ({', '.join(sorted(known))})"
            raise ValueError(msg)
        seconds = entry.get("seconds")
        notes = entry.get("notes")
        out[change_id] = {
            "label": str(label),
            "notes": str(notes) if notes else None,
            "seconds": float(seconds) if isinstance(seconds, int | float) else None,
        }
    return out


_STYLE = """
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f6f7f9;color:#14181f}
header{position:sticky;top:0;background:#14181f;color:#fff;padding:14px 20px;z-index:5;
       display:flex;gap:18px;align-items:center;flex-wrap:wrap}
header h1{font-size:16px;margin:0;font-weight:600}
header .grow{flex:1}
button{font:inherit;padding:8px 14px;border-radius:7px;border:1px solid #55606d;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.wrap{max-width:920px;margin:0 auto;padding:22px 18px 120px}
.defs{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:16px 18px;
      margin-bottom:22px}
.defs h2{font-size:14px;margin:0 0 10px}
.defs dt{font-weight:600;margin-top:9px;
         font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.defs dd{margin:2px 0 0;color:#41505f}
.item{background:#fff;border:1px solid #dfe3e8;border-radius:10px;padding:16px 18px;
      margin-bottom:18px}
.item.done{border-color:#7fb98a;background:#fbfefb}
.meta{font-size:12px;color:#5b6b7c;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
      margin-bottom:10px;display:flex;gap:14px;flex-wrap:wrap}
.chg{border-left:3px solid #cbd3dc;padding:6px 0 6px 12px;margin:9px 0;overflow-x:auto}
.chg .path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
           color:#41505f}
.add{color:#136c2e;white-space:pre-wrap;word-break:break-word}
.rem{color:#9b2020;white-space:pre-wrap;word-break:break-word}
.ev{background:#fff8e6;border:1px solid #f0dfb0;border-radius:7px;padding:8px 11px;
    font-size:13px;margin-top:10px}
.ev ul{margin:6px 0 0;padding-left:20px}
.opts{display:flex;flex-wrap:wrap;gap:8px;margin-top:13px}
.opts label{border:1px solid #cbd3dc;border-radius:7px;padding:7px 11px;cursor:pointer;
            font-size:13px;background:#fbfcfd}
.opts label:hover{border-color:#8a97a5}
.opts input{margin-right:6px}
textarea{width:100%;margin-top:9px;border:1px solid #cbd3dc;border-radius:7px;padding:8px;
         font:inherit;resize:vertical}
"""

_SCRIPT = r"""
var BUNDLE = __BUNDLE__;
var answers = {};
var started = {};

function esc(s) {
  var d = document.createElement('div');
  d.textContent = s === null || s === undefined ? '' : String(s);
  return d.innerHTML;
}

function progress() {
  var n = Object.keys(answers).length;
  document.getElementById('count').textContent = n + ' / ' + BUNDLE.items.length;
  document.getElementById('save').disabled = n === 0;
}

function pick(id, label, card) {
  answers[id] = answers[id] || {};
  answers[id].label = label;
  var t0 = started[id] || Date.now();
  answers[id].seconds = Math.round((Date.now() - t0) / 100) / 10;
  card.classList.add('done');
  progress();
}

function note(id, value) {
  answers[id] = answers[id] || {};
  answers[id].notes = value || null;
}

function save() {
  var payload = JSON.stringify({format: BUNDLE.format, labels: answers}, null, 2);
  var blob = new Blob([payload], {type: 'application/json'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'mcpwatch-labels.json';
  a.click();
}

window.addEventListener('DOMContentLoaded', function () {
  var wrap = document.getElementById('items');
  BUNDLE.items.forEach(function (item, i) {
    started[item.change_id] = Date.now();
    var card = document.createElement('div');
    card.className = 'item';
    var h = '<div class="meta"><span>' + (i + 1) + ' / ' + BUNDLE.items.length + '</span>' +
            '<span>' + esc(item.server) + '</span><span>' + esc(item.layer) + '</span>' +
            '<span>' + esc(item.verdict) + '</span>';
    if (item.gap_days !== null && item.gap_days !== undefined) {
      h += '<span>' + item.gap_days.toFixed(2) + 'd apart</span>';
    }
    h += '</div>';
    item.changes.forEach(function (c) {
      h += '<div class="chg"><div class="path">[' + esc(c.kind) + '] ' + esc(c.path) +
           '</div>';
      if (c.added !== undefined) { h += '<div class="add">+ ' + esc(c.added) + '</div>'; }
      if (c.removed !== undefined) { h += '<div class="rem">- ' + esc(c.removed) + '</div>'; }
      if (c.before !== undefined) { h += '<div class="rem">from ' + esc(c.before) + '</div>'; }
      if (c.after !== undefined && c.added === undefined) {
        h += '<div class="add">to ' + esc(c.after) + '</div>';
      }
      h += '</div>';
    });
    if (item.evidence && item.evidence.length) {
      h += '<div class="ev"><b>rule hits</b> — evidence, not a verdict<ul>';
      item.evidence.forEach(function (e) { h += '<li>' + esc(e) + '</li>'; });
      h += '</ul></div>';
    }
    h += '<div class="opts">';
    Object.keys(BUNDLE.definitions).forEach(function (label) {
      h += '<label><input type="radio" name="r-' + esc(item.change_id) + '" value="' +
           esc(label) + '"><span>' + esc(label) + '</span></label>';
    });
    h += '</div><textarea rows="2" placeholder="notes (optional)"></textarea>';
    card.innerHTML = h;
    card.querySelectorAll('input[type=radio]').forEach(function (input) {
      input.addEventListener('change', function () {
        pick(item.change_id, input.value, card);
      });
    });
    card.querySelector('textarea').addEventListener('input', function (e) {
      note(item.change_id, e.target.value);
    });
    wrap.appendChild(card);
  });
  document.getElementById('save').addEventListener('click', save);
  progress();
});
"""


def render_html(bundle: dict[str, Any], *, title: str = "MCPWatch adjudication") -> str:
    """Render a bundle as one self-contained HTML file.

    No external requests and no frameworks: a rater opens it from a ``file://``
    URL, works down the page, and clicks Save to get a labels JSON back. That
    participation costs nothing but a browser is the entire point.
    """
    defs = "".join(
        f"<dt>{html.escape(name)}</dt><dd>{html.escape(text)}</dd>"
        for name, text in bundle["definitions"].items()
    )
    # `</` is escaped so a description containing "</script>" cannot close the
    # tag it is embedded in. The bundle is our own data, but a tool description
    # is third-party text and this file goes to someone outside the project.
    payload = json.dumps(bundle, ensure_ascii=False).replace("</", "<\\/")
    script = _SCRIPT.replace("__BUNDLE__", payload)
    count = len(bundle["items"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_STYLE}</style></head><body>
<header>
  <h1>{html.escape(title)}</h1>
  <span id="count">0 / {count}</span>
  <span class="grow"></span>
  <button id="save" disabled>Save labels</button>
</header>
<div class="wrap">
  <div class="defs">
    <h2>Pick exactly one label per change. The definitions below are binding —
        rate against these words, not your own reading of the label names.</h2>
    <dl>{defs}</dl>
    <p><b>Nothing saves automatically.</b> Click <i>Save labels</i> before closing.
       Partial progress is fine and imports as-is.</p>
  </div>
  <div id="items"></div>
</div>
<script>{script}</script>
</body></html>"""
