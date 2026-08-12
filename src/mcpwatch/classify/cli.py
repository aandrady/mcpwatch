"""``python -m mcpwatch.classify`` — sample, classify, adjudicate, score.

Four subcommands, in the order a calibration cycle uses them:

``sample``       draw a fixed calibration set from the corpus, stratified
``run``          label ChangeSets with the rule layer, and optionally the model
``adjudicate``   review items one at a time and record an independent label
``reliability``  Cohen's κ between raters, and between the machine and consensus

**On showing the model's label to the human.** WP7's brief asks the review UI to
display the LLM label and rationale. It is off by default here, behind
``--show-llm``, because the same package is asked to report κ between the LLM
and human consensus — and a rater who saw the model's answer before deciding is
not an independent second opinion. Anchoring would inflate that κ without
anyone being able to see it in the data. The flag exists for the case the brief
has in mind (a human triaging a queue, where the model's rationale is a useful
starting point) and should not be used while adjudicating the calibration set.
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

from mcpwatch.diff import ChangeSet, DiffEngine
from mcpwatch.store import Corpus, Layer

from . import reliability
from .llm import MODEL_ID, LlmClassifier
from .rules import classify as rule_classify
from .rules import describe, evaluate
from .store import Adjudication, CalibrationFrame, ClassifyStore, MachineLabel
from .taxonomy import Label, definition

__all__ = ["main"]

CALIBRATION_TARGET = 200
"""The plan's Phase-2 gate is stated over 200 adjudicated diffs."""


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def _store_path(corpus_root: Path) -> Path:
    """Beside the corpus, so the backup job covers the adjudications."""
    return corpus_root / "classify.db"


def _changesets(corpus: Corpus, layer: Layer, limit: int | None = None) -> list[ChangeSet]:
    engine = DiffEngine(corpus)
    out: list[ChangeSet] = []
    for changeset in engine.changesets(layer=layer):
        if not changeset.changes or changeset.quarantined:
            continue
        out.append(changeset)
        if limit is not None and len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------ sample ---


def _sample(args: argparse.Namespace) -> int:
    """Draw a stratified calibration set.

    Stratified rather than random: a uniform draw over the corpus is ~97%
    unflagged ordinary maintenance, and a calibration set of 200 such items
    would measure agreement on `benign` and nothing else. The rare classes are
    the ones the gate needs to be able to see, so flagged ChangeSets are
    deliberately over-sampled — and the stratum is recorded on each row so the
    over-sampling can be corrected for when reporting base rates.
    """
    rng = random.Random(args.seed)
    with Corpus(args.corpus) as corpus:
        pool = _changesets(corpus, Layer(args.layer))

    flagged = [c for c in pool if c.flags]
    plain = [c for c in pool if not c.flags]
    rng.shuffle(flagged)
    rng.shuffle(plain)

    want_flagged = min(len(flagged), args.size // 2)
    chosen = flagged[:want_flagged] + plain[: args.size - want_flagged]
    items = {c.change_id: ("flagged" if c.flags else "unflagged") for c in chosen}

    with ClassifyStore(_store_path(args.corpus)) as store:
        existing = store.calibration_set()
        # A set already under adjudication is the expensive thing in this
        # project, and a second draw silently enlarging it would change what the
        # reported kappa is measured over. Growing it has to be deliberate.
        if existing and not args.extend:
            print(
                f"calibration set already holds {len(existing)} item(s); "
                "pass --extend to add to it",
                file=sys.stderr,
            )
            return 1
        added = store.add_calibration_items(items, layer=args.layer)
        store.add_calibration_frame(
            CalibrationFrame(
                layer=args.layer,
                seed=args.seed,
                size=args.size,
                pool_total=len(pool),
                pool_flagged=len(flagged),
                added=added,
            )
        )
        total = len(store.calibration_set())

    print(
        f"layer {args.layer}, seed {args.seed}: pool {len(pool)} changesets "
        f"({len(flagged)} flagged) -> added {added}, calibration set now {total}"
    )
    if total < CALIBRATION_TARGET:
        print(f"note: the gate is stated over {CALIBRATION_TARGET} items", file=sys.stderr)
    return 0


# --------------------------------------------------------------------- run ---


def _run(args: argparse.Namespace) -> int:
    """Label ChangeSets with the rule layer, and optionally the model."""
    with Corpus(args.corpus) as corpus:
        pool = _changesets(corpus, Layer(args.layer), limit=args.limit)
        by_id = {c.change_id: c for c in pool}

        with ClassifyStore(_store_path(args.corpus)) as store:
            if args.calibration_only:
                wanted = {row["change_id"] for row in store.calibration_set()}
                pool = [c for c in pool if c.change_id in wanted]

            settled = deferred = 0
            for changeset in pool:
                label, hits = rule_classify(changeset)
                store.put_machine_label(
                    MachineLabel(
                        change_id=changeset.change_id,
                        source="rules",
                        label=str(label) if label else "deferred",
                        rationale="; ".join(f"{h.rule}={h.evidence}" for h in hits) or None,
                        hits=tuple(h.as_json() for h in hits),
                    )
                )
                settled += int(label is not None)
                deferred += int(label is None)

            print(f"rules: {settled} settled, {deferred} deferred to the model")

            if not args.llm:
                print("model layer not run (pass --llm)")
                return 0

            classifier = LlmClassifier(store, model_id=args.model)
            done = failed = 0
            for changeset in pool:
                label, hits = rule_classify(changeset)
                if label is not None and not args.llm_all:
                    continue
                try:
                    verdict = classifier.classify(changeset, hits)
                except Exception as exc:
                    failed += 1
                    print(f"  {changeset.change_id}: {type(exc).__name__}: {exc}", file=sys.stderr)
                    continue
                done += 1
                if args.verbose:
                    marker = "cached" if verdict.cached else "fresh"
                    print(
                        f"  {changeset.change_id} {verdict.label} "
                        f"({verdict.confidence:.2f}, {marker})"
                    )
            print(f"model: {done} labelled, {failed} failed")
        del by_id
    return 0


# -------------------------------------------------------------- adjudicate ---


def _render(changeset: ChangeSet, hits: list[object]) -> str:
    lines = [
        "=" * 78,
        f"server:   {changeset.server_key}",
        f"verdict:  {changeset.verdict}   layer: {changeset.layer}",
        f"window:   {changeset.from_effective_at} -> {changeset.to_effective_at}",
    ]
    gap = changeset.gap_days
    if gap is not None:
        lines.append(f"gap:      {gap:.2f} days")
    if changeset.flags:
        lines.append(f"flags:    {', '.join(str(f) for f in changeset.flags)}")
    lines.append("-" * 78)
    for change in changeset.changes[:25]:
        lines.append(f"[{change.kind}] {change.path}")
        if change.text is not None and change.text.added:
            lines.append(f"    + {' '.join(change.text.added)[:600]}")
            if change.text.removed:
                lines.append(f"    - {' '.join(change.text.removed)[:300]}")
        else:
            after = json.dumps(change.after, ensure_ascii=False)[:400]
            before = json.dumps(change.before, ensure_ascii=False)[:200]
            if change.before is not None:
                lines.append(f"    from {before}")
            lines.append(f"    to   {after}")
    if len(changeset.changes) > 25:
        lines.append(f"... {len(changeset.changes) - 25} more changes")
    if hits:
        lines.append("-" * 78)
        lines.append("rule hits (evidence, not a verdict):")
        for hit in hits:
            rule = getattr(hit, "rule", "")
            lines.append(f"  {rule}: {describe(rule)} — {getattr(hit, 'evidence', '')}")
    return "\n".join(lines)


def _adjudicate(args: argparse.Namespace) -> int:
    """Review calibration items one at a time and record a label."""
    if not sys.stdin.isatty():
        print("adjudication needs an interactive terminal", file=sys.stderr)
        return 1

    with Corpus(args.corpus) as corpus, ClassifyStore(_store_path(args.corpus)) as store:
        pending = store.pending_for(args.rater)
        if not pending:
            print(f"nothing pending for rater {args.rater!r}")
            return 0

        # Each item is resolved against the layer it was drawn from, not against
        # a --layer flag. An item is only findable in its own layer's diff, so
        # taking the layer from the flag would silently skip the whole set the
        # first time someone ran this with the default.
        wanted: dict[str, set[str]] = {}
        for row in pending:
            wanted.setdefault(row["layer"] or args.layer, set()).add(row["change_id"])
        pool: dict[str, ChangeSet] = {}
        for layer, ids in wanted.items():
            pool.update(
                {c.change_id: c for c in _changesets(corpus, Layer(layer)) if c.change_id in ids}
            )

        choices = list(Label)
        print(
            f"{len(pending)} items pending for {args.rater}. Ctrl-C to stop; progress is saved.\n"
        )
        for index, row in enumerate(pending, start=1):
            change_id = row["change_id"]
            changeset = pool.get(change_id)
            if changeset is None:
                layer = row["layer"] or args.layer
                print(f"[{index}] {change_id}: not present in the {layer} diff — skipping")
                continue
            hits = evaluate(changeset)
            print(f"\n[{index}/{len(pending)}] {change_id}")
            print(_render(changeset, list(hits)))

            if args.show_llm:
                said = store.machine_label(change_id, source="llm")
                if said is not None:
                    print("-" * 78)
                    print(f"model said: {said['label']} ({said['confidence']})")
                    print(f"  {said['rationale']}")

            print("-" * 78)
            for number, label in enumerate(choices, start=1):
                print(f"  {number}. {label}")
            print("  ?. show definitions   s. skip   q. quit")

            while True:
                answer = input("label> ").strip().lower()
                if answer == "q":
                    print("stopped; progress saved")
                    return 0
                if answer == "s":
                    break
                if answer == "?":
                    for label in choices:
                        print(f"\n{label}:\n  {definition(label)}")
                    continue
                if answer.isdigit() and 1 <= int(answer) <= len(choices):
                    label = choices[int(answer) - 1]
                    notes = input("notes (optional)> ").strip() or None
                    store.add_adjudication(
                        Adjudication(
                            change_id=change_id, rater=args.rater, label=str(label), notes=notes
                        )
                    )
                    print(f"recorded {label}")
                    break
                print("enter a number, ? for definitions, s to skip, or q to quit")
    return 0


# ------------------------------------------------------------- reliability ---


def _reliability(args: argparse.Namespace) -> int:
    """Report Cohen's κ between raters, and between the machine and consensus."""
    with ClassifyStore(_store_path(args.corpus)) as store:
        raters = store.raters()
        payload: dict[str, object] = {"raters": raters}
        report: list[str] = []

        if len(raters) < 2:
            report.append(
                f"only {len(raters)} rater(s) have adjudicated: "
                "Cohen's kappa between raters needs two independent sets of labels."
            )
        else:
            for i, first in enumerate(raters):
                for second in raters[i + 1 :]:
                    agreement = reliability.score(
                        store.rater_labels(first), store.rater_labels(second)
                    )
                    report.append(f"\n=== {first} vs {second} ===\n{agreement.render()}")
                    payload[f"{first}|{second}"] = agreement.as_json()

        truth = store.consensus()
        report.append(f"\n=== consensus ground truth: {len(truth)} items ===")
        for source in ("rules", "llm"):
            machine = {
                k: v for k, v in store.machine_labels(source=source).items() if v != "deferred"
            }
            if not machine:
                report.append(f"{source}: no labels recorded")
                continue
            agreement = reliability.score(machine, truth)
            report.append(f"\n=== {source} vs human consensus ===\n{agreement.render()}")
            payload[f"{source}|consensus"] = agreement.as_json()

            precisions = {}
            for label in Label:
                value, hits, correct = reliability.precision_against(machine, truth, str(label))
                if hits:
                    precisions[str(label)] = {
                        "precision": None if value is None else round(value, 4),
                        "predicted": hits,
                        "correct": correct,
                    }
            payload[f"{source}_precision"] = precisions
            if precisions:
                report.append(f"\n{source} precision against adjudicated truth:")
                for name, stats in sorted(precisions.items()):
                    report.append(
                        f"  {name:24} {stats['correct']}/{stats['predicted']}"
                        f" = {stats['precision']}"
                    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print("\n".join(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.classify",
        description="Classify, adjudicate, and measure agreement over ChangeSets.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--layer", choices=("registry", "manifest"), default="manifest")
    sub = parser.add_subparsers(dest="command", required=True)

    sample = sub.add_parser("sample", help="draw a fixed, stratified calibration set")
    sample.add_argument("--size", type=int, default=CALIBRATION_TARGET)
    sample.add_argument(
        "--seed", type=int, default=20260812, help="fixed so the draw is reproducible"
    )
    sample.add_argument(
        "--extend",
        action="store_true",
        help="add to an existing calibration set instead of refusing; changes what "
        "the reported kappa is measured over",
    )
    sample.set_defaults(func=_sample)

    run = sub.add_parser("run", help="label ChangeSets with the rules, and optionally the model")
    run.add_argument(
        "--llm", action="store_true", help="run the model on what rules left unsettled"
    )
    run.add_argument(
        "--llm-all", action="store_true", help="run the model on every item, even settled ones"
    )
    run.add_argument(
        "--model", default=MODEL_ID, help="override the pinned model (drift experiments only)"
    )
    run.add_argument("--calibration-only", action="store_true")
    run.add_argument("--limit", type=int, default=None)
    run.add_argument("--verbose", action="store_true")
    run.set_defaults(func=_run)

    adjudicate = sub.add_parser("adjudicate", help="review calibration items and record a label")
    adjudicate.add_argument(
        "--rater", required=True, help="your rater id; raters work blind to each other"
    )
    adjudicate.add_argument(
        "--show-llm",
        action="store_true",
        help="show the model's label before you decide — anchors you, so never use this "
        "while adjudicating the calibration set",
    )
    adjudicate.set_defaults(func=_adjudicate)

    score = sub.add_parser("reliability", help="Cohen's kappa, overall and per class")
    score.add_argument("--json", action="store_true")
    score.set_defaults(func=_reliability)

    args = parser.parse_args(argv)
    result = args.func(args)
    return int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
