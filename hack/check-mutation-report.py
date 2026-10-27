#!/usr/bin/env python3
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

"""Enforce Gremlins v0.6.0 metrics and require conclusive mutant results.

Viper returns float flags as strings; Gremlins' typed configuration getter
therefore reads the CLI thresholds as zero. Check the reported JSON metrics
and count every mutation separately: timeouts are never kills. Exit codes:
0 = PASS, 1 = FAIL (including invalid reports), 2 = INCONCLUSIVE (>20% timed
out). Both non-zero codes fail the gate. An optional fourth argument labels
the package; otherwise the report filename is used.
"""

import json
import math
import sys
from pathlib import Path

STATUSES = ("KILLED", "LIVED", "NOT COVERED", "TIMED OUT", "NOT VIABLE")


def percentage(value, name):
    if (
        type(value) not in (int, float)
        or not 0 <= value <= 100
        or not math.isfinite(value)
    ):
        raise ValueError(f"invalid {name}: expected a finite percentage")
    return value


def mutation_counts(report):
    files = report["files"]
    if not isinstance(files, list) or not files:
        raise ValueError("files must be a non-empty array")
    counts = dict.fromkeys(STATUSES, 0)
    unresolved = []
    for file in files:
        if not isinstance(file, dict):
            raise TypeError("each file must be an object")
        filename = file["file_name"]
        if not isinstance(filename, str) or not filename.strip():
            raise ValueError("file_name must be a non-empty string")
        mutations = file["mutations"]
        if not isinstance(mutations, list) or not mutations:
            raise ValueError(f"{filename}: mutations must be a non-empty array")
        for mutation in mutations:
            if not isinstance(mutation, dict):
                raise TypeError(f"{filename}: each mutation must be an object")
            status = mutation["status"]
            if not isinstance(status, str) or status not in counts:
                raise ValueError(f"{filename}: unknown mutation status {status!r}")
            mutator = mutation["type"]
            if not isinstance(mutator, str) or not mutator.strip():
                raise ValueError(
                    f"{filename}: mutation type must be a non-empty string"
                )
            line, column = mutation["line"], mutation["column"]
            if any(type(pos) is not int or pos <= 0 for pos in (line, column)):
                raise ValueError(
                    f"{filename}: line and column must be positive integers"
                )
            counts[status] += 1
            if status in ("TIMED OUT", "NOT VIABLE"):
                unresolved.append(f"{status}: {filename}:{line}:{column} {mutator}")
    return counts, unresolved


def check_report(report, efficacy, mcover, package):
    if not isinstance(report, dict):
        raise TypeError("report must be an object")
    counts, unresolved = mutation_counts(report)
    # v0.6.0 report.go:fileReport excludes NOT COVERED and TIMED OUT from
    # mutants_total and has no top-level timeout count. Use its exact schema.
    expected_counts = {
        "mutants_killed": counts["KILLED"],
        "mutants_lived": counts["LIVED"],
        "mutants_not_covered": counts["NOT COVERED"],
        "mutants_not_viable": counts["NOT VIABLE"],
        "mutants_total": counts["KILLED"] + counts["LIVED"] + counts["NOT VIABLE"],
    }
    for key, expected in expected_counts.items():
        value = report[key]
        if type(value) is not int or value < 0 or value != expected:
            raise ValueError(
                f"invalid {key}: expected {expected} from mutation statuses"
            )

    metrics = (
        (
            "test_efficacy",
            percentage(report["test_efficacy"], "test_efficacy"),
            efficacy,
        ),
        (
            "mutations_coverage",
            percentage(report["mutations_coverage"], "mutations_coverage"),
            mcover,
        ),
    )
    total = sum(counts.values())
    timeout_share = counts["TIMED OUT"] / total * 100
    inconclusive = counts["TIMED OUT"] * 5 > total
    passed = not unresolved and all(
        value >= threshold for _, value, threshold in metrics
    )
    result = "INCONCLUSIVE" if inconclusive else "PASS" if passed else "FAIL"
    print(
        f"{result} {package}: killed={counts['KILLED']}, survived(lived)={counts['LIVED']}, "
        f"not covered={counts['NOT COVERED']}, timed out={counts['TIMED OUT']}, "
        f"not viable={counts['NOT VIABLE']}, total={total}, "
        f"efficacy={metrics[0][1]:.2f}%, mutant coverage={metrics[1][1]:.2f}%, "
        f"timeout share={timeout_share:.2f}%"
    )
    for mutant in unresolved:
        print(f"{result} {package}: {mutant}")
    for metric, value, threshold in metrics:
        if value < threshold:
            print(
                f"FAIL {package}: {metric}: {value:.2f}% (required >= {threshold:g}%)"
            )
    if inconclusive:
        print(f"INCONCLUSIVE {package}: timed-out mutants exceed 20% of all mutants")
        return 2
    return 0 if passed else 1


def main():
    try:
        if len(sys.argv) not in (4, 5):
            raise ValueError(
                "usage: check-mutation-report.py REPORT EFFICACY MCOVER [PACKAGE]"
            )
        report_path, efficacy, mcover = sys.argv[1:4]
        efficacy = percentage(float(efficacy), "efficacy threshold")
        mcover = percentage(float(mcover), "coverage threshold")
        package = sys.argv[4] if len(sys.argv) == 5 else Path(report_path).stem
        with open(report_path, encoding="utf-8") as report_file:
            report = json.load(report_file)
        return check_report(report, efficacy, mcover, package)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
