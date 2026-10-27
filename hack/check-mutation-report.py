#!/usr/bin/env python3
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

"""Enforce Gremlins' reported metrics despite v0.6.0's float CLI flag bug.

Viper returns float flags as strings; Gremlins' typed configuration getter
therefore reads the CLI thresholds as zero. Compare the JSON metrics too,
without reclassifying timed-out mutants or recalculating either metric.
"""

import json
import math
import sys


def main():
    report_path, efficacy, mcover = sys.argv[1:]
    with open(report_path, encoding="utf-8") as report_file:
        report = json.load(report_file)
    passed = True
    for metric, threshold in (
        ("test_efficacy", float(efficacy)),
        ("mutations_coverage", float(mcover)),
    ):
        value = report[metric]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 100:
            raise ValueError(f"invalid {metric}: expected a finite percentage")
        accepted = value >= threshold
        passed = passed and accepted
        print(f"{'PASS' if accepted else 'FAIL'} {metric}: {value:.2f}% (required >= {threshold:g}%)")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
