#!/usr/bin/env python3
"""Minimal regression cases for dgmap's check semantics.

Run from the template root:
  python3 -m unittest discover -s tests -v

These exercise the classification rules with synthetic report/profile dicts
(no experiment binaries required):

* empty check targets          -> profile error, check fails;
* unknown ``expected`` keys    -> profile error (never silently skipped);
* method matched by name with several candidates but no ``expected_func``
  -> INTERMEDIATE evidence, not verification;
* expected_func mismatch       -> reference error;
* rule_record key format       -> per-experiment, declared in the profile.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import dgmap


def make_report(**overrides):
    report = {
        "metadata": {
            "method_count": 10,
            "type_count": 5,
            "literal_count": 7,
            "pair_count": 11,
            "max_destination": 100,
        },
        "table_size": 50,
        "dispatch": {"0": [(100, 65535)]},
        "target_literals": {},
        "methods": [],
        "field_access": {},
    }
    report.update(overrides)
    return report


def make_profile(**overrides):
    profile = {
        "name": "synthetic",
        "_path": os.path.join(tempfile.gettempdir(), "synthetic-profile.json"),
        "expected": {},
        "methods": [],
        "target_literals": {},
        "fields": {},
        "rule_record": None,
        "incomplete_inferences": [],
    }
    profile.update(overrides)
    return profile


class EmptyCheckTargetsTests(unittest.TestCase):
    def test_no_targets_is_a_profile_error_not_success(self):
        result = dgmap.check(make_report(), make_profile())
        self.assertTrue(result["profile_errors"])
        self.assertIn(
            "no check targets", result["profile_errors"][0]
        )

    def test_targets_present_silences_the_error(self):
        profile = make_profile(
            methods=[{"type": "T", "method": "m", "expected_func": 12}]
        )
        report = make_report(
            methods=[
                {
                    "type": "T",
                    "method": "m",
                    "found": True,
                    "resolved": True,
                    "candidates": [{"target": 12}],
                    "resolved_target": 12,
                    "expected_func": 12,
                }
            ]
        )
        result = dgmap.check(report, profile)
        self.assertEqual(result["profile_errors"], [])


class UnknownExpectedKeyTests(unittest.TestCase):
    def test_unknown_key_is_profile_error(self):
        profile = make_profile(
            methods=[{"type": "T", "method": "m", "expected_func": 12}],
            expected={"literal_coutn": 7},  # typo -> unknown key
        )
        result = dgmap.check(make_report(), profile)
        self.assertTrue(
            any("unknown expected key" in e for e in result["profile_errors"])
        )

    def test_known_key_mismatch_is_structure_error(self):
        profile = make_profile(
            methods=[{"type": "T", "method": "m", "expected_func": 12}],
            expected={"literal_count": 8},
        )
        result = dgmap.check(make_report(), profile)
        self.assertEqual(result["profile_errors"], [])
        self.assertTrue(
            any("literal_count" in e for e in result["structure_errors"])
        )


class CandidateDisambiguationTests(unittest.TestCase):
    def _found_method(self, n_candidates, expected_func=None):
        return {
            "type": "T",
            "method": "m",
            "found": True,
            "resolved": True,
            "candidates": [{"target": 10 + i} for i in range(n_candidates)],
            "resolved_target": 10,
            "expected_func": expected_func,
        }

    def test_name_match_without_expected_func_is_intermediate(self):
        profile = make_profile(methods=[{"type": "T", "method": "m"}])
        result = dgmap.check(make_report(methods=[self._found_method(2)]), profile)
        self.assertEqual(result["reference_errors"], [])
        self.assertEqual(len(result["intermediate_evidence"]), 1)
        self.assertIn("not verified", result["intermediate_evidence"][0])
        self.assertIn("2 candidate(s)", result["intermediate_evidence"][0])

    def test_single_candidate_without_expected_func_still_intermediate(self):
        profile = make_profile(methods=[{"type": "T", "method": "m"}])
        result = dgmap.check(make_report(methods=[self._found_method(1)]), profile)
        self.assertEqual(result["reference_errors"], [])
        self.assertEqual(len(result["intermediate_evidence"]), 1)

    def test_expected_func_mismatch_is_reference_error(self):
        profile = make_profile(
            methods=[{"type": "T", "method": "m", "expected_func": 11}]
        )
        result = dgmap.check(make_report(methods=[self._found_method(2, 11)]), profile)
        self.assertEqual(result["intermediate_evidence"], [])
        self.assertTrue(
            any("func[10] != expected func[11]" in e for e in result["reference_errors"])
        )

    def test_expected_func_match_verifies(self):
        profile = make_profile(
            methods=[{"type": "T", "method": "m", "expected_func": 10}]
        )
        result = dgmap.check(make_report(methods=[self._found_method(2, 10)]), profile)
        self.assertEqual(result["reference_errors"], [])
        self.assertEqual(result["intermediate_evidence"], [])

    def test_unresolved_method_is_reference_error(self):
        profile = make_profile(methods=[{"type": "T", "method": "m"}])
        m = self._found_method(1)
        m["resolved"] = False
        result = dgmap.check(make_report(methods=[m]), profile)
        self.assertTrue(result["reference_errors"])


class RuleRecordKeyFormatTests(unittest.TestCase):
    def test_expected_key_without_key_format_is_profile_error(self):
        profile = make_profile(
            rule_record={
                "config": "/nonexistent.json",
                "list": "L",
                "index": 6,
                "expected_key": "a6b:",
            }
        )
        result = dgmap.check(make_report(), profile)
        self.assertTrue(
            any("key_format" in e for e in result["profile_errors"])
        )

    def test_key_format_derivation_checked(self):
        # config missing -> reference error, but the key-format derivation
        # must still be validated (wrong expected_key appended)
        profile = make_profile(
            rule_record={
                "config": "/nonexistent.json",
                "list": "L",
                "index": 6,
                "key_format": "a{index}b:",
                "expected_key": "a7b:",
            }
        )
        result = dgmap.check(make_report(), profile)
        self.assertTrue(
            any("a7b:" in e for e in result["reference_errors"])
        )


if __name__ == "__main__":
    unittest.main()
