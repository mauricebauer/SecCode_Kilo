# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021

import os
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set
from .coverages import CoverageType


class FuzzingLogEntry:
    # No static type hints because of circular dependency!
    def __init__(self, inp: str, outcome) -> None:
        """Initializes the `FuzzingLogEntry`.

        Args:
            inp (str): Testinput which was used.
            outcome (TestOutcome): Result which was achieved.
        """
        self.inp = inp
        self.outcome = outcome
        self.timestamp = datetime.now()


class FuzzingLog:
    def __init__(self, fuzzer, runner) -> None:
        """Initializes the `FuzzingLog`.

        Args:
            fuzzer (Fuzzer): Fuzzer to which the log should be injected.
            runner (Runner): Runner to which the log should be injected.
        """
        self.fuzzer = fuzzer
        self.runner = runner
        self.runner.log = self  # Inject ourself
        self.start_timestamp = datetime.now()
        self.end_timestamp: Optional[float] = None
        self.entries: List[FuzzingLogEntry] = []
        self.coverages: Dict[CoverageType, Dict] = defaultdict(
            lambda: defaultdict(lambda: 0))
        self.coverage_progress: Dict[CoverageType, Dict[float, int]] = defaultdict(
            lambda: defaultdict(lambda: 0))

    def add(self, inp: str, outcome, coverage: Dict[CoverageType, Set]) -> None:
        """Add an entry to the log.

        Args:
            inp (str): Testinput which was used.
            outcome (TestOutcome): Result which was achieved.
            coverage (Dict[CoverageType, Set]): Coverage measurement which should get saved.
        """
        entry = FuzzingLogEntry(inp, outcome)
        self.entries.append(entry)
        for type in coverage.keys():
            dictionary = dict(coverage[type])
            for key in dictionary.keys():
                self.coverages[type][key] += dictionary[key]
            self.coverage_progress[type][(entry.timestamp-self.start_timestamp).total_seconds(
            )/60] = sum(1 for x in self.coverages[type].values() if x > 0)

    def end(self) -> None:
        """ Stop the fuzzing test and set the `end_timestamp`. """
        self.end_timestamp = datetime.now()

    def save(self, path: str) -> None:
        """Save the fuzzing log as a textfile `log.txt` to the `path`.

        Args:
            path (str): Path where the `log.txt`-result should be save to.
        """
        if self.end_timestamp == None:
            self.end_timestamp = datetime.now()
        if not os.path.exists(path):
            os.mkdir(path)
        now = datetime.now()
        folder_name = now.strftime("%Y-%m-%d-%H-%M-%S")
        os.mkdir(os.path.join(path, folder_name))
        with open(os.path.join(path, folder_name, "log.txt"), "w") as log_file:
            log_file.write(str(self))
        for i, log_entry in enumerate(list(filter(lambda e: e.outcome.value == "FAIL", self.entries))):
            with open(os.path.join(path, folder_name, f"crash_{str(i)}"), "w") as crash_file:
                crash_file.write(log_entry.inp)
        for i, log_entry in enumerate(list(filter(lambda e: e.outcome.value == "UNRESOLVED", self.entries))):
            with open(os.path.join(path, folder_name, f"unresolved_{str(i)}"), "w") as unresolved_file:
                unresolved_file.write(log_entry.inp)

    def __str__(self) -> str:
        if self.end_timestamp == None:
            self.end_timestamp = datetime.now()
        return f"""Starttime: {self.start_timestamp.isoformat()}
Endtime:   {self.end_timestamp.isoformat()}
Speed:     {len(self.entries)/(self.end_timestamp-self.start_timestamp).total_seconds():.2f} Excs./s
Fuzzer:    {self.fuzzer}
Runner:    {self.runner}
Entries:   {len(self.entries)} (PASS={str(sum(1 for e in self.entries if e.outcome.value == "PASS"))} FAIL={str(sum(1 for e in self.entries if e.outcome.value == "FAIL"))} UNRESOLVED={str(sum(1 for e in self.entries if e.outcome.value == "UNRESOLVED"))})
"""
