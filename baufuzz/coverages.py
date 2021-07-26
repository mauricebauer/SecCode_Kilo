# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021
# Adaption of: https://www.fuzzingbook.org/html/GreyboxFuzzer.html

import os
import gzip
import json
import pickle
import hashlib
from enum import Enum
from typing import Dict, Set, Tuple


class CoverageType(Enum):
    LINE = "LINE"
    BRANCH = "BRANCH"


class Coverage:
    def __init__(self, program: str) -> None:
        """Initialize coverage analyzer for gcov-usage.

        Args:
            program (str): Path to the testobject to be used with gcov.
        """
        self.program = program

    def _get_gcov_json(self) -> Dict:
        """Generates and parses a JSON file with gcov.

        Returns:
            Dict: JSON content as python dictionary.
        """
        os.system(f"gcov -b -i {self.program} >/dev/null 2>&1")
        file_name = self.program + ".gcov.json.gz"
        with gzip.open(file_name, "r") as file:
            data = file.read()
            return json.loads(data.decode("utf-8"))

    def _get_gcov_text(self) -> str:
        """Execute gcov and parse text output. Only works for line coverage!

        Returns:
            str: Gcov output.
        """
        os.system(f"gcov {self.program} >/dev/null 2>&1")
        file_name = self.program + ".c.gcov"
        with open(file_name, "r") as file:
            return file.read()

    def _line_coverage_text(self, text: str) -> Set[Tuple[int, int]]:
        """Parse line coverage from gcov text output.

        Args:
            text (str): Text output from gcov.

        Returns:
            Set[Tuple[int, int]]: Line coverage as a set with (line_number, 1 if covered else 0).
        """
        lines: Set[Tuple[int, int]] = set()
        for line in text.split("\n"):
            elems = line.split(':')
            if len(elems) < 2:
                continue
            covered = elems[0].strip()
            line_number = int(elems[1].strip())
            if covered.startswith('-') or covered.startswith('#'):
                lines.add((line_number, 0))
            else:
                lines.add((line_number, 1))
        return lines

    def _line_coverage_json(self, json_data: Dict) -> Set[Tuple[int, int]]:
        """Parse line coverage from gcov JSON-file.

        Args:
            json_data (Dict): Parsed JSON-file from gcov.

        Returns:
            Set[Tuple[int, int]]: Line coverage as a set with (line_number, 1 if covered else 0).
        """
        result: Set[Tuple[int, int]] = set()  # (line_number, count)
        for line in json_data['files'][0]['lines']:
            result.add((line['line_number'], 1 if line['count'] > 0 else 0))
        return result

    def _branch_coverage_json(self, json_data: Dict) -> Set[Tuple[str, int]]:
        """Parse branch coverage from gcov JSON-file.

        Args:
            json_data (Dict): Parsed JSON-file from gcov.

        Returns:
            Set[Tuple[str, int]]: Branch coverage as a set with (line_number:index, count).
        """
        result: Set[Tuple[str, int]] = set()  # (line_nbr:i, 1 or 0)
        for line in json_data['files'][0]['lines']:
            for i, branch in enumerate(line['branches']):
                result.add(
                    (f"{str(line['line_number'])}:{str(i)}", 1 if branch['count'] > 0 else 0))
        return result

    def coverage(self, coverage_type: CoverageType) -> Dict[CoverageType, Set]:
        """Get coverage from executed program using gcov.

        Args:
            branch_coverage (bool, optional): Is the branch coverage needed? Significantly slower! Defaults to False.

        Returns:
            Dict[CoverageType, Set]: Different coverages returned.
        """
        coverages: Dict[CoverageType, Set] = {}
        if coverage_type == CoverageType.LINE:
            gcov_text = self._get_gcov_text()
            coverages[CoverageType.LINE] = self._line_coverage_text(gcov_text)
        elif coverage_type == CoverageType.BRANCH:
            json_data = self._get_gcov_json()
            coverages[CoverageType.LINE] = self._line_coverage_json(json_data)
            coverages[CoverageType.BRANCH] = self._branch_coverage_json(
                json_data)
        else:
            raise NotImplementedError("Unknown coverage type")
        return coverages


def getPathID(coverage: Set) -> str:
    """Returns a unique string which identifies the seen `coverage`.

    Args:
        coverage (Set): Set of identifiers (e.g. lines or branches) seen during runtime.

    Returns:
        str: Unique string to identify this coverage.
    """
    pickled = pickle.dumps(coverage)
    return hashlib.md5(pickled).hexdigest()
