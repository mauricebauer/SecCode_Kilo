# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021
# Adaption of: https://www.fuzzingbook.org/html/Fuzzer.html

import os
import subprocess
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from .logs import FuzzingLog
from .coverages import Coverage, CoverageType


class TestOutcome(Enum):
    """ Enum with different states for a testobject execution. """
    PASS = "PASS"
    FAIL = "FAIL"
    UNRESOLVED = "UNRESOLVED"


class Runner:
    def __init__(self, coverage_type: Optional[CoverageType]) -> None:
        """Initialize the abstract `Runner`.

        Args:
            coverage_type (Optional[CoverageType]): `CoverageType` which should get recorded. Can be `None`.
        """
        self.log: Optional[FuzzingLog] = None
        self.coverage_type: Optional[CoverageType] = coverage_type

    def run(self, inp: str) -> Tuple[str, TestOutcome]:
        """Run the testobject with the given testdata `inp`.

        Args:
            inp (str): Testdata to be passed to the testobject.
        """
        return (inp, TestOutcome.UNRESOLVED)

    def __str__(self) -> str:
        return "runners.Runner"


class ProgramRunner(Runner):
    def __init__(self, program: str, coverage_type: Optional[CoverageType] = None) -> None:
        """Initialization of the `ProgramRunner` using the `program` as the testobject.

        Args:
            program (str): Path to the testobject to be executed.
        """
        super().__init__(coverage_type)
        self.program = program
        self.coverage_analyzer = Coverage(program)
        self.coverage_cache: Optional[Dict[CoverageType, FrozenSet]] = None

    def _get_outcome_from_return_code(self, return_code: int) -> TestOutcome:
        """Helper method to convert the `return_code` to a `TestOutcome` enum instance.

        Args:
            return_code (int): Return code of the execution (typically from subprocess).

        Returns:
            TestOutcome: Converted `TestOutcome` result
        """
        if return_code == 0:
            return TestOutcome.PASS
        elif return_code < 0:
            return TestOutcome.FAIL
        return TestOutcome.UNRESOLVED

    def coverage(self) -> Dict[CoverageType, Set]:
        """Get coverage results of last run.

        Returns:
            Dict[CoverageType, Set]: Coverage results for each `CoverageType`.
        """
        if self.coverage_type == None:
            return {}
        if self.coverage_cache == None:
            self.coverage_cache = self.coverage_analyzer.coverage(
                self.coverage_type)
        return self.coverage_cache

    def run_process(self, args: List[str] = [], inp: str = "") -> subprocess.CompletedProcess:
        """Runs the testobject with the passed `args` and input `inp`.

        Args:
            args (List[str], optional): List of parameters to be passed to the testobject without the testobject path! Defaults to [].
            inp (str, optional): Input to be passed to the stdin pipe of the testobject. Defaults to "".

        Returns:
            subprocess.CompletedProcess: Result of the execution from `subprocess.run`.
        """
        # First remove all coverage data
        if self.coverage_type != None and os.path.exists(self.program + ".gcda"):
            os.remove(self.program + ".gcda")
        if self.coverage_type != None and os.path.exists(self.program + ".c.gcov"):
            os.remove(self.program + ".c.gcov")
        self.coverage_cache = None
        return subprocess.run([self.program] + args,
                              input=inp,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              universal_newlines=True)

    def __str__(self) -> str:
        return "runners.ProgramRunner"


class ProgramRunnerFileInput(ProgramRunner):
    """ This class runs a given program with the input first stored in a given file and then passed as a parameter to the program. """

    def __init__(self, program: str, file_path: str, args: List[str] = [], coverage_type: Optional[CoverageType] = None) -> None:
        """Initialize ProgramRunnerFileInput with `file_path` information.

        Args:
            program (str): Program to be executed during test.
            file_path (str): Path where the testinput should be stored.
            args (List[str], optional): Arguments to pass to the program (in most cases the `file_path` should be passed here). Defaults to [].
        """
        super().__init__(program, coverage_type)  # Init parent
        self.file_path = file_path
        self.args = args

    def run(self, inp: str) -> Tuple[str, TestOutcome]:
        """Run the testobject with the given `inp` stored to the file at `file_path`.

        Args:
            inp (str): Fuzzing input to be stored in the file at `file_path`.

        Returns:
            Tuple[str, TestOutcome]: Test results.
        """
        with open(self.file_path, "w+") as file:
            # Write inp to file_path before starting testobject
            file.write(inp)
        result = self.run_process(args=self.args)
        outcome = self._get_outcome_from_return_code(result.returncode)
        if self.log != None:
            self.log.add(inp, outcome, self.coverage())
        return (inp, outcome)

    def __str__(self) -> str:
        return "runners.ProgramRunnerFileInput"


class ProgramRunnerArgsInput(ProgramRunner):
    """ This class runs a given program with the input passed as an argument to the program. """

    def __init__(self, program: str, coverage_type: Optional[CoverageType] = None) -> None:
        super().__init__(program, coverage_type)  # Init parent

    def run(self, inp: str) -> Tuple[str, TestOutcome]:
        """Run the testobject with the given `inp` stored to the file at `file_path`.

        Args:
            inp (str): Fuzzing input to be stored in the file at `file_path`.

        Returns:
            Tuple[str, TestOutcome]: Test results.
        """
        result = self.run_process(args=[inp.replace("\0", "")])
        outcome = self._get_outcome_from_return_code(result.returncode)
        if self.log != None:
            self.log.add(inp, outcome, self.coverage())
        return (inp, outcome)

    def __str__(self) -> str:
        return "runners.ProgramRunnerArgsInput"


class ProgramRunnerInput(ProgramRunner):
    """ This class runs a given program with the input passed to stdin. """

    def __init__(self, program: str, args: List[str] = [], coverage_type: Optional[CoverageType] = None) -> None:
        """Initialize ProgramRunnerInput with the testobject path `program` and optional `args` to be passed to the testobject.

        Args:
            program (str): Program to be executed during test.
            args (List[str], optional): Arguments to pass to the program. Defaults to [].
        """
        super().__init__(program, coverage_type)
        self.args = args

    def run(self, inp: str) -> Tuple[str, TestOutcome]:
        result = self.run_process(args=self.args, inp=inp)
        outcome = self._get_outcome_from_return_code(result.returncode)
        if self.log != None:
            self.log.add(inp, outcome, self.coverage())
        return (inp, outcome)

    def __str__(self) -> str:
        return "runners.ProgramRunnerInput"
