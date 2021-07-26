# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021
# Adaption of: https://www.fuzzingbook.org/html/Fuzzer.html

import sys
import time
import random
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from .seeds import Seed
from .mutators import Mutator
from .coverages import getPathID
from .runners import Runner, TestOutcome
from .schedules import RandomSchedule, Schedule
from .grammars import START_SYMBOL, nonterminals


class Fuzzer:
    def __init__(self) -> None:
        """Initialized the abstract `Fuzzer`.
        """
        self.last_print = time.time()

    def fuzz(self) -> str:
        """Create fuzzing input to be passed to the testobject.

        Returns:
            str: Created input to be passed to the testobject.
        """
        return ""

    def run(self, runner: Runner) -> Tuple[str, TestOutcome]:
        """Runs the testobject using the passed runner and a created fuzz input.

        Args:
            runner (Runner): Runner to be used with the fuzz input.

        Returns:
            Tuple[str, TestOutcome]: Test results.
        """
        return runner.run(self.fuzz())

    def runs(self, runner: Runner, trials: Optional[int] = None, duration_min: Optional[float] = None) -> None:
        """Runs the testobject using the passed runner and a created fuzz input `trials`-times or for `duration_min` minutes.

        Args:
            runner (Runner): Runner to be used with the fuzz input.
            trials (Optional[int], optional): Number of time the test should be executed. Defaults to 1000 if no time limit.
            duration_min (Optional[float], optional): Time limit in minutes. Defaults to no limit.
        """
        if duration_min == None and trials == None:
            print("Setting `trials`-Limit in runs() to 1000")
            trials = 1000  # Default value
        if trials == None:
            trials = sys.maxsize
        if duration_min == None:
            duration_min = 1e30
        start_timestamp = datetime.now()
        i = 0
        while True:
            self.run(runner)
            end = ((datetime.now()-start_timestamp).total_seconds() /
                   60) > duration_min or (i+1) >= trials
            if time.time()-self.last_print > 30 or end:
                print(f"Iteration:  {str(i+1)}")
                print(
                    f"Duration:   {(datetime.now()-start_timestamp).total_seconds():.2f} s")
                if 'population' in self.__dict__:
                    print(f"Population: {len(self.__dict__['population'])}")
                if runner.log != None:
                    print(f"Status:     PASS={str(sum(1 for e in runner.log.entries if e.outcome == TestOutcome.PASS))} FAIL={str(sum(1 for e in runner.log.entries if e.outcome == TestOutcome.FAIL))} UNRESOLVED={str(sum(1 for e in runner.log.entries if e.outcome == TestOutcome.UNRESOLVED))}")
                self.last_print = time.time()
                print()
            if end:
                return
            i += 1

    def __str__(self) -> str:
        return "fuzzers.Fuzzer"


class MutationFuzzer(Fuzzer):
    def __init__(self, seeds: List[Seed], mutator: Mutator = Mutator(), schedule: Schedule = RandomSchedule()) -> None:
        """Initializes the `MutationFuzzer`.

        Args:
            seeds (List[Seed]): Seeds to be used for mutation.
            mutator (Mutator, optional): Mutator-Class to be used for mutations. Defaults to Mutator().
            schedule (Schedule, optional): Schedule-Class to be used for selection. Defaults to RandomSchedule().
        """
        super().__init__()
        self.seeds = seeds
        self.mutator = mutator
        self.schedule = schedule
        self.population: List[Seed] = []
        self.seed_index = 0
        self.reset()

    def reset(self) -> None:
        """ Resets the `population` and `seed_index`. """
        self.population = self.seeds
        self.seed_index = 0

    def create_candidate(self) -> str:
        """Creates a new candidate for running with the testobject, selected with the given `schedule` and mutated with the given `mutator`.

        Returns:
            str: Chosen and mutated candidate.
        """
        seed = self.schedule.choose(self.population)
        candidate = seed.data
        trials = random.randint(2, 100)
        for _ in range(trials):
            candidate = self.mutator.mutate(candidate)
        return candidate

    def fuzz(self) -> str:
        """Create fuzzing input to be used for the testobject.

        Returns:
            str: Testdata to be passed to the testobject.
        """
        if self.seed_index < len(self.seeds):
            # Seeding
            inp = self.seeds[self.seed_index].data
            self.seed_index += 1
        else:
            # Mutation
            inp = self.create_candidate()
        return inp

    def __str__(self) -> str:
        return "fuzzers.MutationFuzzer"


class MutationCoverageFuzzer(MutationFuzzer):
    def __init__(self, seeds: List[Seed], mutator: Mutator = Mutator(), schedule: Schedule = RandomSchedule()) -> None:
        """Initializes the `MutationCoverageFuzzer`.

        Args:
            seeds (List[Seed]): Seeds to be used for mutation.
            mutator (Mutator, optional): Mutator-Class to be used for mutations. Defaults to Mutator().
            schedule (Schedule, optional): Schedule-Class to be used for selection. Defaults to RandomSchedule().
        """
        self.coverages_seen: Set = set()
        super().__init__(seeds, mutator=mutator, schedule=schedule)

    def reset(self) -> None:
        """ Resets the `population`, `seed_index` and the `coverages_seen`. """
        super().reset()
        self.coverages_seen = set()
        self.population = []

    def run(self, runner: Runner) -> Tuple[str, TestOutcome]:
        """Run the testobject with a fuzzing input from `self.fuzz()`.

        Args:
            runner (Runner): Runner to be used for executing the testobject.

        Returns:
            Tuple[str, TestOutcome]: Used testinput (input, result).
        """
        inp, outcome = super().run(runner)
        # coverage = list of lines (line-coverage) or list of branches (branch-coverage)
        coverage = [x[0]
                    for x in runner.coverage()[runner.coverage_type] if x[1] > 0]
        if outcome == TestOutcome.PASS and self._is_new_coverage(coverage):
            self.population.append(Seed(inp))
            for identifier in coverage:
                self.coverages_seen.add(identifier)
        return (inp, outcome)

    def _is_new_coverage(self, new_coverage: List) -> bool:
        """Detects whether the passed `new_coverage` is really not in `self.coverages_seen`.

        Args:
            new_coverage (List): Coverage to be checked for newness.

        Returns:
            bool: True, if the coverage contains new coverage-information that should be stored.
        """
        for identifier in new_coverage:
            if identifier not in self.coverages_seen:
                return True
        return False

    def __str__(self) -> str:
        return "fuzzers.MutationCoverageFuzzer"


class GrammarFuzzer(Fuzzer):
    def __init__(self, grammar: Dict[str, List[str]], start_symbol: str = START_SYMBOL, max_nonterminals: int = 10, max_expansion_trials: int = 100, log: bool = False) -> None:
        """Initializes the `GrammarFuzzer`.

        Args:
            grammar (Dict[str, List[str]]): Grammar to be used for grammar construction. (nonterminal -> list of nonterminals and terminals).
            start_symbol (str, optional): Nonterminal to be used as the start symbol. Defaults to START_SYMBOL.
            max_nonterminals (int, optional): Maximum number of nonterminals. Defaults to 10.
            max_expansion_trials (int, optional): Maximum number of expansion trials. Defaults to 100.
            log (bool, optional): Should debug information should be printed to the console? Defaults to False.
        """
        super().__init__()
        self.log = log
        self.grammar = grammar
        self.start_symbol = start_symbol
        self.max_nonterminals = max_nonterminals
        self.max_expansion_trials = max_expansion_trials

    def fuzz(self) -> str:
        """Create testdata to be passed to the testobject.

        Returns:
            str: Testdata to be passed to the testobject.
        """
        term = self.start_symbol
        expansion_trials = 0

        while len(nonterminals(term)) > 0:
            symbol_to_expand = random.choice(nonterminals(term))
            expansions = self.grammar[symbol_to_expand]
            expansion = random.choice(expansions)
            new_term = term.replace(symbol_to_expand, expansion, 1)

            if len(nonterminals(new_term)) < self.max_nonterminals:
                term = new_term
                if self.log:
                    print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
                expansion_trials = 0
            else:
                expansion_trials += 1
                if expansion_trials >= self.max_expansion_trials:
                    return self.fuzz()  # Try again from start
        return term

    def __str__(self) -> str:
        return "fuzzers.GrammarFuzzer"


class GuidedGrammarFuzzer(GrammarFuzzer):
    def __init__(self, grammar: Dict[str, List[str]], exploration_rate: float = 0.1, start_symbol: str = START_SYMBOL, max_nonterminals: int = 10, max_expansion_trials: int = 100, log: bool = False) -> None:
        """Initializes the `GuidedGrammarFuzzer`.

        Args:
            grammar (Dict[str, List[str]]): Grammar to be used for grammar construction. (nonterminal -> list of nonterminals and terminals).
            exploration_rate (float, optional): Probability of choosing the exploration mode for a trial. Defaults to 0.1 (10%).
            start_symbol (str, optional): Nonterminal to be used as the start symbol. Defaults to START_SYMBOL.
            max_nonterminals (int, optional): Maximum number of nonterminals. Defaults to 10.
            max_expansion_trials (int, optional): Maximum number of expansion trials. Defaults to 100.
            log (bool, optional): Should debug information should be printed to the console? Defaults to False.
        """
        super().__init__(grammar, start_symbol=start_symbol, max_nonterminals=max_nonterminals,
                         max_expansion_trials=max_expansion_trials, log=log)
        self.exploration_rate = exploration_rate
        self.grammar_crashes: Dict[str, int] = defaultdict(lambda: 0)
        self.used_production_rules_last_fuzz: List[str] = []

    def fuzz(self) -> str:
        """Create new testdata to be passed to the testobject.

        Returns:
            str: Testdata to be passed to the testobject.
        """
        expansion_trials = 0
        term = self.start_symbol
        self.used_production_rules_last_fuzz = []
        is_exploration_mode = random.random() < self.exploration_rate

        while len(nonterminals(term)) > 0:
            symbol_to_expand = random.choice(nonterminals(term))
            expansions = self.grammar[symbol_to_expand]
            if is_exploration_mode:
                # Exploration
                expansion = random.choice(expansions)
            else:
                # Exploitation
                max_exp = None
                max_crashes = 0
                for exp in expansions:
                    rule = f"{symbol_to_expand}->{exp}"
                    if self.grammar_crashes[rule] > max_crashes:
                        max_exp = exp
                        max_crashes = self.grammar_crashes[rule]
                expansion = max_exp if max_exp != None else random.choice(
                    expansions)

            self.used_production_rules_last_fuzz.append(
                f"{symbol_to_expand}->{expansion}")
            new_term = term.replace(symbol_to_expand, expansion, 1)

            if len(nonterminals(new_term)) < self.max_nonterminals:
                term = new_term
                if self.log:
                    print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
                expansion_trials = 0
            else:
                expansion_trials += 1
                if expansion_trials >= self.max_expansion_trials:
                    return self.fuzz()  # Try again from start
        return term

    def run(self, runner: Runner) -> Tuple[str, TestOutcome]:
        """Run the testobject with the `runner` Runner and create a suitable testdata for it.

        Args:
            runner (Runner): Runner to be used for executing the testobject.

        Returns:
            Tuple[str, TestOutcome]: Used testinput (input, result).
        """
        inp, outcome = super().run(runner)
        if outcome == TestOutcome.FAIL:
            for rule in self.used_production_rules_last_fuzz:
                self.grammar_crashes[rule] += 1
        return (inp, outcome)

    def __str__(self) -> str:
        return "fuzzers.GrammarCoverageFuzzer"


class CountingGreyboxFuzzer(MutationCoverageFuzzer):
    def reset(self) -> None:
        """ Resets the `population`, `seed_index`, `coverages_seen`, `unique_coverages` and the `path_frequency` of the schedule. """
        super().reset()
        self.schedule.path_frequency = {}
        self.unique_coverages: Dict[str, Set] = {}

    def run(self, runner: Runner) -> Tuple[str, TestOutcome]:
        """Run the testobject with the `runner` Runner and create a suitable testdata for it.

        Args:
            runner (Runner): Runner to be used for executing the testobject.

        Returns:
            Tuple[str, TestOutcome]: Used testinput (input, result).
        """
        inp, outcome = runner.run(self.fuzz())
        if outcome == TestOutcome.PASS:  # only here we have coverage data
            # coverage = set of lines (line-coverage) or set of branches (branch-coverage)
            coverage = set([x[0] for x in runner.coverage()[
                           runner.coverage_type] if x[1] > 0])
            path_id = getPathID(coverage)
            if not path_id in self.unique_coverages:  # new coverage
                self.unique_coverages[path_id] = coverage
                seed = Seed(inp)
                seed.coverage = self.unique_coverages[path_id]
                self.population.append(seed)
                for identifier in coverage:
                    self.coverages_seen.add(identifier)

            if not path_id in self.schedule.path_frequency:
                self.schedule.path_frequency[path_id] = 1
            else:
                self.schedule.path_frequency[path_id] += 1

        return (inp, outcome)

    def __str__(self) -> str:
        return f"fuzzers.CountingGreyboxFuzzer ({str(self.schedule)})"
