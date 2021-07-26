# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 24.06.2021
# Adaption of: https://www.fuzzingbook.org/html/GreyboxFuzzer.html

import re
import random
from typing import Dict, List, Set
import numpy as np
import networkx as nx
from networkx.exception import NetworkXNoPath
from networkx.classes.digraph import DiGraph
from .seeds import Seed
from .coverages import getPathID


class Schedule:
    """ Abstract class for extension to other schedules. """

    def choose(self, population: List[Seed]) -> Seed:
        """Choose a seed from `population`.

        Args:
            population (List[Seed]): Population to choose from.

        Returns:
            Seed: Chosen seed.
        """
        return None


class RandomSchedule(Schedule):
    """ Simples schedule: choose a seed from the population randomly. """

    def choose(self, population: List[Seed]) -> Seed:
        """Choose a seed from `population` randomly.

        Args:
            population (List[Seed]): Population to choose from.

        Returns:
            Seed: Randomly chosen seed.
        """
        return random.choice(population)


class PowerSchedule(Schedule):
    def __init__(self) -> None:
        """ Initializes the abstract `PowerSchedule`. """
        self.path_frequency: Dict = {}

    def assignEnergy(self, population: List[Seed]) -> None:
        """Assigns each seed the same energy = 1.

        Args:
            population (List[Seed]): Seeds for which the energy gets set.
        """
        for seed in population:
            seed.energy = 1

    def normalizedEnergy(self, population: List[Seed]) -> List[float]:
        """Normalize the energy of the `population`.

        Args:
            population (List[Seed]): Seeds which energy should be calculated normalized.

        Returns:
            List[float]: Normalized energies.
        """
        energies = list(map(lambda seed: seed.energy, population))
        total_energy = sum(energies)
        norm_energy = list(map(lambda energy: energy/total_energy, energies))
        return norm_energy

    def choose(self, population: List[Seed]) -> Seed:
        """Choose a seed weighted by normalized energy.

        Args:
            population (List[Seed]): Population from which a Seed should be chosen.

        Returns:
            Seed: Chosen seed.
        """
        self.assignEnergy(population)
        norm_energy = self.normalizedEnergy(population)
        seed = np.random.choice(population, p=norm_energy)
        return seed

    def __str__(self) -> str:
        return "schedules.PowerSchedule"


class AFLFastSchedule(PowerSchedule):
    def __init__(self, exponent: float) -> None:
        """Initializes the `AFLFastSchedule` used for Boosted Greybox Fuzzing.

        Args:
            exponent (float): Exponent to be used in calculation for the seeds `energy`.
        """
        self.exponent = exponent

    def assignEnergy(self, population: List[Seed]) -> None:
        """Assign exponential energy inversely proportional to path frequency.

        Args:
            population (List[Seed]): Seeds to be used for calculation.
        """
        for seed in population:
            seed.energy = 1 / (self.path_frequency[getPathID(
                seed.coverage)] ** self.exponent)

    def __str__(self) -> str:
        return "schedules.AFLFastSchedule"


class DirectedSchedule(PowerSchedule):
    def __init__(self, exponent: float, graph: DiGraph, target_fn: str, source_code_path: str) -> None:
        """Initializes the `DirectedSchedule` used for Directed Greybox Fuzzing.

        Args:
            exponent (float): Exponent to be used in calculation for the seeds `energy`.
            graph (DiGraph): Graph to be used to calculate the mean function distances.
            target_fn (str): Name of the target function which should be reached in the course of the fuzzing test.
            source_code_path (str): Path to the source file used to analyze the function names.
        """
        self.exponent = exponent
        self.graph = graph
        self.target_fn = target_fn
        self.functions: Dict[int, str] = {}
        self._read_functions(source_code_path)

    def _read_functions(self, source_code_path: str) -> None:
        """Parses the function names out of the `source_code_path`-file and matches them to line-numbers.

        Args:
            source_code_path (str): Path to the source code file.
        """
        lines: List[str] = []
        with open(source_code_path, "r") as source:
            lines = source.readlines()
        last_function = ""
        for i in range(len(lines)):  # 0 based
            # detects function declarations
            search = re.search(r"^\w+ (\w+)\(.*\) *{", lines[i])
            if lines[i].strip() != "" and search != None:
                last_function = search.group(1)
            self.functions[i+1] = last_function  # 1 based

    def _get_functions(self, coverage: Set[int]) -> Set[str]:
        """Get a set of function names from a given `coverage`.

        Args:
            coverage (Set[int]): Coverage recorded during testobject execution. Must be `CoverageType.LINE`!

        Returns:
            Set[str]: Set of function names.
        """
        functions = set()
        for line in coverage:
            functions.add(self.functions[line])
        return functions

    def assignEnergy(self, population: List[Seed]) -> None:
        """ Assigns each seed energy inversely proportional to the average function-level distance to target.

        Args:
            population (List[Seed]): Population which should be modified during the energy-calculation.
        """
        for seed in population:
            if not hasattr(seed, 'distance'):
                num_dist = 0
                sum_dist = 0
                for f in self._get_functions(seed.coverage):
                    try:
                        sum_dist += nx.shortest_path_length(
                            self.graph, f, self.target_fn)
                        num_dist += 1
                    except NetworkXNoPath:
                        pass
                seed.distance = sum_dist / num_dist
                seed.energy = (1 / seed.distance) ** self.exponent

    def __str__(self) -> str:
        return "schedules.DirectedSchedule"
