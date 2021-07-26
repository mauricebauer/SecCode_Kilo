# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021

import os
from typing import Dict, List
from .seeds import Seed
from .fuzzers import GrammarFuzzer
from .grammars import START_SYMBOL


class Seeder:
    """ Dummy class to be extended. """

    def seeds(self) -> List[Seed]:
        """Get a list of seeds.

        Returns:
            List[Seed]: List of seeds.
        """
        return []


class StringSeeder(Seeder):
    def __init__(self, strings: List[str]) -> None:
        """Initializes the `StringSeeder`.

        Args:
            strings (List[str]): List of strings to be used as seeds.
        """
        self.strings = strings

    def seeds(self) -> List[Seed]:
        """Get a list of seeds.

        Returns:
            List[Seed]: List of seeds.
        """
        return list(map(lambda s: Seed(s), self.strings))


class FileSeeder(Seeder):
    def __init__(self, path: str) -> None:
        """Initializes the `FileSeeder`.

        Args:
            path (str): Path to a directory containing files to be used as seeds.

        Raises:
            NotADirectoryError: Path does not match a directory. Have you passed a file-path?
        """
        if not os.path.isdir(path):
            raise NotADirectoryError()
        self.path = path

    def seeds(self) -> List[Seed]:
        """Get a list of seeds from the directory.

        Returns:
            List[Seed]: List of seeds.
        """
        seeds: List[Seed] = []
        for root, _, files in os.walk(self.path):
            for file_path in files:
                with open(os.path.join(root, file_path), 'r') as file:
                    seeds.append(Seed(file.read()))
        if len(seeds) == 0:
            raise FileNotFoundError(f"No input seeds in {self.path}")
        return seeds


class GrammarSeeder(Seeder):
    def __init__(self, grammar: Dict[str, List[str]], start_symbol: str = START_SYMBOL, max_nonterminals: int = 10, max_expansion_trials: int = 100, n: int = 10) -> None:
        """Initialize the `GrammarSeeder`.

        Args:
            grammar (Dict[str, List[str]]): Grammar to be used for grammar constructions to create seeds.
            start_symbol (str, optional): Nonterminal which should be used to start the grammar constructions. Defaults to START_SYMBOL.
            max_nonterminals (int, optional): Maximum number of nonterminals. Defaults to 10.
            max_expansion_trials (int, optional): Maximum number of expansion trials. Defaults to 100.
            n (int, optional): Number of seeds to be created using the grammar. Defaults to 10.
        """
        self.n = n
        self.grammar = grammar
        self.start_symbol = start_symbol
        self.max_nonterminals = max_nonterminals
        self.max_expansion_trials = max_expansion_trials

    def seeds(self) -> List[Seed]:
        """Get a list of seeds using the grammar.

        Returns:
            List[Seed]: List of seeds.
        """
        seeds: List[Seed] = []
        fuzzer = GrammarFuzzer(self.grammar,
                               start_symbol=self.start_symbol,
                               max_nonterminals=self.max_nonterminals,
                               max_expansion_trials=self.max_expansion_trials)
        for _ in range(self.n):
            seeds.append(Seed(fuzzer.fuzz()))
        return seeds
