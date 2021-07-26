# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 15.06.2021
# Adaption of: https://www.fuzzingbook.org/html/GreyboxFuzzer.html

import random


class Mutator:
    def __init__(self, random_char_start: int = 1, random_char_end: int = 127) -> None:
        """Initialize the `Mutator`.

        Args:
            random_char_start (int, optional): ASCII start number of a randomly created char. Defaults to 1.
            random_char_end (int, optional): ASCII end number of a randomly created char. Defaults to 127.
        """
        self.random_char_start = random_char_start
        self.random_char_end = random_char_end

        self.mutators = [
            self.delete_random_character,
            self.insert_random_character,
            self.flip_random_character
        ]

    def insert_random_character(self, inp: str) -> str:
        """Returns `inp` with a random character inserted.

        Args:
            inp (str): Original input to be changed.

        Returns:
            str: `ìnp` with a random character inserted.
        """
        pos = random.randint(0, len(inp))
        random_char = chr(random.randrange(
            self.random_char_start, self.random_char_end))
        return inp[:pos] + random_char + inp[pos:]

    def delete_random_character(self, inp: str) -> str:
        """Returns `inp` with a random character deleted.

        Args:
            inp (str): Original input to be changed.

        Returns:
            str: `inp` with a random character removed.
        """
        if inp == "":
            return self.insert_random_character(inp)

        pos = random.randint(0, len(inp) - 1)
        return inp[:pos] + inp[pos + 1:]

    def flip_random_character(self, inp: str) -> str:
        """Returns `inp` with a random bit flipped in a random position.

        Args:
            inp (str): Original input to be changed.

        Returns:
            str: `inp` with a random character bit-flipped.
        """
        if inp == "":
            return self.insert_random_character(inp)

        pos = random.randint(0, len(inp) - 1)
        char = inp[pos]
        bit = 1 << random.randint(0, 6)
        new_char = chr(ord(char) ^ bit)
        return inp[:pos] + new_char + inp[pos + 1:]

    def mutate(self, inp: str) -> str:
        """Return `inp` with a random mutation applied.

        Args:
            inp (str): Original input to be changed.

        Returns:
            str: `inp` with a random mutation applied.
        """
        mutator = random.choice(self.mutators)
        return mutator(inp)
