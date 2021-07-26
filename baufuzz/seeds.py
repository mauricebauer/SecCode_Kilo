# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 20.06.2021
# Adaption of: https://www.fuzzingbook.org/html/GreyboxFuzzer.html

from typing import Optional


class Seed:
    def __init__(self, data: str, energy: Optional[float] = None) -> None:
        """Initialize the `Seed`.

        Args:
            data (str): Data of the seed (input data).
            energy (Optional[float], optional): Energy assigned from a `Schedule`. Defaults to None.
        """
        self.data = data
        self.energy = energy

    def __str__(self) -> str:
        """Returns a `str` represenstation of this `Seed`.

        Returns:
            str: Representation.
        """
        return self.data

    __repr__ = __str__
