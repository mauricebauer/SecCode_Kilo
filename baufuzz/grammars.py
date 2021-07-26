# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 18.06.2021
# Adaption of: https://www.fuzzingbook.org/html/Grammars.html

import re
from typing import List

SIMPLE_C_GRAMMAR = {
    "<start>": ["<includes><newline><main><newline>"],
    "<includes>": ["#include \"a.h\"<newline>", "<includes><includes>"],
    "<main>": ["int main() {<newline><statements><indents>return 0;<newline>}"],
    "<statements>": ["<indents><function-call><newline>", "<indents><comment><newline>",
                     "<indents><function-call><indents><comment><newline>",
                     "<indents><branch><newline>", "<statements><statements>"],
    "<branch>": ["if (x) {<newline><statements>}",
                 "if (x) {<newline><statements>} else {<newline><statements>}",
                 "while (y) {<newline><statements>}",
                 "do {<newline><statements>} while (z);"],
    "<function-call>": ["a();", "b(1);", "c(\"Hi\");"],
    "<comment>": ["/* a */", "// a", "// a();"],
    "<newline>": ["\r\n", "\n\r", "\n"],
    "<indents>": [" ", "  ", "    ", "\t", "<indents><indents>"]
}


START_SYMBOL = "<start>"
RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')


def nonterminals(expansion: List[str]) -> List[str]:
    """Gets the nonterminals (indicated by <>) from all expansions.

    Args:
        expansion (List[str]): List of possible expansions from the grammar.

    Returns:
        List[str]: All nonterminal expansions from the `expansion` list.
    """
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return re.findall(RE_NONTERMINAL, expansion)


def is_nonterminal(s: str) -> bool:
    """Detects whether the passed string `s` is a nonterminal.

    Args:
        s (str): String to check.

    Returns:
        bool: True, if `s` is a nonterminal.
    """
    return re.match(RE_NONTERMINAL, s)
