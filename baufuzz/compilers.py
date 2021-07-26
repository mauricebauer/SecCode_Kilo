# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 24.06.2021

import os


class Compiler:
    def compile(self, c_file: str, with_coverage: bool = True, remove_existing_files: bool = True) -> str:
        """Compiles the given `c_file` using gcc and optionally `with_coverage`.

        Args:
            c_file (str): Path to the *.c file which should be compiled.
            with_coverage (bool, optional): True, if gcc coverage flag should bet set. Defaults to True.
            remove_existing_files (bool, optional): True, if existing compilation and coverage files should be removed first. Defaults to True.

        Raises:
            FileNotFoundError: *.c file was not found at the given path `c_file`.

        Returns:
            str: Name of the compiled program to be used for the ProgramRunner.
        """
        program_name = c_file.removesuffix(".c")
        if not os.path.exists(c_file):
            raise FileNotFoundError()

        if remove_existing_files and os.path.exists(program_name):
            os.remove(program_name)
        if remove_existing_files and os.path.exists(program_name + ".gcno"):
            os.remove(program_name + ".gcno")
        if remove_existing_files and os.path.exists(program_name + ".gcda"):
            os.remove(program_name + ".gcda")
        if remove_existing_files and os.path.exists(program_name + ".gcov.json.gz"):
            os.remove(program_name + ".gcov.json.gz")

        command = "gcc "
        if with_coverage:
            command += "-coverage "
        command += c_file
        command += " -o " + program_name
        os.system(command)
        return program_name
