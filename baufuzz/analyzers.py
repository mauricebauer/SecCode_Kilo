# Assignment Secure Coding (Kilo)
# Author: Maurice Bauer
# Date: 24.06.2021

import re
import subprocess
from typing import Dict
import matplotlib.pyplot as plt
import networkx as nx
from networkx.classes.digraph import DiGraph
from .runners import TestOutcome
from .logs import FuzzingLog
from .coverages import CoverageType


def line_coverage_over_time(log: FuzzingLog, show_plot: bool = True) -> Dict[float, int]:
    """Creates data and a line diagram showing the line coverage over the test period.

    Args:
        log (FuzzingLog): Log containing all coverages.
        show_plot (bool, optional): Should the created plot be opened in a new window? Defaults to True.

    Returns:
        Dict[float, int]: Line coverage (value) over time (key)
    """
    n_lines_time: Dict[float, int] = log.coverage_progress[CoverageType.LINE]
    if show_plot:
        plt.title("Line coverage over time")
        plt.xlabel("Execution time in min")
        plt.ylabel("# lines covered")
        plt.plot(n_lines_time.keys(), n_lines_time.values())
        plt.show()
    return n_lines_time


def branch_coverage_over_time(log: FuzzingLog, show_plot: bool = True) -> Dict[float, int]:
    """Creates the branch coverage data and a line diagram showing the coverage over the test period.

    Args:
        log (FuzzingLog): Log containing all coverages.
        show_plot (bool, optional): Should the created plot be opened in a new window? Defaults to True.

    Returns:
        Dict[float, int]: Branch coverage (value) over time (key)
    """
    n_branches_per_time: Dict[float,
                              int] = log.coverage_progress[CoverageType.BRANCH]
    if show_plot:
        plt.title("Branch coverage over time")
        plt.xlabel("Execution time in min")
        plt.ylabel("# branches covered")
        plt.plot(n_branches_per_time.keys(), n_branches_per_time.values())
        plt.show()
    return n_branches_per_time


def crashes_over_time(log: FuzzingLog, show_plot: bool = True) -> Dict[float, int]:
    """Creates data of crashes over time with a line diagram showing the progress.

    Args:
        log (FuzzingLog): Log containing all `TestOutcome`s.
        show_plot (bool, optional): Should the created plot be opened in a new window? Defaults to True.

    Returns:
        Dict[float, int]: Crashes (value) over time (key)
    """
    n_crashes = 0
    n_crashes_per_time: Dict[float, int] = {}
    for entry in log.entries:
        time_in_min = (entry.timestamp -
                       log.start_timestamp).total_seconds() / 60
        if entry.outcome == TestOutcome.FAIL:
            n_crashes += 1
        n_crashes_per_time[time_in_min] = n_crashes
    if show_plot:
        plt.title("Crashes over time")
        plt.xlabel("Execution time in min")
        plt.ylabel("# crashes")
        plt.plot(n_crashes_per_time.keys(), n_crashes_per_time.values())
        plt.show()
    return n_crashes_per_time


def _get_cflow_data(source_file_path: str) -> str:
    """Run the cflow command line application for the file at `source_file_path`.

    Args:
        source_file_path (str): File to be analyzed using cflow.

    Returns:
        str: Analysis result from cflows stdout.
    """
    process = subprocess.run(["cflow", source_file_path],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             universal_newlines=True)
    return process.stdout


def _get_nx_graph_from_cflow_data(cflow_data: str) -> DiGraph:
    """Create a `DiGraph` directed callgraph using the data from cflows stdout.

    Args:
        cflow_data (str): Analysis result from cflows stdout.

    Returns:
        DiGraph: Directed callgraph which can be used to calculate function distances.
    """
    graph = nx.DiGraph()
    # stack-Dict: key = indentation-level, value = function name
    stack: Dict[int, str] = dict()
    lines = cflow_data.replace("\r", "").split("\n")
    for line in lines:
        # 1st regex group: whitespaces for indentation, 2nd regex group: function name
        search = re.search(r"^( *)(\w+)\(\)", line)
        if line == "" or search == None:
            continue
        # 4 spaces per indentation level
        indent_level = len(search.group(1)) // 4
        function_name = search.group(2)
        stack[indent_level] = function_name
        if not function_name in graph:
            graph.add_node(function_name)
        if indent_level != 0:
            parent_function = stack[indent_level-1]
            if not graph.has_edge(parent_function, function_name):
                graph.add_edge(parent_function, function_name)
    # nx.draw(graph, with_labels=True)
    # plt.show()
    return graph


def get_call_graph(source_file_path: str) -> DiGraph:
    """Create a `DiGraph` directed callgraph using the file at `source_file_path`.

    Args:
        source_file_path (str): Path to the source file to be analyzed.

    Returns:
        DiGraph: Directed callgraph which can be used to calculate function distances.
    """
    cflow_data = _get_cflow_data(source_file_path)
    nx_graph = _get_nx_graph_from_cflow_data(cflow_data)
    return nx_graph
