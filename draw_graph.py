from baufuzz.analyzers import get_call_graph
import matplotlib.pyplot as plt
import networkx as nx

graph = get_call_graph("./kilo_direct_quit.c")
nx.draw(graph, with_labels=True, node_color="grey", node_size=100, arrowsize=12)
plt.show()
