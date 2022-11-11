#!/usr/bin/env python3
"""Produce a Sankey-like graph from Insight `topn` data using Graphviz dot

This program reads the environment variables `INSIGHT_PI` and `API_TOKEN`, then
contacts the Insight PI and runs a query against the `topn` endpoint to get
data that can be used to build the relationship between Source IP address,
Source Port, Destination Port, and Destination IP address with traffic flow
rates represented on each link.

The two non-standard Python packages required are:
  - requests; http://docs.python-requests.org/
  - networkx: https://networkx.github.io/

And you will need the `dot` package from Graphviz (http://graphviz.org/) to
convert the output of this script into a graphical representation of the
traffic """

import requests
import json
import sys
import os

try:
    import pydot
except ImportError:
    exit('cannot import pydot, install with "pip install pydot"')

try:
    import networkx as nx
    from networkx.drawing.nx_pydot import write_dot
except ImportError:
    exit('cannot import networkx, install with "pip install networkx"')

from datetime import datetime, timedelta


if __name__ == "__main__":
    #
    # set the SP leader hostname and API key
    #
    if "SP_LEADER" in os.environ:
        SP_LEADER = os.environ["SP_LEADER"]
    else:
        exit('no environment variable "SP_LEADER" found')

    if "SP_API_KEY" in os.environ:
        API_KEY = os.environ["SP_API_KEY"]
    else:
        exit('no environment variable "SP_API_KEY" found')

    relationships_lr = [
        "Source_IPv4_Address",
        "Source_Port",
        "Destination_Port",
        "Destination_IPv4_Address",
    ]
    labels_lr = ["Src IP", "Src Port", "Dst Port", "Dst IP"]

    date_format = "%Y-%m-%dT%H:%M:%S+00:00"
    end = datetime.now()
    start = end - timedelta(hours=3)
    END_DATE = end.strftime(date_format)
    START_DATE = start.strftime(date_format)
    # Set the query for our example; the limit is intentionally small, but can
    # be made larger
    query = {
        "limit": 25,
        "groupby": relationships_lr,
        "filters": {
            "type": "or",
            "fields": [
                {"type": "selector", "facet": "Destination_Port", "value": "80"},
                {"type": "selector", "facet": "Destination_Port", "value": "25"},
                {"type": "selector", "facet": "Destination_Port", "value": "53"},
                {"type": "selector", "facet": "Destination_Port", "value": "443"},
            ],
        },
        "start": START_DATE,
        "end": END_DATE,
        "view": "Network",
        "metric": "bps",
        "calculation": "average",
    }

    # create the URL for our Insight UI device
    url = "https://{}/api/sp/insight/topn".format(SP_LEADER)

    # POST the query and get the results
    r = requests.post(
        url,
        headers={"X-Arbux-APIToken": API_KEY, "Content-Type": "application/json"},
        json=query,
        verify="./certfile",
    )

    # make sure we got results, otherwise print what the error to the screen
    if r.status_code != requests.codes.ok:
        print(json.dumps(r.json()))
        sys.exit(1)

    # Convert the results to json
    rj = r.json()

    # Set up a directed graph using networkx
    G = nx.DiGraph()

    # Go through the results JSON and look at each key in it that is also in
    # the `relationships_lr` list, creating a FROM and a TO node, label them
    # with their type (from the `labels` list), create the edge between them
    # with either a new weight (traffic rate) or add to the existing weight
    # (traffic rate)
    node_shape = "box"
    for rel in rj["data"]:
        for edge_num in range(len(relationships_lr) - 1):
            from_ = (
                relationships_lr[edge_num] + "_" + str(rel[relationships_lr[edge_num]])
            )
            to = (
                relationships_lr[edge_num + 1]
                + "_"
                + str(rel[relationships_lr[edge_num + 1]])
            )
            G.add_node(
                from_,
                label="{}\n{}".format(
                    labels_lr[edge_num], rel[relationships_lr[edge_num]]
                ),
                shape=node_shape,
            )
            G.add_node(
                to,
                label="{}\n{}".format(
                    labels_lr[edge_num + 1], rel[relationships_lr[edge_num + 1]]
                ),
                shape=node_shape,
            )
            if G.has_edge(from_, to):
                G[from_][to]["weight"] += rel["bps"]["average"]["total"]
            else:
                G.add_edge(from_, to, weight=rel["bps"]["average"]["total"])

    # compute the line widths based on the edge weights and the thickest
    # allowed line
    max_weight = max([G[e[0]][e[1]]["weight"] for e in G.edges])
    max_edge_width = 8
    for e in G.edges:
        G[e[0]][e[1]]["penwidth"] = max(
            1, int(((G[e[0]][e[1]]["weight"] / max_weight) * max_edge_width) + 0.5)
        )
        G[e[0]][e[1]]["label"] = "{}bps".format(G[e[0]][e[1]]["weight"])
    # Set the graph to go left to right
    G.graph["graph"] = {"rankdir": "LR"}
    # write out the graphviz/dot file to `thing.dot`
    write_dot(G, "./traffic-flow.dot")

    # print some information to the screen
    print("Insight PI: {}".format(SP_LEADER))
    print("There are {} things in the response".format(len(rj["data"])))
    print("Start Time: {}".format(query["start"]))
    print("  End Time: {}".format(query["end"]))
