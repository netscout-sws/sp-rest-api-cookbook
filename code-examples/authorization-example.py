#!/usr/bin/env python3
"""Demonstrate different results depending on the user

The user of the API is identified by the token that is used, so with SP
configured with two different tokens for two different users may return
different data.  This example produces a simple report of alert types and
related managed objects for two diferent user, demonstrating the different
results for each user"""

import os
import sys
import requests


def get_some_alerts(leader, token, cert):
    """Get some alerts

    For the purposes of this demonstration, we will just get one page
    of alerts and return them as json"""

    url = "https://{}/api/sp/alerts/?perPage=15".format(leader)

    r = requests.get(
        url,
        headers={"X-Arbux-APIToken": token, "Content-Type": "application/vnd.json+api"},
        verify=cert,
    )

    if r.status_code is not requests.codes.ok:
        print(
            "API request for alerts returned {} ({})".format(r.reason, r.status_code),
            file=sys.stderr,
        )
        return None

    return r.json()


def alert_report(alerts):
    """Print a summary of alerts

    The summary has IDs and types, and (if available) the misuse types
    """

    print_nl = False
    for alert in alerts["data"]:
        print("{}".format(alert["id"]), end="")
        if "alert_type" in alert["attributes"]:
            print("\t{}".format(alert["attributes"]["alert_type"]), end="")
        else:
            print_nl = True
        if (
            "subobject" in alert["attributes"]
            and "misuse_types" in alert["attributes"]["subobject"]
        ):
            print(
                "\t{}".format(
                    ", ".join(alert["attributes"]["subobject"]["misuse_types"])
                )
            )
        else:
            print_nl = True

        if print_nl:
            print("")

    return None


if __name__ == "__main__":
    #
    # set the SP leader hostname and API key
    #
    if "SP_LEADER" in os.environ:
        SP_LEADER = os.environ["SP_LEADER"]
    else:
        exit('no environment variable "SP_LEADER" found')

    # this is assumed to be an admin token
    if "SP_API_KEY" in os.environ:
        API_KEY = os.environ["SP_API_KEY"]
    else:
        exit('no environment variable "SP_API_KEY" found')

    # this is assumed to be an admin token
    if "MSSP_TOKEN" in os.environ:
        MSSP_TOKEN = os.environ["MSSP_TOKEN"]
    else:
        exit('no environment variable "MSSP_TOKEN" found')
    MSSP_TOKEN = os.getenv("MSSP_TOKEN")
    CERT_FILE = "./certfile"
    for token in (API_KEY, MSSP_TOKEN):
        print("Getting alerts for the {} account".format(token))
        alerts = get_some_alerts(SP_LEADER, token, CERT_FILE)
        if alerts is not None:
            alert_report(alerts)
