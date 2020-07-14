from flask import Flask, render_template
import requests
import urllib3
import json
import datetime
import nessusconfig
from flask_caching import Cache
from datetime import datetime

config = {
    "CACHE_TYPE": "simple",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 3600
}
app = Flask(__name__)
app.config.from_mapping(config)
cache = Cache(app)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Prevent errors when connecting without valid SSL cert

headers = {"X-ApiKeys": f"accessKey={ nessusconfig.tenableaccessKey }; secretKey={ nessusconfig.tenablesecretKey }"}
hostnames = {}


@app.route('/api/scans/summary')
@cache.cached(timeout=300) 
def getscansummary():
    scans = []
    scansummary=[]
    nessusdata = requests.get(
        f"https://cloud.tenable.com/scans?folder_id={ nessusconfig.tenablefolderid }", headers=headers).json()
    for scan in nessusdata["scans"]:
        rawscandata = requests.get(
            f"https://cloud.tenable.com/scans/{ scan['id'] }", headers=headers).json()
        try:
            scandata={}
            scandata["name"]=rawscandata["info"]["name"]
            scandata["hosts"]=len(rawscandata["hosts"])
            scandata["network"]=rawscandata["info"]["targets"]
            scandate=datetime.fromtimestamp(rawscandata["info"]["timestamp"])
            scandata["lastScan"]=str(scandate)
            scansummary.append(scandata)
        except KeyError as e:
            print("Scan not yet run" + str(e))
    return json.dumps(scansummary)


@app.route('/api/vulns/summary')
@cache.cached(timeout=300) 
def getvulnsummary():
    scans = []
    hosts = []
    allvulns = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    nessusdata = requests.get(
        f"https://cloud.tenable.com/scans?folder_id={ nessusconfig.tenablefolderid }", headers=headers).json()
    for scan in nessusdata["scans"]:
        scandata = requests.get(
            f"https://cloud.tenable.com/scans/{ scan['id'] }", headers=headers).json()
        try:
            for vuln in scandata["vulnerabilities"]:
                allvulns[vuln["severity"]] += 1
        except:
            print("Scan not yet run")
    return json.dumps(allvulns)


@app.route('/api/hosts/detail')
@cache.cached(timeout=3600)
def gethostdetails():
    scans = []
    hosts = []
    nessusdata = requests.get(
        f"https://cloud.tenable.com/scans?folder_id={ nessusconfig.tenablefolderid }", headers=headers).json()
    for scan in nessusdata["scans"]:
        scandata = requests.get(
            f"https://cloud.tenable.com/scans/{ scan['id'] }", headers=headers).json()
        try:
            for host in scandata["hosts"]:
                hosts.append(host)
        except:
            print("Scan not yet run")
    return json.dumps(hosts)


def gethostname(hostid):
    return hostnames[hostid]


@app.route('/api/vulns/detail')
@cache.cached(timeout=7200) # 2 hour cache in memory due to high number of HTTP requests triggered by this lookup
def getvulndetails():
    scans = []
    hosts = []
    vulns = {}
 #  print("Start: " + str(datetime.datetime.now().time()))
    nessusdata = requests.get(
        f"https://cloud.tenable.com/scans?folder_id={ nessusconfig.tenablefolderid }", headers=headers).json()
    for scan in nessusdata["scans"]:
        scandata = requests.get(
            f"https://cloud.tenable.com/scans/{ scan['id'] }", headers=headers).json()
        try:
            for host in scandata["hosts"]: # For each host in that scan get host details
                hostname = host["hostname"]
                vulns[hostname] = []
                hostdata = requests.get(f"https://cloud.tenable.com/scans/{ scan['id'] }/hosts/{ host['host_id'] }", headers=headers).json()
                for vuln in hostdata["vulnerabilities"]: # For each vuln on the host get vuln details
                    vulns[hostname].append(vuln)
        except KeyError:
            print("Scan not yet run")
    #print("End: " + str(datetime.datetime.now().time()))
    return json.dumps(vulns)


@app.route('/')
def showdashboard():
    html="<h1>Node4 Nessus API</h1> Contact Security Team for Information"
    return html
