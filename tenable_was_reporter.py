import json
import requests
import time
import smtplib
from datetime import datetime
from os.path import basename
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

credential = DefaultAzureCredential()
client = SecretClient(
   vault_url=%AZURE_URL%,
   credential=credential
)
TENABLE_ACCESS_KEY = client.get_secret("tenableAccessAPIKey")
TENABLE_SECRET_KEY = client.get_secret("tenableSecretAPIKey")
SPLUNK_URI = https://splunkhec.%DOMAIN%.com:8088/services/collector
SPLUNK_TOKEN = client.get_secret("splunkAPIKey")
print(f"Tenable secret value is retrieved") #{TENABLE_KEYS.value}
print(f"Splunk secret value is retrieved") #{SPLUNK_KEY.value}


HEADERS = {

   "Accept": "application/json",
   "Content-Type": "application/pdf",
   "X-ApiKeys": "accessKey=" + TENABLE_ACCESS_KEY.value + ";secretKey=" + TENABLE_SECRET_KEY.value

}

def get_vuln_scans():
   #depricated function, do not use
   url = https://cloud.tenable.com/was/v2/scans/scan_id


   #response = requests.request("GET", url, headers=headers)
   # Get all the scans and filter web app scans to gather their UUIDs
   #print(response.text)

   print("Requesting Scans")
   scansURL  = https://cloud.tenable.com/scans

   response  = requests.request("GET", scansURL, headers=HEADERS)

   scansDict = json.loads(response.text)


   #print scansDict

   #for scan in scansDict:
       #print(scan)

   #print scansDict.get("folders")
   #print "                 "
   #print scansDict.get("scans")[0]

   webAppScanUUIDs = []

   for scan in scansDict['scans']:
       #print(scan)
       print(scan.get("name"))
       if scan.get("uuid"):
           print("    " + scan.get("uuid"))
       if scan.get('type') == "webapp" and scan.get('status') == "completed" and scan.get('enabled') == True:
           print(scan)
           print("GOT ONE")

           webAppScanUUIDs.append(scan['uuid'])

def filter_WAS_scan(scan):
   if scan.get("last_scan"):
       status = scan.get("last_scan").get("status")
       if status != "aborted":
           time = scan.get("last_scan").get("finalized_at")[:10]
           scan_date = datetime.strptime(time, '%Y-%m-%d').date()
           now = datetime.now().date()
           if (now-scan_date).days < 7:
               return True
   return False

def get_completed_WAS_scans_past_week():
   print("getting WEB APP SCANS")
   searchURL = https://cloud.tenable.com/was/v2/configs/search?limit=200
   print(HEADERS)
   response  = requests.request("POST", searchURL, headers=HEADERS)
   print(response.text)
   webscans = json.loads(response.text)
   print(len(webscans.get("items")))
   #print(json.dumps(webscans, indent=4, sort_keys=True))
   print("Listing out recent scans (within the week)")
   completed_scans = []
   for scan in webscans.get('items'):
       #print(json.dumps(scan, indent=4, sort_keys=True))
       #TODO: add date check to ensure run in past week
       #TODO, need to track scan name
       if filter_WAS_scan(scan):
           print(scan.get("target"))
           scan_id = scan.get("last_scan").get("scan_id")
           print(scan_id)
           completed_scans.append(scan_id)
           #print(json.dumps(scan, indent=4, sort_keys=True))

   return completed_scans

def get_exported_pdf_report(uuid):
   try:
       print("requesting generation of report for scan: " + uuid)
       url = https://cloud.tenable.com/was/v2/scans/ + uuid + "/report"
       response = requests.request("PUT", url, headers=HEADERS)
       print(response)
       print(type(response))
   except:
       print("ERROR requesting report for scan uuid: " + uuid)
   time.sleep(100)
   try:
       print("requesting report for scan: " + uuid)
       url = https://cloud.tenable.com/was/v2/scans/ + uuid + "/report"
       response = requests.request("GET", url, headers=HEADERS)
       print(response.text)
   except:
       print("ERROR downloading report for scan uuid: " + uuid)


def send_mail(send_from, send_to, subject, text, files=None, username="", password="", server="", port="587", use_tls=True):
   assert isinstance(send_to, list)

   msg = MIMEMultipart()
   msg['From'] = send_from
   msg['To'] = COMMASPACE.join(send_to)
   msg['Date'] = formatdate(localtime=True)
   msg['Subject'] = subject

   msg.attach(MIMEText(text))

   for f in files or []:
       # After the file is closed
       #TODO need to add an actual filename
       part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
       msg.attach(part)

   smtp = smtplib.SMTP(server, port)
   if use_tls:
       print("starting tls")
       smtp.starttls()
   print("authenticating")
   print("logging in with: " + username + " " + password)
   smtp.login(username, password)
   smtp.sendmail(send_from, send_to, msg.as_string())
   smtp.close()

def get_WAS_vulnerabilities_by_asset():
   #Not used right now
   print("getting WAS vulnerabilities")
   searchURL = https://cloud.tenable.com/was/v2/vulnerabilities/by-assets/search?limit=10&offset=0&sort=last_seen:desc

   response  = requests.request("POST", searchURL, headers=HEADERS)
   print(response)
   was_vulns = json.loads(response.text)
   print(len(was_vulns.get("items")))
   print(json.dumps(was_vulns, indent=4, sort_keys=True))

def get_WAS_scan_details(uuid):
   searchURL = https://cloud.tenable.com/was/v2/scans/ + uuid
   response  = requests.request("GET", searchURL, headers=HEADERS)
   scan = json.loads(response.text)
   print(json.dumps(scan, indent=4, sort_keys=True))

def get_WAS_scan_target(uuid):
   searchURL = https://cloud.tenable.com/was/v2/scans/ + uuid
   response  = requests.request("GET", searchURL, headers=HEADERS)
   scan = json.loads(response.text)
   return scan.get("target")

def get_WAS_scan_vulnerabilities(uuid):
   print("getting WAS scan_details")
   searchURL = https://cloud.tenable.com/was/v2/scans/+uuid+"/vulnerabilities/by-plugins/search?limit=200&offset=0"

   response  = requests.request("POST", searchURL, headers=HEADERS)
   print(response)
   was_vulns = json.loads(response.text)
   was_vulns = was_vulns.get("items")
   print(len(was_vulns))
   print(json.dumps(was_vulns, indent=4, sort_keys=True))
   target = get_WAS_scan_target(uuid)
   no_info = []
   for vuln in was_vulns:
       if vuln.get("severity") != "info":
           vuln["target"] = target
           no_info.append(vuln)
   return no_info

def send_info_to_splunk(scan):
   #service = client.connect(host='’,port=8088,username='admin',password='somepass')
   authHeader = {'Authorization': 'Splunk {}'.format(SPLUNK_TOKEN.value)}

   for vuln in scan:
       jsonDict = {"event": vuln }
       r = requests.post(SPLUNK_URI, headers=authHeader, json=jsonDict, verify=False)
       print(r.text)
       print("DATA SENT")


def load_vulns_to_splunk_functions(scans):
   for scan in scans:
       target = get_WAS_scan_target(scan) #pass the uuid
       vulns = get_WAS_scan_vulnerabilities(scan)
       print(json.dumps(vulns, indent=4, sort_keys=True))
       send_info_to_splunk(vulns)



def send_weekly_WAS_reports(scans):
   #completed_scans = [""]
   print(completed_scans)
   for scan in completed_scans:
       get_exported_pdf_report(scan)
   send_mail(from@gmail.com,[to@me.com], "subject", "body", username=from@gmail.com, password="", server="smtp.gmail.com")


def main():
   print("Getting past week scans")
   past_week_scans = get_completed_WAS_scans_past_week()
   #send_weekly_WAS_reports(past_week_scans)
   load_vulns_to_splunk_functions(past_week_scans)
   return


if __name__ == "__main__":
   main()
