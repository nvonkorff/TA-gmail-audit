import argparse
import datetime
import gdata.apps.audit.service
import httplib2
import json
import logging as log
import oauth2client
import os
import os.path
import random
import requests
import socket
import socks
import splunk.appserver.mrsparkle.lib.util as util
import sys
import threading
import time
from gmail_Utilities import KennyLoggins, Utilities
from gmail_Utilities import Utilities
from apiclient import errors
from apiclient.discovery import build
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta, datetime
from httplib2 import Http
from oauth2client import file, client, tools
from oauth2client.file import Storage
from requests.exceptions import *
from splunk.appserver.mrsparkle.lib.util import isCloud
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

# SYSTEM EXIT CODES
_SYS_EXIT_FAILED_VALIDATION = 7
_SYS_EXIT_FAILED_GET_OAUTH_CREDENTIALS = 6
_SYS_EXIT_FAILURE_FIND_API = 5
_SYS_EXIT_OAUTH_FAILURE = 4
_SYS_EXIT_FAILED_CONFIG = 3

_APP_NAME = 'TA-gmail-audit'

# Necessary
_CRED = None
_DOMAIN = None

_SPLUNK_HOME = os.getenv("SPLUNK_HOME")
if _SPLUNK_HOME is None:
    _SPLUNK_HOME = make_splunkhome_path([""])

_APP_HOME = os.path.join(util.get_apps_dir(), _APP_NAME)
_app_local_directory = os.path.join(_APP_HOME, "local")
_BIN_PATH = os.path.join(_APP_HOME, "bin")

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user',
          'https://apps-apis.google.com/a/feeds/compliance/audit/']

kl = KennyLoggins()
# log = kl.get_logger(_APP_NAME, "modularinput", log.INFO)
log = kl.get_logger(_APP_NAME, "modularinput", log.DEBUG)

log.debug("logging setup complete")

def send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime):
   """Sends an event to the HTTP Event collector of a Splunk Instance"""

   splunk_session = requests.Session()
   try:


      hostname = socket.gethostname()
      post_data = {
         "host": hostname
      }

      post_data["time"] = eventtime
      post_data["sourcetype"] = sourcetype
      post_data["event"] = payload

      # Create request URL
      request_url = "https://%s:8088/services/collector" % splunk_host

      # Encode data in JSON utf-8 format
      post_data = json.dumps(post_data).encode('utf-8')

      # Encode data in JSON utf-8 format
      # data = json.dumps(post_data)
      # data_payload = str(json.dumps(payload)) + "\n" + str(data)

      # Create auth header
      auth_header = "Splunk %s" % auth_token
      headers = {'Authorization' : auth_header}

      splunk_session.headers.update(headers)

      # print json.dumps(post_data, indent=4, sort_keys=True)

      response = splunk_session.post(request_url, data=post_data, verify=False)

      try:
         response_json = json.loads(response.content)

         if "text" in response_json:
            if response_json["text"] == "Success":
               post_success = True
            else:
               post_success = False
      except:
         post_success = False

      if post_success == True:
         # Event was recieved successfully
         pass
         #print ("Event was recieved successfully")
      else:
         # Event returned an error
         print ("Error sending request.")
         print(response_json)

   except Exception as err:
      # Network or connection error
      post_success = False
      print ("Error sending request")
      print (str(err))

   return post_success

def log_to_hec(log_msg):
    # print("Got: " + log_msg)
    eventtime = time.time()
    sourcetype = "gmail:disable:audit:ta:output"
    payload = { "log": log_msg }
    send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime)

def get_audit_config_user(audit_user_name, AuditUser_domain, access_token):

    data = []
    count = 0
    total = 0
    start = 0
    next_page = True

    url = "https://apps-apis.google.com/a/feeds/compliance/audit/mail/monitor/{}/{}".format(AuditUser_domain, audit_user_name)

    headers = {"Authorization": "Bearer {}".format(access_token)}
    # log_to_hec("url={}".format(url))
    # log_to_hec("headers={}".format(headers))
    try:
        r = requests.get(url, headers=headers)
    except requests.exceptions.RequestException:
       log_to_hec('HTTP Request failed')
       return

    # json_response = json.loads(r.text)

    # for entry in json_response["data"]:
        # log_to_hec("Entry={}".format(entry))
        # data.append(entry)

    data = r.text

    return data

def unset_audit_config_user(AuditUser_domain, audit_user_name, destUserName, access_token):

    data = []
    count = 0
    total = 0
    start = 0
    next_page = True

    url = "https://apps-apis.google.com/a/feeds/compliance/audit/mail/monitor/{}/{}/{}".format(AuditUser_domain, audit_user_name, destUserName)

    headers = {"Authorization": "Bearer {}".format(access_token) }

    # log_to_hec("url={}".format(url))
    # log_to_hec("headers={}".format(headers))
    # log_to_hec("xml={}".format(xml))
    try:
        r = requests.delete(url, headers=headers)
    except requests.exceptions.RequestException:
       log_to_hec('HTTP Request failed')
       return

    # json_response = json.loads(r.text)

    # for entry in json_response["data"]:
        # log_to_hec("Entry={}".format(entry))
        # data.append(entry)

    data = r.text

    return data


def disable_audit(AuditUser, AuditUser_domain, AuditRecipient, AuditRecipient_domain, gd_client, access_token, expires_in):

    log_to_hec("AuditUser_domain = " + AuditUser_domain)
    log_to_hec("AuditRecipient_domain = " + AuditRecipient_domain)

    if AuditUser_domain != AuditRecipient_domain:
        log_to_hec(AuditUser_domain + " is a different domain to audit recipient domain: " + AuditRecipient_domain + " - switching gd_client settings")
        gd_client = gdata.apps.audit.service.AuditService(domain=AuditUser.split('@')[1])
        gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)

    audit_user_name = AuditUser.split('@')[0]
    audit_recipient_name = AuditRecipient.split('@')[0]

    try:
        # monitors = get_audit_config_user(audit_user_name, AuditUser_domain, access_token)
        monitors = gd_client.getEmailMonitors(user=audit_user_name)
    except Exception as err:
        log_to_hec("Error: Could not list monitors for {} - Error={}".format(AuditUser, err))
        return

    log_to_hec("User={} Monitors={}".format(AuditUser, monitors))

    destUserName = monitors[0][b'destUserName'].decode('utf-8')
    
    log_to_hec("destUserName={}".format(destUserName))
    if monitors:
        try:
            monitors = unset_audit_config_user(AuditUser_domain, audit_user_name, destUserName, access_token)

        # except Exception as e:
        #     exc_type, exc_obj, exc_tb = sys.exc_info()
        #     fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        #     log_to_hec("exc_type={} exc_obj={} lineno={}".format(exc_type, fname, exc_tb.tb_lineno))
        except Exception as err:
            log_to_hec("Error: Could not delete monitors for User={} destUserName={} - Error={}".format(AuditUser, destUserName, err))

    log_to_hec("User={} Monitors={}".format(AuditUser, monitors))
    return

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # hec_token = definition.parameters.get('hec_token', None)
    pass

def collect_events(helper, ew):
    domain = helper.get_arg('domain')
    opt_hec_token = helper.get_arg('hec_token')
    opt_hostname = helper.get_arg('hostname')
    opt_audit_recipient = helper.get_arg('audit_recipient')

    global splunk_host
    splunk_host = opt_hostname

    global auth_token
    auth_token = opt_hec_token

    session_key = helper.context_meta['session_key']

    run(session_key, domain, opt_hostname, opt_hec_token, opt_audit_recipient)
    return

def refresh_auth_token(domain, app_name, session_key):

    utils = Utilities(app_name=app_name, session_key=session_key)

    log.info("action=getting_credentials domain={}".format(domain))
    goacd = utils.get_creds_splunk_client(app_name, domain)
    log.info("action=getting_credentials domain={} goacd_type={}".format(domain, type(goacd)))
    google_oauth_credentials = json.loads(goacd)

    assert type(google_oauth_credentials) is dict
    if goacd is None:
        log.error("operation=load_credentials error_message={}".format("No Credentials Found in Store"))
        sys.exit(_SYS_EXIT_FAILED_GET_OAUTH_CREDENTIALS)

    proxy_config_file = os.path.join(_app_local_directory, "proxy.conf")
    proxy_info = None
    h = None

    utils = Utilities(app_name=_APP_NAME, session_key=session_key)
    if os.path.isfile(proxy_config_file):
        try:
            pc = utils.get_proxy_configuration("gapps_proxy")
            sptype = socks.PROXY_TYPE_HTTP
            proxy_info = httplib2.ProxyInfo(sptype, pc["host"], int(pc["port"]),
                                            proxy_user=pc["authentication"]["username"],
                                            proxy_pass=pc["authentication"]["password"])
        except Exception as e:
            log.warn("action=load_proxy status=failed message=No_Proxy_Information stanza=gapps_proxy")

    if proxy_info is not None:
        log.info("proxy_info={0}".format(proxy_info.__dict__))

    # Build HTTP session using OAuth creds
    http = httplib2.Http(proxy_info=proxy_info)
    credentials = oauth2client.client.OAuth2Credentials.from_json(json.dumps(google_oauth_credentials))

    http_session = credentials.authorize(http)

    service = build('admin', 'directory_v1', http=http_session, cache_discovery=False)

    token_info = credentials.get_access_token(http_session)

    access_token = token_info.access_token
    expires_in = token_info.expires_in

    return access_token, expires_in, service

def run(session_key, domain, splunk_host, auth_token, audit_recipient):

    AuditRecipient = audit_recipient
    AuditRecipient_domain = AuditRecipient.split('@')[1]

    domain = AuditRecipient_domain

    access_token, expires_in, service = refresh_auth_token(domain, _APP_NAME, session_key)

    script = sys.argv[0]
    log_to_hec("Starting: {}".format(script))

    max_threads = 10

    log_to_hec("Auth token expires in {} seconds".format(expires_in))

    gd_client = gdata.apps.audit.service.AuditService(domain=AuditRecipient.split('@')[1])
    gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)
    # auth_headers = {u'Authorization': u'Bearer %s' % access_token}
    # gd_client.additional_headers = auth_headers

    # Call the Admin SDK Directory API
    log_to_hec('Getting the users in the domain')

    request = service.users().list(customer='my_customer', orderBy='email')

    users = []
    while request is not None:
       results = request.execute()
       users.append(results.get('users', []))
       request = service.users().list_next(request, results)

    full_user_list = []
    for userlist in users:
        for user in userlist:
            full_user_list.append(user)

    if not full_user_list:
        log_to_hec('No users in the domain.')
    else:
        
        if len(full_user_list) >= 500:
        # Randomly delete half the elmenents from the list. API do not seem to be able to be increased, so each run will process a random subset of the full list ensuring that over time, all users will have auditing disabled
            no_elements_to_delete = len(full_user_list) // 2    ## Thanos the list
            no_elements_to_keep = len(full_user_list) - no_elements_to_delete
            ulist = random.sample(full_user_list, no_elements_to_keep)
        else:
            ulist = full_user_list
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for user in ulist:

                if expires_in <= 60:

                   log_to_hec("Refreshing auth token")
                   access_token, expires_in, service = refresh_auth_token(domain, _APP_NAME, session_key)
                   log_to_hec("Auth token expires in {} seconds".format(expires_in))

                   gd_client = gdata.apps.audit.service.AuditService(domain=AuditRecipient.split('@')[1])
                   gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)
                   # auth_headers = {u'Authorization': u'Bearer %s' % access_token}
                   # gd_client.additional_headers = auth_headers

                if user['primaryEmail'] == AuditRecipient:
                    continue

                if user['isMailboxSetup'] == False:
                    log_to_hec("Mailbox is not configured. Cannot disable auditing on: {}".format(user['primaryEmail']))
                    continue

                AuditUser = user['primaryEmail']
                log_to_hec("User: {} {}".format(user['primaryEmail'], user['name']['fullName']))

                AuditUser_domain = AuditUser.split('@')[1]

                futures = executor.submit(disable_audit, AuditUser, AuditUser_domain, AuditRecipient, AuditRecipient_domain, gd_client, access_token, expires_in)

    script = sys.argv[0]
    log_to_hec("Finished: {}".format(script))

    return
