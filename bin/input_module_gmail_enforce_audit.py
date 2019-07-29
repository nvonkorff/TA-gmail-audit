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
from Utilities import KennyLoggins, Utilities
from Utilities import Utilities
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
      post_data = json.dumps(post_data).encode('utf8')

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
    sourcetype = "gmail:enforce:audit:ta:output"
    payload = { "log": log_msg }
    send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime)

def enable_audit(AuditUser, AuditUser_domain, AuditRecipient, AuditRecipient_domain, gd_client, access_token):

    log_to_hec("AuditUser_domain = " + AuditUser_domain)
    log_to_hec("AuditRecipient_domain = " + AuditRecipient_domain)

    if AuditUser_domain != AuditRecipient_domain:
        log_to_hec(AuditUser_domain + " is a different domain to audit recipient domain: " + AuditRecipient_domain + " - switching gd_client settings")
        gd_client = gdata.apps.audit.service.AuditService(domain=AuditUser.split('@')[1])
        gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)

    for n in range(0, 5):
        try:
            monitors = gd_client.getEmailMonitors( AuditUser.split('@')[0] )
        except Exception as err:
            if err[0]['status'] == 400:
                log_to_hec(str(datetime.now()) + " - Error: Could not list monitors for " + AuditUser + " - " + str(err))
                return
            if err[0]['status'] == 503:
                log_to_hec(str(datetime.now()) + " - Error: Could not list monitors for " + AuditUser + " - " + str(err))
                return
            else:
                log_to_hec(str(datetime.now()) + " - Error: Could not list monitors for " + AuditUser + " - " + str(err))
                log_to_hec(str(datetime.now()) + " - Retry list monitoring attempt: " + str(n) + " for "  + AuditUser)
                time.sleep((2 ** n))


    if not monitors or monitors['outgoingEmailMonitorLevel'] == 'HEADER_ONLY':
        try:
            monitors = gd_client.createEmailMonitor( AuditUser.split('@')[0],
                                                     AuditRecipient.split('@')[0],
                                                     end_date='2118-11-21 00:00',
                                                     incoming_headers_only=False,
                                                     outgoing_headers_only=False,
                                                     drafts=False,
                                                     chats=False)

        except Exception as err:
            if err[0]['status'] == 400:
                log_to_hec(str(datetime.now()) + " - Error: Could not list monitors for " + AuditUser + " - " + str(err))
                return
            if err[0]['status'] == 503:
                log_to_hec(str(datetime.now()) + " - Error: Could not list monitors for " + AuditUser + " - " + str(err))
                return
            else:
                log_to_hec(str(datetime.now()) + " - Error: Could not enable monitoring for " + AuditUser + " - " + str(err))
                log_to_hec(str(datetime.now()) + " - Retry enable monitoring attempt: " + str(n) + " for "  + AuditUser + " - " + str(err))
                time.sleep((2 ** n))

    log_to_hec(str(datetime.now()) + " - User:" + AuditUser + " Monitors: " + str(monitors))
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
    goacd = utils.get_credential(app_name, domain)
    log.info("action=getting_credentials domain={} goacd_type={}".format(domain, type(goacd)))
    google_oauth_credentials = json.loads(goacd)

    assert type(google_oauth_credentials) is dict
    if goacd is None:
        log.error("operation=load_credentials error_message={}".format("No Credentials Found in Store"))
        sys.exit(_SYS_EXIT_FAILED_GET_OAUTH_CREDENTIALS)

    # Build HTTP session using OAuth creds
    http = httplib2.Http(proxy_info=None)
    credentials = oauth2client.client.OAuth2Credentials.from_json(json.dumps(google_oauth_credentials))

    http_session = credentials.authorize(http)

    service = build('admin', 'directory_v1', http=http_session)

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
    log_to_hec(str(datetime.now()) + " - Starting: " + script)

    max_threads = 10

    log_to_hec("Auth token expires within: " + str(expires_in) + " seconds.")

    gd_client = gdata.apps.audit.service.AuditService(domain=AuditRecipient.split('@')[1])
    gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)

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
        # Randomly delete half the elmenents from the list. API do not seem to be able to be increased, so each run will process a random subset of the full list ensuring that over time, all users will have auditing enabled
            no_elements_to_delete = len(full_user_list) // 2    ## Thanos the list
            no_elements_to_keep = len(full_user_list) - no_elements_to_delete
            ulist = random.sample(full_user_list, no_elements_to_keep)
        else:
            ulist = full_user_list
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for user in ulist:

                # if user['primaryEmail'] != "ashlee.connolly@qantasloyalty.com":
                #    continue

                if expires_in <= 60:
                   print("Refreshing auth token")
                   access_token, expires_in, service = refresh_auth_token()
                   print("Auth token expires within: " + str(expires_in) + " seconds.")

                   gd_client = gdata.apps.audit.service.AuditService(domain=AuditRecipient.split('@')[1])
                   gd_client.additional_headers[u'Authorization'] = u'Bearer {0}'.format(access_token)

                if user['primaryEmail'] == AuditRecipient:
                    continue

                if user['isMailboxSetup'] == False:
                    print("Mailbox is not configured. Cannot enable auditing on: " + user['primaryEmail'])
                    continue

                AuditUser = user['primaryEmail']
                print(str(datetime.now()) + " - User:" + user['primaryEmail'] + " " + user['name']['fullName'])

                AuditUser_domain = AuditUser.split('@')[1]

                futures = executor.submit(enable_audit, AuditUser, AuditUser_domain, AuditRecipient, AuditRecipient_domain, gd_client, access_token)

    script = sys.argv[0]
    log_to_hec(str(datetime.now()) + " - Finished: " + script)

    return
