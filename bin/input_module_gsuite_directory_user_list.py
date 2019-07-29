import httplib2
import json
import logging as log
import oauth2client
import os.path
import requests
import socket
import socks
import splunk.appserver.mrsparkle.lib.util as util
import sys
import time
from Utilities import KennyLoggins, Utilities
from Utilities import Utilities
from apiclient import errors
from apiclient.discovery import build
from datetime import timedelta, datetime
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

SCOPES = 'https://www.googleapis.com/auth/admin.directory.user'

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
    sourcetype = "gsuite:directory:user:list:ta:output"
    payload = { "log": log_msg }
    send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime)

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # hec_token = definition.parameters.get('hec_token', None)
    pass

def collect_events(helper, ew):
    domain = helper.get_arg('domain')
    opt_hec_token = helper.get_arg('hec_token')
    opt_hostname = helper.get_arg('hostname')

    session_key = helper.context_meta['session_key']

    run(session_key, domain, opt_hostname, opt_hec_token)
    return

def run(session_key, domain, splunk_host, auth_token):
    
    utils = Utilities(app_name=_APP_NAME, session_key=session_key)

    log.info("action=getting_credentials domain={}".format(domain))
    goacd = utils.get_credential(_APP_NAME, domain)
    log.info("action=getting_credentials domain={} goacd_type={}".format(domain, type(goacd)))
    google_oauth_credentials = json.loads(goacd)

    assert type(google_oauth_credentials) is dict
    if goacd is None:
        MI._catch_error("operation=load_credentials error_message={} config={}".format("No Credentials Found in Store", MI.get_config("name")))
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
        except Exception, e:
            log.warn("action=load_proxy status=failed message=No_Proxy_Information stanza=gapps_proxy")

    log.info("proxy_info={0}".format(proxy_info.__dict__))

    # Build HTTP session using OAuth creds
    http = httplib2.Http(proxy_info=proxy_info)

    credentials = oauth2client.client.OAuth2Credentials.from_json(json.dumps(google_oauth_credentials))
    http_session = credentials.authorize(http)
    
    service = build('admin', 'directory_v1', http=http_session)
        
    # Call the Admin SDK Directory API
    print('Getting the users in the domain')
    results = service.users().list(customer='my_customer',
                                orderBy='email').execute()
    users = results.get('users', [])

    if not users:
        print('No users in the domain.')
    else:
        print('Users:')
        for user in users:
            print(u'{0} ({1})'.format(user['primaryEmail'], user['name']['fullName']))
            eventtime = time.time()
            sourcetype = "gsuite:directory:user"
            send_to_splunk(splunk_host, auth_token, user, sourcetype, eventtime)                        

    return


