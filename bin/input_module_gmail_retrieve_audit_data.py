import argparse
import base64
import datetime
import dateutil.parser
import email
import httplib2
import json
import logging as log
import oauth2client
import os
import os.path
import random
import re
import requests
import socket
import socks
import splunk.appserver.mrsparkle.lib.util as util
import string
import sys
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from gmail_Utilities import KennyLoggins, Utilities
from gmail_Utilities import Utilities
from apiclient import discovery
from apiclient import errors
from apiclient.discovery import build
from apiclient.http import BatchHttpRequest
from collections import OrderedDict
from datetime import timedelta, datetime
from email.parser import HeaderParser
from email.parser import Parser
from httplib2 import Http
from oauth2client import file, client, tools
from oauth2client.file import Storage
from requests.exceptions import *
from splunk.appserver.mrsparkle.lib.util import isCloud
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from random import randrange


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

SCOPES = 'https://www.googleapis.com/auth/gmail.modify' # we are using modify and not readonly, as we will be marking the messages Read


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
    eventtime = time.time()
    sourcetype = "gmail:audit:ta:output"
    payload = { "log": log_msg }
    send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime)

def isBase64(sb):
        try:
                if type(sb) == str:
                        # If there's any unicode here, an exception will be thrown and the function will return false
                        sb_bytes = bytes(sb, 'ascii')
                elif type(sb) == bytes:
                        sb_bytes = sb
                else:
                        raise ValueError("Argument must be string or bytes")
                return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
                return False


def GetMessageBody(message):
    try:
            msg_str = str(base64.urlsafe_b64decode(message["raw"]), 'utf-8')
            mime_msg = email.message_from_string(msg_str)
            messageMainType = mime_msg.get_content_maintype()
            if messageMainType == 'multipart':
                for part in mime_msg.get_payload():
                        if part.get_content_maintype() == 'text':
                                return str(base64.urlsafe_b64decode(part.get_payload()), 'utf-8')
                return ""
            elif messageMainType == 'text':
                if isBase64(mime_msg.get_payload()):
                    return str(base64.urlsafe_b64decode(mime_msg.get_payload()), 'utf-8')
                else:
                    return mime_msg.get_payload()
    except errors.HttpError as error:
            log_to_hec('An error occurred: %s' % error)


def mark_as_read_batch(message_ids, user_id, GMAIL, http_session):

    result = None
    n = 0
    while result is None:
        try:
            body = {'ids': message_ids, 'removeLabelIds': ['UNREAD']}
            GMAIL.users().messages().batchModify(userId=user_id, body=body).execute(http=http_session)
            n = 0
            result = "Success"
            # log_to_hec("Marked message as read:" + user_id + " message_id=" + m_id)
        except Exception as err:
            time.sleep((2 ** n))
            log_to_hec("Error: Could not mark_as_read_batch for user=" + user_id + " - " + str(err) + ". Retrying after " + str(2 ** n) + " seconds.")
            n += 1

def mark_as_read(m_id, user_id, GMAIL, http_session):

    result = None
    n = 0
    while result is None:
        try:
            GMAIL.users().messages().modify(userId=user_id, id=m_id,body={ 'removeLabelIds': ['UNREAD']}).execute(http=http_session)
            n = 0
            result = "Success"
            log_to_hec("Marked message as read:" + user_id + " message_id=" + m_id)
        except Exception as err:
            time.sleep((2 ** n))
            log_to_hec("Error: Could not mark_as_read for user=" + user_id + " message_id=" + m_id + " - " + str(err) + ". Retrying after " + str(2 ** n) + " seconds.")
            n += 1
    return


def process_message(m_id, user_id, GMAIL, splunk_host, auth_token, local_domains, include_body, domain, _APP_NAME, session_key):
 
    log_to_hec("Processing message_id={}".format(m_id)) 

    # Random sleep time to reduce api rate limiting
    sec = randrange(2) 
    ms = randrange(100) 
    sleep_time="{}.{}".format(sec, ms)
    log_to_hec("Sleeping for {} seconds".format(sleep_time)) 
    time.sleep(float(sleep_time))

    body_data = dict()

    http_session = auth_http(domain, _APP_NAME, session_key)

    try:
        message = json.dumps(GMAIL.users().messages().get(userId=user_id, id=m_id, format='raw').execute(http=http_session))
    except Exception as err:
        log_to_hec("Error: Could not get message_id={} - {}".format(m_id, err))
        return

    message = json.loads(message)

    if 'error' in message:
        log_to_hec("Error encountered for request_id: " + str(request_id))
        for key, value in message.iteritems() :
            log_to_hec("key=" + str(key) + " value=" + str(value))
        return

    if 'raw' in message:
        b = GetMessageBody(message)
        b = email.message_from_string(b)
    else:
        log_to_hec("'raw' not found in message for request_id: " + str(request_id))
        for key, value in message.iteritems() :
            log_to_hec("key=" + str(key) + " value=" + str(value))
        return

    body = ""

    if b.is_multipart():
        for part in b.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # skip any text/plain (txt) attachments
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body = part.get_payload(decode=True)  # decode
                break
    # not multipart - i.e. plain text, no attachments, keeping fingers crossed
    else:
        body = b.get_payload(decode=True)
    body = body.decode("utf-8").split('\n')
    cleaned_body = ''
    for line in body:
        should_add_line = True
        if line == '\r':
            should_add_line = False
        if len(line) > 0:
            if line[0] == '>':
                should_add_line = False
        if len(line) > 8:
           if line[-7:] == 'wrote:\r':
                should_add_line = False
        if should_add_line:
            cleaned_body += line + '\n'


    body_data[m_id] = cleaned_body


    try:
        message = json.dumps(GMAIL.users().messages().get(userId=user_id, id=m_id).execute(http=http_session))
    except Exception as err:
        log_to_hec("Error: Could not get message_id={} - {}".format(m_id, err))
        return


    message = json.loads(message)

    m_id = message['id']

    payld = message['payload'] # get payload of the message

    if 'data' in message['payload']['body'] :
        file_data = base64.urlsafe_b64decode(message['payload']['body']['data'].encode('ASCII'))

    for part in message['payload'].get('parts', ''):
        if part['filename']:
            if 'data' in part['body']:
                data=part['body']['data']
            else:
                att_id=part['body']['attachmentId']
                att=GMAIL.users().messages().attachments().get(userId=user_id, messageId=m_id,id=att_id).execute(http=http_session)
                data=att['data']
            file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))

    parser = HeaderParser()
    msg = email.message_from_string(str(file_data, 'utf-8'))


    payload = {}
    attachments = {}

    partno = 0

    for part in msg.walk():
        partkey = "part" + str(partno)
        content_disposition = str(part.get('Content-Disposition'))
        
        if "filename" in content_disposition:

            #extract filename and attachment base64 data
            filename = part.get_filename()
            attbase64 = part.get_payload()

            #base64 decode the attachment
            base64decode = base64.b64decode(attbase64)

            #create hashes for the attachment
            attmd5 = hashlib.md5(base64decode).hexdigest()
            attsha1 = hashlib.sha1(base64decode).hexdigest()
            attsha256 = hashlib.sha256(base64decode).hexdigest()

            #update attachments dict with filename and hash info
            attachments.update({filename + '-md5' : attmd5})
            attachments.update({filename + '-sha1' : attsha1})
            attachments.update({filename + '-sha256' : attsha256})

            #create payload info for Splunk ingest
            payload['attachments'] = attachments

        for key, value in part.items():
            if partno == 0:
                payload.update({key : value})
            else:
                if partkey in payload:
                    payload[partkey].update({key : value})
                else:
                    payload[partkey] = ({key : value})
        partno += 1

    to_addr = payload.get("To","undisclosed-recipients")
    cc_addr = payload.get("CC","")
    to_addr = ('{0} {1}'.format(to_addr, cc_addr))
    from_addr = payload.get("From","")

    if m_id in body_data:

        # Extract any links from original email body
        body_payload = body_data[m_id]

        links = re.findall(r'(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-;]*[\w@?^=%&\/~+#-])?', body_payload)
        email_links = []

        for link in links:
           link_url = link[0] + "://" + link[1] + link[2]
           if not link_url in email_links:
             email_links.append(link_url)

        if email_links:
             payload["links"] = email_links

    # Determine direction of message based on domains in from/to addresses
    from_domain = []
    to_domains = []
    to_domain = []


    try:
        to_domains = re.findall('@(([A-Za-z0-9|-]+\.)*[A-Za-z0-9|-]+\.[A-Za-z]+)', to_addr)
    except AttributeError:
        log_to_hec('Error: "to" address domain regex failed: {0}'.format(to_addr))
        return
    for domain in to_domains:
       to_domain.append(domain[0])

    try:
        from_domain = re.search('@(([A-Za-z0-9|-]+\.)*[A-Za-z0-9|-]+\.[A-Za-z]+)', from_addr).group(1)
    except AttributeError:
        log_to_hec('Error: "from" address domain regex failed: {0}'.format(from_addr))
        return


    local_domains_string = '|'.join(map(lambda x: x.decode('utf-8'), local_domains))
    regex = '^(?!({0})).*'.format(local_domains_string)

    map(lambda x: x.decode('utf-8'), local_domains)

    # log_to_hec('to_domains: {0} from_domain: {1} to_addr: {2} local_domains: {3}'.format(to_domain, from_domain, to_addr, local_domains))

    r = re.compile(regex, re.IGNORECASE)
    external_domains = list(filter(r.match, to_domain))

    if from_domain.encode('utf-8') in local_domains and len(external_domains) == 0:
        message_info = "internal"
    elif from_domain.encode('utf-8') not in local_domains:
        message_info = "inbound"
    elif from_domain.encode('utf-8') in local_domains and len(external_domains) > 0:
        message_info = "outbound"

    payload["external_domains"] = external_domains
    payload["message_info"] = message_info

    include_body = int(include_body)

    if include_body == 1:
        log_to_hec("Including body for {}".format(m_id))
        payload["body"] = body_payload

    if 'Date' in msg:
        msg_date = msg['Date']
        # Strip off an anything from first bracket. This is causing the dateparser to fail on certain patterns e.g.: Tue, 11 Dec 2018 22:55:36 +0000 (GMT+00:00)
        head, sep, tail = msg_date.partition('(')
        msg_date = head
    else:
        msg_date = datetime.now()


    try:
        get_date_obj = dateutil.parser.parse(str(msg_date))
        eventtime = int(time.mktime(get_date_obj.timetuple()))
    except Exception as e:
        log_to_hec('Error: "msg_date" is invalid: {0}'.format(msg_date))
        msg_date = datetime.now()

    # eventtime = time.time()
    sourcetype = "gmail:audit:headers"

    send_to_splunk(splunk_host, auth_token, payload, sourcetype, eventtime)

    # Mark the messages as read
    mark_as_read(m_id, user_id, GMAIL, http_session)

    log_to_hec("Processed message_id={}".format(m_id)) 

    return

def process_batch(message_ids, user_id, GMAIL, splunk_host, auth_token, local_domains, include_body, batch_size, domain, _APP_NAME, session_key):

    max_threads = int(batch_size)
    log_to_hec("max_threads={}".format(batch_size))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for m_id in message_ids:
            futures = executor.submit(process_message, m_id, user_id, GMAIL, splunk_host, auth_token, local_domains, include_body, domain, _APP_NAME, session_key)

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
    opt_batch_size = helper.get_arg('batch_size')
    opt_local_domains = helper.get_arg('local_domains')
    opt_include_body = helper.get_arg('include_body')

    local_domains = [x.strip() for x in opt_local_domains.split(',')]

    local_domains = [x.encode('UTF8') for x in local_domains]

    global splunk_host
    splunk_host = opt_hostname

    global auth_token
    auth_token = opt_hec_token

    session_key = helper.context_meta['session_key']

    run(session_key, domain, opt_hostname, opt_hec_token, opt_batch_size, local_domains, opt_include_body)
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

    service = build('gmail', 'v1', http=http_session, cache_discovery=False)


    token_info = credentials.get_access_token(http_session)

    access_token = token_info.access_token
    expires_in = token_info.expires_in

    return access_token, expires_in, service

def auth_http(domain, app_name, session_key):

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

    return http_session

def run(session_key, domain, splunk_host, auth_token, batch_size, local_domains, include_body):

    script = sys.argv[0]
    log_to_hec("Starting: " + script)

    access_token, expires_in, GMAIL = refresh_auth_token(domain, _APP_NAME, session_key)

    user_id =  'me'

    result = None
    n = 0

    while result is None:
        try:
            unread_msgs = GMAIL.users().messages().list(userId='me',q='from:compliance-noreply@google.com is:unread',maxResults=batch_size).execute()
            n = 0
            result = "Success"
        except Exception as err:
            time.sleep((2 ** n))
            log_to_hec("Error: Could not get unread_msgs: " + " - " + str(err) + ". Retrying after " + str(2 ** n) + " seconds.")
            n += 1

    label_info = GMAIL.users().labels().get(userId='me', id='UNREAD').execute()
    log_to_hec(label_info['id'] + '=' + str(label_info['messagesUnread']))
    log_to_hec("UNREAD={}".format(len(unread_msgs)))

    if 'messagesUnread' in unread_msgs:
        total_unread_count = unread_msgs['messagesUnread']

    messages = []

    processed_message_count = 0

    if 'messages' in unread_msgs:
        messages.extend(unread_msgs['messages'])

        message_ids = []

        msg_list = messages
        for msg in msg_list:
            m_id = msg['id'] # get id of individual message
            message_ids.append(m_id)
        process_batch(message_ids, user_id, GMAIL, splunk_host, auth_token, local_domains, include_body, batch_size, domain, _APP_NAME, session_key)
        processed_message_count += len(msg_list)

        log_msg = ("Processed=" + str(processed_message_count))
        log_to_hec(log_msg)
        label_info = GMAIL.users().labels().get(userId='me', id='UNREAD').execute()
        log_to_hec(label_info['id'] + '=' + str(label_info['messagesUnread']))
    else:
       log_to_hec("No unread messages in inbox. Exiting.")
       log_to_hec("Finished: " + script)
       exit()

    while 'nextPageToken' in unread_msgs:
        messages = []
        page_token = unread_msgs['nextPageToken']

        result = None
        n = 0

        while result is None:
            try:
                unread_msgs = GMAIL.users().messages().list(userId='me',q='from:compliance-noreply@google.com is:unread',maxResults=batch_size,pageToken=page_token).execute()
                n = 0
                result = "Success"
            except Exception as err:
                time.sleep((2 ** n))
                log_to_hec("Error: Could not get unread_msgs: " + " - " + str(err) + ". Retrying after " + str(2 ** n) + " seconds.")
                n += 1

        messages.extend(unread_msgs['messages'])
        message_ids = []

        msg_list = messages
        for msg in msg_list:
            m_id = msg['id'] # get id of individual message
            message_ids.append(m_id)

        process_batch(message_ids, user_id, GMAIL, splunk_host, auth_token, local_domains, include_body, batch_size)

        processed_message_count += len(msg_list)

        log_msg = ("Processed=" + str(processed_message_count))
        log_to_hec(log_msg)
        label_info = GMAIL.users().labels().get(userId='me', id='UNREAD').execute()
        log_to_hec(label_info['id'] + '=' + str(label_info['messagesUnread']))

    label_info = GMAIL.users().labels().get(userId='me', id='UNREAD').execute()
    log_to_hec(label_info['id'] + '=' + str(label_info['messagesUnread']))
    log_to_hec("Total messages processed: " +  str(processed_message_count))
    log_to_hec("Finished: " + script)
