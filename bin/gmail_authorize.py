from __future__ import absolute_import
import sys
import os.path
import os
import splunk.appserver.mrsparkle.lib.util as util
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

_APP_NAME = 'TA-gmail-audit'
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "bin", "lib"]))
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "bin", "lib", "python3.7"]))
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "bin", "lib", "python3.7", "site-packages"]))
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "bin", "lib", "python3.7", "site-packages", "apiclient"]))
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "bin", "lib", "python3.7", "site-packages", "google_auth_oauthlib"]))

import json
import logging
import os
import splunk
import uuid
# Google Stuff
import httplib2
import socks
from gmail_Utilities import Utilities, KennyLoggins
from google_auth_oauthlib.flow import Flow

httplib2.CA_CERTS = "{}/{}".format(os.path.join(util.get_apps_dir(), _APP_NAME, 'bin'), "cacerts.txt")
_LOCALDIR = os.path.join(util.get_apps_dir(), _APP_NAME, 'local')
if not os.path.exists(_LOCALDIR):
    os.makedirs(_LOCALDIR)

kl = KennyLoggins()
logger = kl.get_logger(_APP_NAME, "gmail_authorize_endpoint", logging.INFO)


class gmail_authorize(splunk.rest.BaseRestHandler):
    def _catch_error(self, e):
        myJson = {"log_level": "ERROR"}
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        myJson["errors"] = [{"msg": str(e),
                             "exception_type": "{}".format(type(e)),
                             "exception_arguments": "{}".format(e),
                             "filename": fname,
                             "line": exc_tb.tb_lineno
                             }]
        return myJson

    # /custom/GoogleAppsForSplunk/gmail_authorize/build
    # @expose_page(must_login=True, methods=['GET', 'POST'])
    def handle_GET(self, **kwargsraw):
        try:
            logger.info("operation=build_url")
            kwargs = self.request["query"]
            logger.debug("setting domain")
            gapps_domain = kwargs['domain'].strip().lower()
            logger.debug("setting client id")
            gapps_client_id = kwargs['clientid'].strip()
            logger.debug("setting clientsecret")
            gapps_client_secret = kwargs['clientsecret'].strip()
            logger.debug("setting authtoken")
            gapps_auth_token = kwargs['authtoken'].strip()
            logger.debug("setting step")
            gapps_gui_step = kwargs['step'].strip()
            logger.debug("setting scope")
            # Check https://developers.google.com/admin-sdk/reports/v1/guides/authorizing for all available scopes
            # Temp Removal
            # 'https://www.googleapis.com/auth/gmail.readonly',  # Allows for Gmail reading.
            gapps_oauth_scope = ['https://www.googleapis.com/auth/admin.directory.user',   # List directory users
                                 'https://apps-apis.google.com/a/feeds/compliance/audit/', # Enable email audit
                                 'https://www.googleapis.com/auth/gmail.modify'            # Read/Mark audit messages as read
                                 ]
            # Redirect URI for installed apps
            gapps_redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'  # AUTO?
            gapps_token_uri = "https://www.googleapis.com/oauth2/v4/token"
            # https://developers.google.com/identity/protocols/oauth2/native-app
            # Run through the OAuth flow and retrieve credentials
            code_verifier = kwargs.get("flow_tmp", None) or "{}".format(uuid.uuid4()).lower().replace("-", "")
            logger.debug("setting flow '{}'".format(code_verifier))
            logger.debug("using cacerts: {}".format(httplib2.CA_CERTS))
            flow = Flow.from_client_config(
                {"installed": {
                    "client_id": gapps_client_id,
                    "client_secret": gapps_client_secret,
                    "redirect_uris": [gapps_redirect_uri],
                    "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_uri": gapps_token_uri
                }},
                scopes=gapps_oauth_scope,
                redirect_uri=gapps_redirect_uri)
            flow.code_verifier = code_verifier
            flow_url, state = flow.authorization_url(prompt='select_account')
            if "one" == gapps_gui_step:
                logger.debug("return the flow to the browser {}".format(code_verifier))
                logger.debug("returning to launch url")
                return json.dumps({"step": "launch_url", "url": flow_url,
                                   "flow_tmp": "{}".format(flow.code_verifier),
                                   "msg": "Once you have authorized Splunk, enter the Authorization Token above, and click the authorization button again."})
            logger.debug("action=compare_verifier flow='{}' request='{}'".format(flow.code_verifier, kwargs['flow_tmp'].strip()))
            proxy_config_file = os.path.join(_LOCALDIR, "proxy.conf")
            proxy_info = None
            utils = Utilities(app_name=_APP_NAME, session_key=self.sessionKey)
            logger.debug("action=setting_proxy file={}".format(proxy_config_file))
            if os.path.isfile(proxy_config_file):
                try:
                    pc = utils.get_proxy_configuration("gapps_proxy")
                    scheme = "http"
                    logger.debug("action=setting_proxy pc={} scheme={} host={}, port={} username={}".format(pc, scheme,
                                                                                                      pc["host"],
                                                                                                      pc["port"],
                                                                                                      pc[
                                                                                                          "authentication"][
                                                                                                          "username"]))
                    if pc["useSSL"] == "true":
                        scheme = "https"
                    if pc["authentication"]["username"]:
                       proxy_url="{}://{}:{}@{}:{}/".format(scheme, pc["authentication"]["username"],
                                  pc["authentication"]["password"], pc["host"], pc["port"])
                    else:
                       proxy_url="{}://{}:{}/".format(scheme, pc["host"], pc["port"])
                    proxy_info={"http": proxy_url, "https": proxy_url}
                except Exception as e:
                    logger.warn("action=load_proxy status=failed message=No_Proxy_Information stanza=gapps_proxy error={}".format(e))
            h = flow.fetch_token(code=gapps_auth_token,
                                 code_verifier=flow.code_verifier,
                                 proxies=proxy_info,
                                 include_client_id=True,
                                 client_secret=gapps_client_secret)
            h["client_id"] = gapps_client_id
            h["client_secret"] = gapps_client_secret
            h["token_uri"] = gapps_token_uri
            utils.set_credential(_APP_NAME, gapps_domain, "{}".format(h))
            return json.dumps({"step": "end_of_discussion",
                               "msg": 'Credentials Written to Encrypted Password Store.'})
        except Exception as e:
            logger.error("{}".format(self._catch_error(e)))
            return json.dumps({"msg": "{}".format(e), "step": "end_of_discussion"})

    handle_POST = handle_GET
