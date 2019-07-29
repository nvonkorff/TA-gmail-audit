import json
import logging
import os
import sys

import splunk
# from splunk import AuthorizationFailed as AuthorizationFailed
import splunk.appserver.mrsparkle.lib.util as util

# Google Stuff
import httplib2
import socks
from Utilities import Utilities, KennyLoggins
from oauth2client.client import OAuth2WebServerFlow

_APP_NAME = 'TA-gmail-audit'
dir = os.path.join(util.get_apps_dir(), _APP_NAME, 'bin', 'lib')

if not dir in sys.path:
    sys.path.append(dir)
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
                             "exception_type": "%s" % type(e).__name__,
                             "exception_arguments": "%s" % e,
                             "filename": fname,
                             "line": exc_tb.tb_lineno
                             }]
        return myJson

    # @expose_page(must_login=False, methods=['GET'])
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
            # Run through the OAuth flow and retrieve credentials
            logger.debug("setting flow")
            logger.debug("using cacerts: {}".format(httplib2.CA_CERTS))

            flow = OAuth2WebServerFlow(gapps_client_id, gapps_client_secret, gapps_oauth_scope, gapps_redirect_uri)
            import pickle
            _FLOW = os.path.join(_LOCALDIR, "flowtmp")
            logger.debug("setting flow location: %s" % _FLOW)
            if "one" == gapps_gui_step:
                logger.debug("writing flow to flowtmp")
                f = open(_FLOW, "wb")
                pickle.dump(flow, f)
                f.close()
                logger.debug("returning to launch url")
                return json.dumps({"step": "launch_url", "url": flow.step1_get_authorize_url(),
                                   "msg": "Once you have authorized Splunk, enter the Authorization Token above, and click the authorization button again."})
            logger.debug("reading flow from flowtmp: %s" % _FLOW)
            f = open(_FLOW, "rb")
            sflow = pickle.load(f)
            f.close()
            proxy_config_file = os.path.join(_LOCALDIR, "proxy.conf")
            proxy_info = None
            h = None

            utils = Utilities(app_name=_APP_NAME, session_key=self.sessionKey)
            if os.path.isfile(proxy_config_file):
                try:
                    pc = utils.get_proxy_configuration("gapps_proxy")
                    sptype = socks.PROXY_TYPE_HTTP
                    proxy_info = httplib2.ProxyInfo(sptype, pc["host"], int(pc["port"]),
                                                    proxy_user=pc["authentication"]["username"],
                                                    proxy_pass=pc["authentication"]["password"])
                except Exception, e:
                    logger.warn("action=load_proxy status=failed message=No_Proxy_Information stanza=gapps_proxy")
            h = httplib2.Http(proxy_info=proxy_info)
            credentials = sflow.step2_exchange(gapps_auth_token, h)
            my_credentials = "{}".format(credentials.to_json())
            utils.set_credential(_APP_NAME, gapps_domain, my_credentials)
            logger.debug("deleting flowtmp")
            os.remove(_FLOW)
            return json.dumps({"step": "end_of_discussion",
                               "msg": 'Credentials Written to Encrypted Password Store.'})
        except Exception, e:
            logger.error("%s" % self._catch_error(e))
            return json.dumps({"msg": "{}".format(e), "step": "end_of_discussion"})
        finally:
            f.close()

    handle_POST = handle_GET
