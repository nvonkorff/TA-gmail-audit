#!/usr/bin/python
import httplib2, json
from apiclient import errors
from apiclient.discovery import build
from datetime import datetime, timedelta
from oauth2client.client import OAuth2WebServerFlow
import os
# Copy your credentials from the console
DOMAIN = raw_input('Enter your Google Apps Domain: ').strip()
CLIENT_ID = raw_input('Enter Client ID: ').strip()
CLIENT_SECRET = raw_input('Enter Client Secret: ').strip()
# Check https://developers.google.com/admin-sdk/reports/v1/guides/authorizing for all available scopes
OAUTH_SCOPE = [ 'https://www.googleapis.com/auth/admin.reports.audit.readonly', #ADMIN SDK REPORTS
		'https://www.googleapis.com/auth/admin.reports.usage.readonly',#ADMIN SDK USAGE
		'https://www.googleapis.com/auth/drive.readonly', #RO GOOGLE DRIVE
		'https://www.googleapis.com/auth/calendar.readonly',#RO GOOGLE CALENDAR
		'https://www.googleapis.com/auth/admin.directory.user.readonly', #RO USER DIRECTORY
		'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly', #RO Devices
		'https://www.googleapis.com/auth/admin.directory.group.readonly', #RO GRoups
		'https://www.googleapis.com/auth/admin.directory.orgunit.readonly', #RO Org Unit
		'https://www.googleapis.com/auth/tasks' #RW USER TASKS
		]
# Redirect URI for installed apps
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
# Run through the OAuth flow and retrieve credentials
flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE, REDIRECT_URI)
authorize_url = flow.step1_get_authorize_url()
print 'Go to the following link in your browser: \n\n' + authorize_url
code = raw_input('Enter verification code: ').strip()
credentials = flow.step2_exchange(code)
from oauth2client.file import Storage
if not os.path.exists("../local"):
	os.makedirs("../local")
myCredFile = "../local/GoogleApps.%s.cred"%DOMAIN.lower()
storage = Storage(myCredFile)
storage.put(credentials)
print 'Credentials Written to "%s"'%myCredFile
