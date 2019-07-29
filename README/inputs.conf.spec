[gsuite_directory_user_list://<name>]
domain = GSuite domain - You need to have already authenticated the domain: Configuration > Application Configuration
hec_token = HTTP Event Collector token
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.

[gmail_enforce_audit://<name>]
audit_recipient = A valid email address of the user that will receive audit event from monitored inboxes. This is usually the same user used to authenticate the domain in Configuration > Application Configuration
hec_token = HEC token to which the events should be sent
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.

[gmail_retrieve_audit_data://<name>]
domain = GSuite domain - You need to have already authenticated the domain: Configuration > Application Configuration
hec_token = HTTP Event Collector token
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.
batch_size = Batch size of audit messages to process from the compliance inbox. 20 is a good default as it does not run into API limits.
local_domains = Comma separated list of "local" domains. This is to allow the script to differentiate inbound, outbound and internal communications.