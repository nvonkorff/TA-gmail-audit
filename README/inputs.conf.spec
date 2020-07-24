[gsuite_directory_user_list://<name>]
domain = GSuite domain - You need to have already authenticated the domain: Configuration > Application Configuration
hec_token = HTTP Event Collector token
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.

[gmail_retrieve_audit_data://<name>]
domain = GSuite domain - You need to have already authenticated the domain: Configuration > Application Configuration
hec_token = HTTP Event Collector token
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.
batch_size = Batch size of audit messages to process from the compliance inbox. 20 is a good default as it does not run into API limits.
local_domains = Comma separated list of "local" domains. This is to allow the script to differentiate inbound, outbound and internal communications.
include_body = Include body of email as well as headers. WARNING: Security/privacy implications and increased license/indexing/storage requirements. Use with caution.

[gmail_enforce_audit://<name>]
audit_recipient = A valid email address that will receive audit events from monitored inboxes in the same domain. Usually the same user used to authenticate the domain in Configuration > Application Configuration
hec_token = HEC token to which the events should be sent
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.

[gmail_disable_audit://<name>]
audit_recipient = A valid email address of the user receiving audit event from monitored inboxes
hec_token = HEC token to which the events should be sent
hostname = Leave this as localhost under most circumstances. Ensure you have added a HEC input on localhost.
