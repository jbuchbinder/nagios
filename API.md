API
===

* `api.cgi?action=host.list`

	Get list of hosts.

* `api.cgi?action=host.get&host=HOSTNAME`

	Get host information.

* `api.cgi?action=host.services&host=HOSTNAME`

	Get services for a host.

* `api.cgi?action=service.get&host=HOSTNAME&service=SERVICENAME`

	Get detail for a single service.

* `api.cgi?action=host.ack&host=HOSTNAME[&sticky=1][&send_notification=1][&persistent_comment=1][&comment_data=COMMENT]`

	Acknowledge a host problem.

* `api.cgi?action=service.ack&host=HOSTNAME&service=SERVICENAME[&sticky=1][&send_notification=1][&persistent_comment=1][&comment_data=COMMENT]`

	Acknowledge a service problem.

