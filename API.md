API
===

* `api.cgi?action=api.methods`

	Get list of supported API methods.

* `api.cgi?action=host.list`

	Get list of hosts.

* `api.cgi?action=host.get&host=HOSTNAME`

	Get host information.

* `api.cgi?action=host.services&host=HOSTNAME`

	Get services for a host.

* `api.cgi?action=service.get&host=HOSTNAME&service=SERVICENAME`

	Get detail for a single service.

* `api.cgi?action=host.schedule&host=HOSTNAME&service=SERVICENAME[&start_time=TIME]

	Reschedule a host check.

* `api.cgi?action=service.schedule&host=HOSTNAME&service=SERVICENAME[&start_time=TIME]

	Reschedule a service check.

* `api.cgi?action=host.ack&host=HOSTNAME[&sticky=1][&send_notification=1][&persistent_comment=1][&comment_data=COMMENT]`

	Acknowledge a host problem.

* `api.cgi?action=service.ack&host=HOSTNAME&service=SERVICENAME[&sticky=1][&send_notification=1][&persistent_comment=1][&comment_data=COMMENT]`

	Acknowledge a service problem.

* `api.cgi?action=host.notifications&host=HOSTNAME&enable=0`

	Enable or disable host notifications.

* `api.cgi?action=service.notifications&host=HOSTNAME&service=SERVICENAME&enable=0`

	Enable or disable service notifications.

* `api.cgi?action=service.problems[&only_active=1]`

	Get all service issues.

* `api.cgi?action=host.gangliaevents&host=HOSTNAME[&service=SERVICENAME][&start_time=STARTTIME][&end_time=ENDTIME]`

	Get Ganglia event format JSON output for events matching criteria.

