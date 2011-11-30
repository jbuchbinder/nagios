/**************************************************************************
 *
 * API.C -  Nagios API CGI
 *
 * Copyright (c) 1999-2010  Ethan Galstad (egalstad@nagios.org)
 * Last Modified: 08-05-2020
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *************************************************************************/

#include "../include/config.h"
#include "../include/common.h"
#include "../include/objects.h"
#include "../include/comments.h"
#include "../include/macros.h"
#include "../include/statusdata.h"

#include "../include/cgiutils.h"
#include "../include/getcgi.h"
#include "../include/cgiauth.h"

#include "../json-c/json.h"

extern const char *extcmd_get_name(int id);

extern char main_config_file[MAX_FILENAME_LENGTH];
extern char command_file[MAX_FILENAME_LENGTH];

extern host *host_list;
extern service *service_list;
extern hostgroup *hostgroup_list;
extern servicegroup *servicegroup_list;
extern hoststatus *hoststatus_list;
extern servicestatus *servicestatus_list;
extern int date_format;

static nagios_macros *mac;

#define MAX_MESSAGE_BUFFER		4096

#define SERVICE_HISTORY                 0
#define HOST_HISTORY                    1
#define SERVICE_FLAPPING_HISTORY        2
#define HOST_FLAPPING_HISTORY           3
#define SERVICE_DOWNTIME_HISTORY        4
#define HOST_DOWNTIME_HISTORY           5

#define DISPLAY_HOSTS			0
#define DISPLAY_HOSTGROUPS		1
#define DISPLAY_SERVICEGROUPS           2

int process_cgivars(void);
void document_header();
json_object *service_to_json(servicestatus *s);
json_object *host_to_json(host *h);
json_object *build_result(int code, char *comment);
__attribute__((format(printf, 2, 3))) static int cmd_submitf(int id, const char *fmt, ...);
int write_command_to_file(char *cmd);
int string_to_time(char *buffer, time_t *t);
json_object * history_to_json(host *s);

authdata current_authdata;
time_t current_time;

char alert_message[MAX_MESSAGE_BUFFER];
char *api_action = NULL;
char *host_name = NULL;
char *service_name = NULL;
char *host_filter = NULL;
char *hostgroup_name = NULL;
char *servicegroup_name = NULL;
int host_alert = FALSE;
int show_all_hosts = TRUE;
int show_all_hostgroups = TRUE;
int show_all_servicegroups = TRUE;
int display_system_messages = FALSE;
int display_flapping_alerts = FALSE;
int display_downtime_alerts = TRUE;
int sticky = FALSE;
int enable = -1;
int send_notification = FALSE;
int persistent_comment = FALSE;
char *comment_author = NULL;
char *comment_data = NULL;

char *start_time_string = "";
char *end_time_string = "";
time_t start_time = 0L;
time_t end_time = 0L;

unsigned long host_properties = 0L;
unsigned long service_properties = 0L;

char *api_methods[] = {
	  "api.methods"

	  /* Host methods */
	, "host.ack"
	, "host.get"
	, "host.list"
	, "host.notifications"
	, "host.schedule"
	, "host.services"

	  /* Service methods */
	, "service.ack"
	, "service.get"
	, "service.list"
	, "service.notifications"
	, "service.problems"
	, "service.schedule"

	, NULL
};

#define RETURN_API_ERROR(code, text) { \
	printf("{\"response_type\":\"ERROR\",\"error_code\":%d,\"error_message\":\"%s\"}\n", code, text); \
        free_memory(); \
        free_comment_data(); \
	exit(0); \
	}

#define STATUS_API_ERROR_SETUP 500
#define STATUS_API_ERROR_PARAM 501

int main(void) {
	int result = OK;

	mac = get_global_macros();

	time(&current_time);

	/* get the arguments passed in the URL */
	process_cgivars();

	/* reset internal variables */
	reset_cgi_vars();

	/* return headers */
	document_header();

	/* read the CGI configuration file */
	result = read_cgi_config_file(get_cgi_config_location());
	if(result == ERROR) {
		RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Error reading config file");
		}

	/* read the main configuration file */
	result = read_main_config_file(main_config_file);
	if(result == ERROR) {
		RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Error reading config file");
		}

	/* This requires the date_format parameter in the main config file */
	if(strcmp(start_time_string, "")) {
		string_to_time(start_time_string, &start_time);
		}
	if(strcmp(end_time_string, "")) {
		string_to_time(end_time_string, &end_time);
		}

	/* read all object configuration data */
	result = read_all_object_configuration_data(main_config_file, READ_ALL_OBJECT_DATA);
	if(result == ERROR) {
		RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Error reading configuration data");
		}

	/* read all status data */
	result = read_all_status_data(get_cgi_config_location(), READ_ALL_STATUS_DATA);
	if(result == ERROR) {
		free_memory();
		RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Error reading status data");
		}

	/* initialize macros */
	init_macros();

	/* get authentication information */
	get_authentication_information(&current_authdata);

	contact *contact = find_contact(current_authdata.username);
	if(contact != NULL && contact->alias != NULL)
		comment_author = contact->alias;
	else
		comment_author = current_authdata.username;

	/* Error out if someone has left out the 'api_action' parameter. */
	if (api_action == NULL) {
		RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "API action parameter not present.");
		}

	/* perform actions here */
	if (!strcmp(api_action, "host.list")) {
		json_object *jout = json_object_new_array();
		host *temp_host = NULL;
		for (temp_host = host_list; temp_host != NULL; temp_host = temp_host->next) {
			json_object_array_add(jout, json_object_new_string(temp_host->name));
			}
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "host.services")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		json_object *jout = json_object_new_array();
		service *temp_service = NULL;
		for (temp_service = service_list; temp_service != NULL; temp_service = temp_service->next) {
			if (!strcmp(temp_service->host_name, host_name)) {
				json_object_array_add(jout, json_object_new_string(temp_service->display_name));
				}
			}
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "service.get")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		if (service_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Service name not given.");
			}
		servicestatus *s = find_servicestatus(host_name, service_name);
		json_object *jout = service_to_json(s);
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "service.problems")) {
		servicestatus *temp_servicestatus = NULL;
		json_object *jout = json_object_new_array();
		for (temp_servicestatus = servicestatus_list; temp_servicestatus != NULL; temp_servicestatus = temp_servicestatus->next) {
			if (temp_servicestatus->status == SERVICE_CRITICAL || temp_servicestatus->status == SERVICE_WARNING || temp_servicestatus->status == SERVICE_UNKNOWN) {
				json_object *jitem = service_to_json(temp_servicestatus);
				json_object_array_add(jout, jitem);
				}
			}
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "host.ack")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		int result = cmd_submitf(CMD_ACKNOWLEDGE_HOST_PROBLEM, "%s;%d;%d;%d;%s;%s", host_name, (sticky == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, comment_author, comment_data);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "host.notifications")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		if (enable == -1) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Enable not given.");
			}
		int result = cmd_submitf(enable ? CMD_ENABLE_HOST_NOTIFICATIONS : CMD_DISABLE_HOST_NOTIFICATIONS, "%s", host_name);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "host.schedule")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		int result = cmd_submitf(CMD_SCHEDULE_FORCED_HOST_CHECK, "%s;%lu", host_name, start_time);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "service.schedule")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		if (service_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Service name not given.");
			}
		int result = cmd_submitf(CMD_SCHEDULE_FORCED_SVC_CHECK, "%s;%s;%lu", host_name, service_name, start_time);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "service.notifications")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		if (service_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Service name not given.");
			}
		if (enable == -1) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Enable not given.");
			}
		int result = cmd_submitf(enable ? CMD_ENABLE_SVC_NOTIFICATIONS : CMD_DISABLE_SVC_NOTIFICATIONS, "%s;%s", host_name, service_name);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "service.ack")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		if (service_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Service name not given.");
			}
		int result = cmd_submitf(CMD_ACKNOWLEDGE_SVC_PROBLEM, "%s;%s;%d;%d;%d;%s;%s", host_name, service_name, (sticky == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, comment_author, comment_data);
		printf("%s", json_object_to_json_string(build_result(result, NULL)));
		}
	else if (!strcmp(api_action, "host.get")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		host *s = find_host(host_name);
		json_object *jout = host_to_json(s);
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "host.gangliaevents")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		host *s = find_host(host_name);
		json_object *jout = history_to_json(s);
		printf("%s", json_object_to_json_string(jout));
		}
	else if (!strcmp(api_action, "api.methods")) {
		json_object *jout = json_object_new_array();
		int i;
		for (i=0; api_methods[i] != NULL; i++) {
			json_object_array_add(jout, json_object_new_string(api_methods[i]));
			}
		printf("%s", json_object_to_json_string(jout));
		}

	/* free all allocated memory */
	free_memory();
	free_comment_data();

	return OK;
	}


#define PROCESS_CGIVARS_TRUE_FALSE( X ) x++; \
	if (variables[x] == NULL) { error = TRUE; break; } \
	if (!strcmp(variables[x], "0")) { X = FALSE; } else { X = TRUE; } 

int process_cgivars(void) {
	char **variables;
	int error = FALSE;
	int x;

	variables = getcgivars();

	for(x = 0; variables[x] != NULL; x++) {

		/* do some basic length checking on the variable identifier to prevent buffer overflows */
		if(strlen(variables[x]) >= MAX_INPUT_BUFFER - 1) {
			x++;
			continue;
			}

		/* Parse action */
		else if(!strcmp(variables[x], "action")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}
			api_action = strdup(variables[x]);
			strip_html_brackets(api_action);
			}

		/* we found the host argument */
		else if(!strcmp(variables[x], "host")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}

			host_name = strdup(variables[x]);
			strip_html_brackets(host_name);
			}

		/* we found the service argument */
		else if(!strcmp(variables[x], "service")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}

			service_name = strdup(variables[x]);
			strip_html_brackets(service_name);
			}

		/* we found the start time */
		else if(!strcmp(variables[x], "start_time")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}

			start_time_string = (char *)malloc(strlen(variables[x]) + 1);
			if (start_time_string == NULL) {
				start_time_string = NULL;
			} else 
				strcpy(start_time_string, variables[x]);
			}

		else if(!strcmp(variables[x], "end_time")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}

			end_time_string = (char *)malloc(strlen(variables[x]) + 1);
			if (end_time_string == NULL) {
				end_time_string = NULL;
			} else 
				strcpy(end_time_string, variables[x]);
			}

		else if(!strcmp(variables[x], "enable")) {
			PROCESS_CGIVARS_TRUE_FALSE(enable)
			}

		else if(!strcmp(variables[x], "sticky")) {
			PROCESS_CGIVARS_TRUE_FALSE(sticky)
			}

		else if(!strcmp(variables[x], "send_notification")) {
			PROCESS_CGIVARS_TRUE_FALSE(send_notification)
			}

		else if(!strcmp(variables[x], "persistent_comment")) {
			PROCESS_CGIVARS_TRUE_FALSE(persistent_comment)
			}

		else if(!strcmp(variables[x], "comment_data")) {
			x++;
			if(variables[x] == NULL) {
				error = TRUE;
				break;
				}

			comment_data = strdup(variables[x]);
			strip_html_brackets(comment_data);
			}

		}

	/* free memory allocated to the CGI variables */
	free_cgivars(variables);

	return error;
}

void document_header() {
        char date_time[MAX_DATETIME_LENGTH];
        time_t expire_time;

        printf("Cache-Control: no-store\r\n");
        printf("Pragma: no-cache\r\n");

        get_time_string(&current_time, date_time, (int)sizeof(date_time), HTTP_DATE_TIME);
        printf("Last-Modified: %s\r\n", date_time);

        expire_time = (time_t)0L;
        get_time_string(&expire_time, date_time, (int)sizeof(date_time), HTTP_DATE_TIME);
        printf("Expires: %s\r\n", date_time);

        printf("Content-type: application/json\r\n\r\n");
}

json_object *host_to_json(host *h) {
	json_object *jout = json_object_new_object();
	json_object_object_add(jout, "name", json_object_new_string(h->name));
	if (h->alias) json_object_object_add(jout, "alias", json_object_new_string(h->alias));
	json_object_object_add(jout, "address", json_object_new_string(h->address));
	json_object_object_add(jout, "checks_enabled", json_object_new_int(h->checks_enabled));
	json_object_object_add(jout, "flap_detection_enabled", json_object_new_int(h->flap_detection_enabled));
	json_object_object_add(jout, "obsess_over_host", json_object_new_int(h->obsess_over_host));
	if (h->notes) json_object_object_add(jout, "notes", json_object_new_string(h->notes));
	return jout;
}

json_object *service_to_json(servicestatus *s) {
	json_object *jout = json_object_new_object();
	json_object_object_add(jout, "host", json_object_new_string(s->host_name));
	json_object_object_add(jout, "service", json_object_new_string(s->description));
	if (s->status == SERVICE_CRITICAL) {
		json_object_object_add(jout, "status", json_object_new_string("CRITICAL"));
		}
	else if (s->status == SERVICE_WARNING) {
		json_object_object_add(jout, "status", json_object_new_string("WARNING"));
		}
	else if (s->status == SERVICE_UNKNOWN) {
		json_object_object_add(jout, "status", json_object_new_string("UNKNOWN"));
		}
	else {
		json_object_object_add(jout, "status", json_object_new_string("OK"));
		}
	if (s->plugin_output) json_object_object_add(jout, "plugin_output", json_object_new_string(s->plugin_output));
	if (s->long_plugin_output) json_object_object_add(jout, "long_plugin_output", json_object_new_string(s->long_plugin_output));
	json_object_object_add(jout, "acknowledged", json_object_new_int(s->problem_has_been_acknowledged));
	json_object_object_add(jout, "current_attempt", json_object_new_int(s->current_attempt));
	json_object_object_add(jout, "max_attempts", json_object_new_int(s->max_attempts));
	json_object_object_add(jout, "checks_enabled", json_object_new_int(s->checks_enabled));
	json_object_object_add(jout, "notifications_enabled", json_object_new_int(s->notifications_enabled));
	json_object_object_add(jout, "is_flapping", json_object_new_int(s->is_flapping));
	json_object_object_add(jout, "scheduled_downtime_depth", json_object_new_int(s->scheduled_downtime_depth));
	return jout;
}


json_object *build_result(int code, char *comment) {
	json_object *jout = json_object_new_object();
	json_object_object_add(jout, "code", json_object_new_int(code));
	switch (code) {
		case OK:
			json_object_object_add(jout, "result", json_object_new_string("OK"));
			break;
		case ERROR:
			json_object_object_add(jout, "result", json_object_new_string("ERROR"));
			break;
		default:
			json_object_object_add(jout, "result", json_object_new_string("UNKNOWN"));
			break;
	}
	if (comment) json_object_object_add(jout, "comment", json_object_new_string(comment));
	return jout;
}


__attribute__((format(printf, 2, 3)))
static int cmd_submitf(int id, const char *fmt, ...) {
	char cmd[MAX_EXTERNAL_COMMAND_LENGTH];
	const char *command;
	int len, len2;
	va_list ap;

	command = extcmd_get_name(id);
	/*
	 * We disallow sending 'CHANGE' commands from the cgi's
	 * until we do proper session handling to prevent cross-site
	 * request forgery
	 */
	if(!command || (strlen(command) > 6 && !memcmp("CHANGE", command, 6)))
		return ERROR;

	len = snprintf(cmd, sizeof(cmd) - 1, "[%lu] %s;", time(NULL), command);
	if(len < 0)
		return ERROR;

	if(fmt) {
		va_start(ap, fmt);
		len2 = vsnprintf(&cmd[len], sizeof(cmd) - len - 1, fmt, ap);
		va_end(ap);
		if(len2 < 0)
			return ERROR;
		}

	return write_command_to_file(cmd);
	}

int write_command_to_file(char *cmd) {
	FILE *fp;
	struct stat statbuf;

	/*
	* Commands are not allowed to have newlines in them, as
	* that allows malicious users to hand-craft requests that
	* bypass the access-restrictions.
	*/
	if(!cmd || !*cmd || strchr(cmd, '\n'))
		return ERROR;

	/* bail out if the external command file doesn't exist */
	if(stat(command_file, &statbuf)) {
		return ERROR;
		}

	/* open the command for writing (since this is a pipe, it will really be appended) */
	fp = fopen(command_file, "w");
	if(fp == NULL) {
		return ERROR;
		}

	/* write the command to file */
	fprintf(fp, "%s\n", cmd);

	/* flush buffer */
	fflush(fp);
	fclose(fp);

	return OK;
	}

int string_to_time(char *buffer, time_t *t) {
	struct tm lt;
	int ret = 0;

	if (buffer == NULL) {
		t = &current_time;
		return OK;
		}

	lt.tm_mon = 0;
	lt.tm_mday = 1;
	lt.tm_year = 1900;
	lt.tm_hour = 0;
	lt.tm_min = 0;
	lt.tm_sec = 0;
	lt.tm_wday = 0;
	lt.tm_yday = 0;

	/* Handle seconds since epoch format */
	if(atol(buffer) > 500000000) {
		*t = (time_t) atol(buffer);
		return OK;
		}

	if(date_format == DATE_FORMAT_EURO)
		ret = sscanf(buffer, "%02d-%02d-%04d %02d:%02d:%02d", &lt.tm_mday, &lt.tm_mon, &lt.tm_year, &lt.tm_hour, &lt.tm_min, &lt.tm_sec);
	else if(date_format == DATE_FORMAT_ISO8601 || date_format == DATE_FORMAT_STRICT_ISO8601)
		ret = sscanf(buffer, "%04d-%02d-%02d%*[ T]%02d:%02d:%02d", &lt.tm_year, &lt.tm_mon, &lt.tm_mday, &lt.tm_hour, &lt.tm_min, &lt.tm_sec);
	else
		ret = sscanf(buffer, "%02d-%02d-%04d %02d:%02d:%02d", &lt.tm_mon, &lt.tm_mday, &lt.tm_year, &lt.tm_hour, &lt.tm_min, &lt.tm_sec);

	if(ret != 6)
		return ERROR;

	lt.tm_mon--;
	lt.tm_year -= 1900;

	lt.tm_isdst = -1;

	*t = mktime(&lt);

	return OK;
	}

json_object *
history_to_json( host *s ) {
	// json_object_array_add(jout, jitem);
	int rc = 0;
	json_object *o = json_object_new_array();

	/* Parsing variables */
	char description[MAX_INPUT_BUFFER];
	char date_time[MAX_DATETIME_LENGTH];
	char *input = NULL;
	char *input2 = NULL;
	char *temp_buffer = NULL;
	char *entry_host_name = NULL;
	char *entry_service_desc = NULL;
	host *temp_host = NULL;
	service *temp_service = NULL;
	int history_type = SERVICE_HISTORY;
	int history_detail_type = HISTORY_SERVICE_CRITICAL;
	time_t t;
	struct tm *time_ptr = NULL;
	int system_message = FALSE;
	char current_message_date[MAX_INPUT_BUFFER] = "";

	char log_file_to_use[MAX_FILENAME_LENGTH];
	int log_archive = 0;
	get_log_archive_to_use(log_archive, log_file_to_use, (int)sizeof(log_file_to_use));
	rc = read_file_into_lifo(log_file_to_use);
	if (rc != LIFO_OK) {
		if (rc == LIFO_ERROR_MEMORY) {
			RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Insufficient memory");
		} else if (rc == LIFO_ERROR_FILE) {
			RETURN_API_ERROR(STATUS_API_ERROR_SETUP, "Error reading log file");
			}
		}

	while (1) {

		my_free(input);
		my_free(input2);

		if ((input = pop_lifo()) == NULL) break;

		strip(input);

		strcpy(description, "");
		system_message = FALSE;

		if ((input2 = (char *)strdup(input)) == NULL) continue;

		/* service state alerts */
		if(strstr(input, "SERVICE ALERT:")) {

			history_type = SERVICE_HISTORY;

			/* get host and service names */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_service_desc = strdup(temp_buffer);
			else
				entry_service_desc = NULL;

			if (strstr(input, ";CRITICAL;")) {
				history_detail_type = HISTORY_SERVICE_CRITICAL;
				}
			else if (strstr(input, ";WARNING;")) {
				history_detail_type = HISTORY_SERVICE_WARNING;
				}
			else if (strstr(input, ";UNKNOWN;")) {
				history_detail_type = HISTORY_SERVICE_UNKNOWN;
				}
			else if (strstr(input, ";RECOVERY;") || strstr(input, ";OK;")) {
				history_detail_type = HISTORY_SERVICE_RECOVERY;
				}

                        }
		/* service flapping alerts */
		else if (strstr(input, "SERVICE FLAPPING ALERT:")) {

			if(display_flapping_alerts == FALSE) continue;

			history_type = SERVICE_FLAPPING_HISTORY;

			/* get host and service names */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_service_desc = strdup(temp_buffer);
			else
				entry_service_desc = NULL;

			if(strstr(input, ";STARTED;"))
				strncpy(description, "Service started flapping", sizeof(description));
			else if(strstr(input, ";STOPPED;"))
				strncpy(description, "Service stopped flapping", sizeof(description));
			else if(strstr(input, ";DISABLED;"))
				strncpy(description, "Service flap detection disabled", sizeof(description));
                        }

		/* service downtime alerts */
		else if(strstr(input, "SERVICE DOWNTIME ALERT:")) {

			if(display_downtime_alerts == FALSE) continue;

			history_type = SERVICE_DOWNTIME_HISTORY;

			/* get host and service names */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;
			temp_buffer = my_strtok(NULL, ";");

			if (temp_buffer)
				entry_service_desc = strdup(temp_buffer);
			else
				entry_service_desc = NULL;

			if(strstr(input, ";STARTED;"))
				strncpy(description, "Service entered a period of scheduled downtime", sizeof(description));
			else if(strstr(input, ";STOPPED;"))
				strncpy(description, "Service exited from a period of scheduled downtime", sizeof(description));
			else if(strstr(input, ";CANCELLED;"))
				strncpy(description, "Service scheduled downtime has been cancelled", sizeof(description));
                        }

		/* host state alerts */
		else if(strstr(input, "HOST ALERT:")) {

			history_type = HOST_HISTORY;

			/* get host name */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;

			if(strstr(input, ";DOWN;")) {
				history_detail_type = HISTORY_HOST_DOWN;
				}
			else if(strstr(input, ";UNREACHABLE;")) {
				history_detail_type = HISTORY_HOST_UNREACHABLE;
				}
			else if(strstr(input, ";RECOVERY") || strstr(input, ";UP;")) {
				history_detail_type = HISTORY_HOST_RECOVERY;
				}
			}
		/* host flapping alerts */
		else if(strstr(input, "HOST FLAPPING ALERT:")) {

			if(display_flapping_alerts == FALSE) continue;

			history_type = HOST_FLAPPING_HISTORY;

			/* get host name */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;

			if(strstr(input, ";STARTED;"))
				strncpy(description, "Host started flapping", sizeof(description));
			else if(strstr(input, ";STOPPED;"))
				strncpy(description, "Host stopped flapping", sizeof(description));
			else if(strstr(input, ";DISABLED;"))
				strncpy(description, "Host flap detection disabled", sizeof(description));
			}

		/* host downtime alerts */
		else if(strstr(input, "HOST DOWNTIME ALERT:")) {

			if(display_downtime_alerts == FALSE) continue;

			history_type = HOST_DOWNTIME_HISTORY;

			/* get host name */
			temp_buffer = my_strtok(input2, "]");
			temp_buffer = my_strtok(NULL, ":");
			temp_buffer = my_strtok(NULL, ";");
			if(temp_buffer)
				entry_host_name = strdup(temp_buffer + 1);
			else
				entry_host_name = NULL;

			if(strstr(input, ";STARTED;"))
				strncpy(description, "Host entered a period of scheduled downtime", sizeof(description));
			else if(strstr(input, ";STOPPED;"))
				strncpy(description, "Host exited from a period of scheduled downtime", sizeof(description));
			else if(strstr(input, ";CANCELLED;"))
				strncpy(description, "Host scheduled downtime has been cancelled", sizeof(description));
			}

		else if(display_system_messages == FALSE) continue;

		/* Don't push out "soft" status changes */
		if (strstr(input, ";SOFT;")) continue;

		description[sizeof(description) - 1] = '\x0';

		/* get the timestamp */
		temp_buffer = strtok(input, "]");
		t = (temp_buffer == NULL) ? 0L : strtoul(temp_buffer + 1, NULL, 10);
		time_ptr = localtime(&t);
		strftime(current_message_date, sizeof(current_message_date), "%B %d, %Y %H:00\n", time_ptr);
		current_message_date[sizeof(current_message_date) - 1] = '\x0';

		get_time_string(&t, date_time, sizeof(date_time), SHORT_DATE_TIME);
		strip(date_time);

		/* Ignore all out of range stuff, if specified */
		if (start_time != 0L && t < start_time) continue;
		if (end_time   != 0L && t > end_time  ) continue;

		temp_buffer = strtok(NULL, "\n");

		/* Form host/service history description properly */
		if (history_type == HOST_HISTORY && !strcmp(description, "")) {
			strcpy(description, temp_buffer + 1);
			}
		if (history_type == SERVICE_HISTORY && !strcmp(description, "")) {
			//temp_service = find_service(entry_host_name, entry_service_desc);
			//sprintf(description, "%s [%s]: %s", temp_service->host_name, temp_service->display_name, temp_buffer);
			strcpy(description, temp_buffer + 1);
			}

		if (strcmp(description, "")) {
			if (system_message == FALSE) {
				if(history_type == HOST_HISTORY || history_type == HOST_FLAPPING_HISTORY || history_type == HOST_DOWNTIME_HISTORY) {
					temp_host = find_host(entry_host_name);
					if (strcmp(temp_host->name, s->name)) continue;
					//if (temp_host != s) continue;
					json_object *entry = json_object_new_object();
					json_object_object_add(entry, "event_id", json_object_new_int(t));
					json_object_object_add(entry, "host_regex", json_object_new_string(temp_host->name));
					json_object_object_add(entry, "summary", json_object_new_string(description));
					json_object_object_add(entry, "grid", json_object_new_string("*"));
					json_object_object_add(entry, "cluster", json_object_new_string("*"));
					json_object_object_add(entry, "start_time", json_object_new_int(t));
					json_object_object_add(entry, "end_time", json_object_new_int(t));
					json_object_array_add(o, entry);
				} else {
					temp_host = find_host(entry_host_name);
					//if (temp_host != s) continue;
					temp_service = find_service(entry_host_name, entry_service_desc);
					if (service_name != NULL && strcmp(temp_service->display_name, service_name)) continue;
					if (strcmp(temp_host->name, s->name)) continue;
					json_object *entry = json_object_new_object();
					json_object_object_add(entry, "event_id", json_object_new_int(t));
					json_object_object_add(entry, "host_regex", json_object_new_string(temp_host->name));
					json_object_object_add(entry, "summary", json_object_new_string(description));
					json_object_object_add(entry, "grid", json_object_new_string("*"));
					json_object_object_add(entry, "cluster", json_object_new_string("*"));
					json_object_object_add(entry, "start_time", json_object_new_int(t));
					json_object_object_add(entry, "end_time", json_object_new_int(t));
					json_object_array_add(o, entry);
					}
				}
			}

		}

	return o;
	}

