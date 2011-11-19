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

static nagios_macros *mac;

#define MAX_MESSAGE_BUFFER		4096

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
int sticky = FALSE;
int send_notification = FALSE;
int persistent_comment = FALSE;
char *comment_author = NULL;
char *comment_data = NULL;

unsigned long host_properties = 0L;
unsigned long service_properties = 0L;

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
	else if (!strcmp(api_action, "host.ack")) {
		if (host_name == NULL) {
			RETURN_API_ERROR(STATUS_API_ERROR_PARAM, "Host name not given.");
			}
		int result = cmd_submitf(CMD_ACKNOWLEDGE_HOST_PROBLEM, "%s;%d;%d;%d;%s;%s", host_name, (sticky == TRUE) ? ACKNOWLEDGEMENT_STICKY : ACKNOWLEDGEMENT_NORMAL, send_notification, persistent_comment, comment_author, comment_data);
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

	/* free all allocated memory */
	free_memory();
	free_comment_data();

	return OK;
	}


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

		else if(!strcmp(variables[x], "sticky")) {
			sticky = TRUE;
			}

		else if(!strcmp(variables[x], "send_notification")) {
			send_notification = TRUE;
			}

		else if(!strcmp(variables[x], "persistent_comment")) {
			persistent_comment = TRUE;
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

