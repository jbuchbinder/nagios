/************************************************************************
 *
 * Nagios Common Header File
 * Written By: Ethan Galstad (nagios@nagios.org)
 * Last Modified: 04-20-2002
 *
 * License:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 ************************************************************************/


#define PROGRAM_VERSION "1.3"
#define PROGRAM_MODIFICATION_DATE "10-24-2004"


/***************************** COMMANDS *********************************/

#define CMD_NONE			0

#define CMD_ADD_HOST_COMMENT		1
#define CMD_DEL_HOST_COMMENT		2

#define CMD_ADD_SVC_COMMENT		3
#define CMD_DEL_SVC_COMMENT		4

#define CMD_ENABLE_SVC_CHECK		5
#define CMD_DISABLE_SVC_CHECK		6
#define CMD_DELAY_SVC_CHECK		7
#define CMD_IMMEDIATE_SVC_CHECK		8

#define CMD_DELAY_SVC_NOTIFICATION	9

#define CMD_DELAY_HOST_NOTIFICATION	10

#define CMD_DISABLE_NOTIFICATIONS	11
#define CMD_ENABLE_NOTIFICATIONS	12

#define CMD_RESTART_PROCESS		13
#define CMD_SHUTDOWN_PROCESS		14

#define CMD_ENABLE_HOST_SVC_CHECKS              15
#define CMD_DISABLE_HOST_SVC_CHECKS             16

#define CMD_DELAY_HOST_SVC_CHECKS               17
#define CMD_IMMEDIATE_HOST_SVC_CHECKS           18
#define CMD_DELAY_HOST_SVC_NOTIFICATIONS        19  /* currently unimplemented */

#define CMD_DEL_ALL_HOST_COMMENTS               20
#define CMD_DEL_ALL_SVC_COMMENTS                21

#define CMD_ENABLE_SVC_NOTIFICATIONS                    22
#define CMD_DISABLE_SVC_NOTIFICATIONS                   23
#define CMD_ENABLE_HOST_NOTIFICATIONS                   24
#define CMD_DISABLE_HOST_NOTIFICATIONS                  25
#define CMD_ENABLE_ALL_NOTIFICATIONS_BEYOND_HOST        26
#define CMD_DISABLE_ALL_NOTIFICATIONS_BEYOND_HOST       27
#define CMD_ENABLE_HOST_SVC_NOTIFICATIONS		28
#define CMD_DISABLE_HOST_SVC_NOTIFICATIONS		29

#define CMD_PROCESS_SERVICE_CHECK_RESULT		30

#define CMD_SAVE_STATE_INFORMATION			31
#define CMD_READ_STATE_INFORMATION			32

#define CMD_ACKNOWLEDGE_HOST_PROBLEM			33
#define CMD_ACKNOWLEDGE_SVC_PROBLEM			34

#define CMD_START_EXECUTING_SVC_CHECKS			35
#define CMD_STOP_EXECUTING_SVC_CHECKS			36

#define CMD_START_ACCEPTING_PASSIVE_SVC_CHECKS		37
#define CMD_STOP_ACCEPTING_PASSIVE_SVC_CHECKS		38

#define CMD_ENABLE_PASSIVE_SVC_CHECKS			39
#define CMD_DISABLE_PASSIVE_SVC_CHECKS			40

#define CMD_ENABLE_EVENT_HANDLERS			41
#define CMD_DISABLE_EVENT_HANDLERS			42

#define CMD_ENABLE_HOST_EVENT_HANDLER			43
#define CMD_DISABLE_HOST_EVENT_HANDLER			44

#define CMD_ENABLE_SVC_EVENT_HANDLER			45
#define CMD_DISABLE_SVC_EVENT_HANDLER			46

#define CMD_ENABLE_HOST_CHECK				47
#define CMD_DISABLE_HOST_CHECK				48

#define CMD_START_OBSESSING_OVER_SVC_CHECKS		49
#define CMD_STOP_OBSESSING_OVER_SVC_CHECKS		50

#define CMD_REMOVE_HOST_ACKNOWLEDGEMENT			51
#define CMD_REMOVE_SVC_ACKNOWLEDGEMENT			52

#define CMD_FORCE_DELAY_HOST_SVC_CHECKS                 53
#define CMD_FORCE_DELAY_SVC_CHECK                       54

#define CMD_SCHEDULE_HOST_DOWNTIME                      55
#define CMD_SCHEDULE_SVC_DOWNTIME                       56

#define CMD_ENABLE_HOST_FLAP_DETECTION                  57
#define CMD_DISABLE_HOST_FLAP_DETECTION                 58

#define CMD_ENABLE_SVC_FLAP_DETECTION                   59
#define CMD_DISABLE_SVC_FLAP_DETECTION                  60

#define CMD_ENABLE_FLAP_DETECTION                       61
#define CMD_DISABLE_FLAP_DETECTION                      62

#define CMD_ENABLE_HOSTGROUP_SVC_NOTIFICATIONS          63 /* not internally implemented */
#define CMD_DISABLE_HOSTGROUP_SVC_NOTIFICATIONS         64 /* not internally implemented */

#define CMD_ENABLE_HOSTGROUP_HOST_NOTIFICATIONS         65 /* not internally implemented */
#define CMD_DISABLE_HOSTGROUP_HOST_NOTIFICATIONS        66 /* not internally implemented */

#define CMD_ENABLE_HOSTGROUP_SVC_CHECKS                 67 /* not internally implemented */
#define CMD_DISABLE_HOSTGROUP_SVC_CHECKS                68 /* not internally implemented */

#define CMD_CANCEL_HOST_DOWNTIME                        69 /* not internally implemented */
#define CMD_CANCEL_SVC_DOWNTIME                         70 /* not internally implemented */

#define CMD_CANCEL_ACTIVE_HOST_DOWNTIME                 71 /* old - no longer used */
#define CMD_CANCEL_PENDING_HOST_DOWNTIME                72 /* old - no longer used */

#define CMD_CANCEL_ACTIVE_SVC_DOWNTIME                  73 /* old - no longer used */
#define CMD_CANCEL_PENDING_SVC_DOWNTIME                 74 /* old - no longer used */

#define CMD_CANCEL_ACTIVE_HOST_SVC_DOWNTIME             75 /* unimplemented */
#define CMD_CANCEL_PENDING_HOST_SVC_DOWNTIME            76 /* unimplemented */

#define CMD_FLUSH_PENDING_COMMANDS                      77

#define CMD_DEL_HOST_DOWNTIME                           78
#define CMD_DEL_SVC_DOWNTIME                            79

#define CMD_ENABLE_FAILURE_PREDICTION                   80
#define CMD_DISABLE_FAILURE_PREDICTION                  81

#define CMD_ENABLE_PERFORMANCE_DATA                     82
#define CMD_DISABLE_PERFORMANCE_DATA                    83

#define CMD_SCHEDULE_HOSTGROUP_HOST_DOWNTIME            84 /* not internally implemented */
#define CMD_SCHEDULE_HOSTGROUP_SVC_DOWNTIME             85 /* not internally implemented */
#define CMD_SCHEDULE_HOST_SVC_DOWNTIME                  86



/************************ SERVICE CHECK TYPES ****************************/

#define SERVICE_CHECK_ACTIVE		0	/* Nagios performed the service check */
#define SERVICE_CHECK_PASSIVE		1	/* the service check result was submitted by an external source */


/************************ SERVICE STATE TYPES ****************************/

#define SOFT_STATE			0	
#define HARD_STATE			1


/**************************** COMMENT TYPES ******************************/

#define HOST_COMMENT			1
#define SERVICE_COMMENT			2


/************************* SCHEDULED DOWNTIME TYPES **********************/

#define SERVICE_DOWNTIME		0	/* service downtime */
#define HOST_DOWNTIME			1	/* host downtime */


/**************************** DEPENDENCY TYPES ***************************/

#define NOTIFICATION_DEPENDENCY		1
#define EXECUTION_DEPENDENCY		2


/**************************** PROGRAM MODES ******************************/

#define STANDBY_MODE		0	
#define ACTIVE_MODE		1


/************************** LOG ROTATION MODES ***************************/

#define LOG_ROTATION_NONE       0
#define LOG_ROTATION_HOURLY     1
#define LOG_ROTATION_DAILY      2
#define LOG_ROTATION_WEEKLY     3
#define LOG_ROTATION_MONTHLY    4


/************************* GENERAL DEFINITIONS  **************************/

#define	OK				0
#define ERROR				-2	/* value was changed from -1 so as to not interfere with STATUS_UNKNOWN plugin result */

#define TRUE				1
#define FALSE				0


/****************** HOST CONFIG FILE READING OPTIONS ********************/

#define READ_HOSTS			1
#define READ_HOSTGROUPS			2
#define READ_CONTACTS			4
#define READ_CONTACTGROUPS		8
#define READ_SERVICES			16
#define READ_COMMANDS			32
#define READ_TIMEPERIODS		64
#define READ_SERVICEESCALATIONS		128
#define READ_HOSTGROUPESCALATIONS	256
#define READ_SERVICEDEPENDENCIES        512
#define READ_HOSTDEPENDENCIES           1024
#define READ_HOSTESCALATIONS            2048

#define READ_ALL_OBJECT_DATA            READ_HOSTS | READ_HOSTGROUPS | READ_CONTACTS | READ_CONTACTGROUPS | READ_SERVICES | READ_COMMANDS | READ_TIMEPERIODS | READ_SERVICEESCALATIONS | READ_HOSTGROUPESCALATIONS | READ_SERVICEDEPENDENCIES | READ_HOSTDEPENDENCIES | READ_HOSTESCALATIONS


/************************** DATE/TIME TYPES *****************************/

#define LONG_DATE_TIME			0
#define SHORT_DATE_TIME			1
#define SHORT_DATE			2
#define SHORT_TIME			3
#define HTTP_DATE_TIME			4	/* time formatted for use in HTTP headers */


/**************************** DATE FORMATS ******************************/

#define DATE_FORMAT_US                  0       /* U.S. (MM-DD-YYYY HH:MM:SS) */
#define DATE_FORMAT_EURO                1       /* European (DD-MM-YYYY HH:MM:SS) */
#define DATE_FORMAT_ISO8601             2       /* ISO8601 (YYYY-MM-DD HH:MM:SS) */
#define DATE_FORMAT_STRICT_ISO8601      3       /* ISO8601 (YYYY-MM-DDTHH:MM:SS) */


/************************** MISC DEFINITIONS ****************************/

#define MAX_FILENAME_LENGTH			256	/* max length of path/filename that Nagios will process */
#define MAX_INPUT_BUFFER			1024	/* size in bytes of max. input buffer (for reading files) */

#define MAX_DATETIME_LENGTH			48

