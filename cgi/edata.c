/*****************************************************************************
 *
 * EDATA.C - External extended object config data for Nagios CGIs
 *
 * Copyright (c) 1999-2001 Ethan Galstad (nagios@nagios.org)
 * Last Modified:   05-07-2001
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
 *
 *****************************************************************************/

/*********** COMMON HEADER FILES ***********/

#include "../common/config.h"
#include "../common/common.h"
#include "../common/objects.h"
#include "cgiutils.h"
#include "edata.h"


/**** IMPLEMENTATION SPECIFIC HEADER FILES ****/

#ifdef USE_XEDDEFAULT
#include "../xdata/xeddefault.h"		/* default routines */
#endif
#ifdef USE_XEDTEMPLATE
#include "../xdata/xedtemplate.h"		/* template-based routines */
#endif
#ifdef USE_XEDDB
#include "../xdata/xeddb.h"			/* database routines */
#endif




hostextinfo     *hostextinfo_list=NULL;
serviceextinfo  *serviceextinfo_list=NULL;




/******************************************************************/
/******************* TOP-LEVEL INPUT FUNCTIONS ********************/
/******************************************************************/


/* reads in all extended data */
int read_extended_object_config_data(char *config_file, int options){
	int result;

	/**** IMPLEMENTATION-SPECIFIC CALLS ****/
#ifdef USE_XEDDEFAULT
	result=xeddefault_read_extended_object_config_data(config_file,options);
	if(result!=OK)
		return ERROR;
#endif
#ifdef USE_XEDTEMPLATE
	result=xedtemplate_read_extended_object_config_data(config_file,options);
	if(result!=OK)
		return ERROR;
#endif
#ifdef USE_XEDDB
	result=xeddb_read_extended_object_config_data(config_file,options);
	if(result!=OK)
		return ERROR;
#endif

	return OK;
        }



/******************************************************************/
/********************** ADDITION FUNCTIONS ************************/
/******************************************************************/


/* adds an extended host info structure to the list in memory */
int add_extended_host_info(char *host_name,char *notes_url, char *icon_image, char *vrml_image, char *gd2_icon_image, char *icon_image_alt, int x_2d, int y_2d, double x_3d, double y_3d, double z_3d, int have_2d_coords, int have_3d_coords){
	hostextinfo *new_hostextinfo;


	/* make sure we have what we need */
	if(host_name==NULL)
		return ERROR;
	if(!strcmp(host_name,""))
		return ERROR;


	/* allocate memory for a new data structure */
	new_hostextinfo=(hostextinfo *)malloc(sizeof(hostextinfo));
	if(new_hostextinfo==NULL)
		return ERROR;
				
	new_hostextinfo->host_name=(char *)malloc(strlen(host_name)+1);
	if(new_hostextinfo->host_name==NULL){
		free(new_hostextinfo);
		return ERROR;
	        }
	strcpy(new_hostextinfo->host_name,host_name);

	if(notes_url==NULL || !strcmp(notes_url,""))
		new_hostextinfo->notes_url=NULL;
	else{
		new_hostextinfo->notes_url=(char *)malloc(strlen(notes_url)+1);
		if(new_hostextinfo->notes_url==NULL){
			free(new_hostextinfo->host_name);
			free(new_hostextinfo);
			return ERROR;
		        }
		strcpy(new_hostextinfo->notes_url,notes_url);
	        }

	if(icon_image==NULL || !strcmp(icon_image,""))
		new_hostextinfo->icon_image=NULL;
	else{
		new_hostextinfo->icon_image=(char *)malloc(strlen(icon_image)+1);
		if(new_hostextinfo->icon_image==NULL){
			free(new_hostextinfo->notes_url);
			free(new_hostextinfo->host_name);
			free(new_hostextinfo);
			return ERROR;
	                }
		strcpy(new_hostextinfo->icon_image,icon_image);
	        }

	if(vrml_image==NULL || !strcmp(vrml_image,""))
		new_hostextinfo->vrml_image=NULL;
	else{
		new_hostextinfo->vrml_image=(char *)malloc(strlen(vrml_image)+1);
		if(new_hostextinfo->vrml_image==NULL){
			free(new_hostextinfo->icon_image);
			free(new_hostextinfo->notes_url);
			free(new_hostextinfo->host_name);
			free(new_hostextinfo);
			return ERROR;
	                }
		strcpy(new_hostextinfo->vrml_image,vrml_image);
	        }


	if(gd2_icon_image==NULL || !strcmp(gd2_icon_image,""))
		new_hostextinfo->gd2_icon_image=NULL;
	else{
		new_hostextinfo->gd2_icon_image=(char *)malloc(strlen(gd2_icon_image)+1);
		if(new_hostextinfo->gd2_icon_image==NULL){
			free(new_hostextinfo->vrml_image);
			free(new_hostextinfo->icon_image);
			free(new_hostextinfo->notes_url);
			free(new_hostextinfo->host_name);
			free(new_hostextinfo);
			return ERROR;
		        }
		strcpy(new_hostextinfo->gd2_icon_image,gd2_icon_image);
	        }


	if(icon_image_alt==NULL || !strcmp(icon_image_alt,""))
		new_hostextinfo->icon_image_alt=NULL;
	else{
		new_hostextinfo->icon_image_alt=(char *)malloc(strlen(icon_image_alt)+1);
		if(new_hostextinfo->icon_image_alt==NULL){
			free(new_hostextinfo->gd2_icon_image);
			free(new_hostextinfo->vrml_image);
			free(new_hostextinfo->icon_image);
			free(new_hostextinfo->notes_url);
			free(new_hostextinfo->host_name);
			free(new_hostextinfo);
			return ERROR;
		        }
		strcpy(new_hostextinfo->icon_image_alt,icon_image_alt);
	        }

	/* 2-D coordinates */
	new_hostextinfo->x_2d=x_2d;
	new_hostextinfo->y_2d=y_2d;
	new_hostextinfo->have_2d_coords=have_2d_coords;

	/* 3-D coordinates */
	new_hostextinfo->x_3d=x_3d;
	new_hostextinfo->y_3d=y_3d;
	new_hostextinfo->z_3d=z_3d;
	new_hostextinfo->have_3d_coords=have_3d_coords;

	/* default is to not draw this item */
	new_hostextinfo->should_be_drawn=FALSE;

	/* add new host extended info entry to head of list */
	new_hostextinfo->next=hostextinfo_list;
	hostextinfo_list=new_hostextinfo;

	return OK;
        }
	


/* adds an extended service info structure to the list in memory */
int add_extended_service_info(char *host_name,char *description, char *notes_url, char *icon_image, char *icon_image_alt){
	serviceextinfo *new_serviceextinfo;

	/* make sure we have what we need */
	if(host_name==NULL)
		return ERROR;
	if(!strcmp(host_name,""))
		return ERROR;
	if(description==NULL)
		return ERROR;
	if(!strcmp(description,""))
		return ERROR;

	/* allocate memory for a new data structure */
	new_serviceextinfo=(serviceextinfo *)malloc(sizeof(serviceextinfo));
	if(new_serviceextinfo==NULL)
		return ERROR;
				
	new_serviceextinfo->host_name=(char *)malloc(strlen(host_name)+1);
	if(new_serviceextinfo->host_name==NULL){
		free(new_serviceextinfo);
		return ERROR;
	        }
	strcpy(new_serviceextinfo->host_name,host_name);
				
	new_serviceextinfo->description=(char *)malloc(strlen(description)+1);
	if(new_serviceextinfo->description==NULL){
		free(new_serviceextinfo->host_name);
		free(new_serviceextinfo);
		return ERROR;
	        }
	strcpy(new_serviceextinfo->description,description);

	if(notes_url==NULL || !strcmp(notes_url,""))
		new_serviceextinfo->notes_url=NULL;
	else{
		new_serviceextinfo->notes_url=(char *)malloc(strlen(notes_url)+1);
		if(new_serviceextinfo->notes_url==NULL){
			free(new_serviceextinfo->description);
			free(new_serviceextinfo->host_name);
			free(new_serviceextinfo);
			return ERROR;
		        }
		strcpy(new_serviceextinfo->notes_url,notes_url);
	        }

	if(icon_image==NULL || !strcmp(icon_image,""))
		new_serviceextinfo->icon_image=NULL;
	else{
		new_serviceextinfo->icon_image=(char *)malloc(strlen(icon_image)+1);
		if(new_serviceextinfo->icon_image==NULL){
			free(new_serviceextinfo->notes_url);
			free(new_serviceextinfo->description);
			free(new_serviceextinfo->host_name);
			free(new_serviceextinfo);
			return ERROR;
	                }
		strcpy(new_serviceextinfo->icon_image,icon_image);
	        }

	if(icon_image_alt==NULL || !strcmp(icon_image_alt,""))
		new_serviceextinfo->icon_image_alt=NULL;
	else{
		new_serviceextinfo->icon_image_alt=(char *)malloc(strlen(icon_image_alt)+1);
		if(new_serviceextinfo->icon_image_alt==NULL){
			free(new_serviceextinfo->icon_image);
			free(new_serviceextinfo->notes_url);
			free(new_serviceextinfo->description);
			free(new_serviceextinfo->host_name);
			free(new_serviceextinfo);
			return ERROR;
		        }
		strcpy(new_serviceextinfo->icon_image_alt,icon_image_alt);
	        }

	/* add new service extended info entry to head of list */
	new_serviceextinfo->next=serviceextinfo_list;
	serviceextinfo_list=new_serviceextinfo;

	return OK;
        }
	


/******************************************************************/
/*********************** CLEANUP FUNCTIONS ************************/
/******************************************************************/

void free_extended_data(void){
	hostextinfo *this_hostextinfo;
	hostextinfo *next_hostextinfo;
	serviceextinfo *this_serviceextinfo;
	serviceextinfo *next_serviceextinfo;

	/* free memory for the extended host info list */
	for(this_hostextinfo=hostextinfo_list;this_hostextinfo!=NULL;this_hostextinfo=next_hostextinfo){
		next_hostextinfo=this_hostextinfo->next;
		free(this_hostextinfo->host_name);
		if(this_hostextinfo->notes_url!=NULL)
			free(this_hostextinfo->notes_url);
		if(this_hostextinfo->icon_image!=NULL)
			free(this_hostextinfo->icon_image);
		if(this_hostextinfo->vrml_image!=NULL)
			free(this_hostextinfo->vrml_image);
		if(this_hostextinfo->gd2_icon_image!=NULL)
			free(this_hostextinfo->gd2_icon_image);
		if(this_hostextinfo->icon_image_alt!=NULL)
			free(this_hostextinfo->icon_image_alt);
		free(this_hostextinfo);
	        }

	hostextinfo_list=NULL;

	/* free memory for the extended service info list */
	for(this_serviceextinfo=serviceextinfo_list;this_serviceextinfo!=NULL;this_serviceextinfo=next_serviceextinfo){
		next_serviceextinfo=this_serviceextinfo->next;
		free(this_serviceextinfo->host_name);
		free(this_serviceextinfo->description);
		if(this_serviceextinfo->notes_url!=NULL)
			free(this_serviceextinfo->notes_url);
		if(this_serviceextinfo->icon_image!=NULL)
			free(this_serviceextinfo->icon_image);
		free(this_serviceextinfo);
	        }

	serviceextinfo_list=NULL;

	return;
        }




/******************************************************************/
/************************ SEARCH FUNCTIONS ************************/
/******************************************************************/

/* find the extended information for a given host */
hostextinfo * find_hostextinfo(char *host_name){
	hostextinfo *temp_hostextinfo;

	for(temp_hostextinfo=hostextinfo_list;temp_hostextinfo!=NULL;temp_hostextinfo=temp_hostextinfo->next){
		if(!strcmp(host_name,temp_hostextinfo->host_name))
			return temp_hostextinfo;
	        }
	
	return NULL;
        }


/* find the extended information for a given service */
serviceextinfo * find_serviceextinfo(char *host_name, char *description){
	serviceextinfo *temp_serviceextinfo;

	for(temp_serviceextinfo=serviceextinfo_list;temp_serviceextinfo!=NULL;temp_serviceextinfo=temp_serviceextinfo->next){
		if(!strcmp(host_name,temp_serviceextinfo->host_name) && !strcmp(description,temp_serviceextinfo->description))
			return temp_serviceextinfo;
	        }
	
	return NULL;
        }
