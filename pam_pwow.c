
/*

  Created by: David Pereira - inexhero@gamil.com

  This is a pam module to to login into the system using the owncloud database.
  Some function are based in the project pam_userdb: https://github.com/Broadcom/stblinux-3.8/tree/master/uclinux-rootfs/lib/libpam/modules/pam_userdb
 */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "pam_pwow.h"
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <security/_pam_macros.h>


static int converse(pam_handle_t *pamh,
		    struct pam_message **message,
		    struct pam_response **response)
{
  int retval;
  const struct pam_conv *conv;

  retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv ) ;
  if (retval == PAM_SUCCESS)
    retval = conv->conv(1, (const struct pam_message **)message,
			response, conv->appdata_ptr);
	
  return retval;
}


static char *_pam_delete(register char *xx)
{
  _pam_overwrite(xx);
  _pam_drop(xx);
  return NULL;
}

/*
 * This is a conversation function to obtain the user's password
 */
int conversation(pam_handle_t *pamh)
{
  struct pam_message msg[2],*pmsg[2];
  struct pam_response *resp;
  int retval;
  char * token = NULL;
    
  pmsg[0] = &msg[0];
  msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
  msg[0].msg = "Password: ";

  /* so call the conversation expecting i responses */
  resp = NULL;
  retval = converse(pamh, pmsg, &resp);

  if (resp != NULL) {
    const char * item;
    /* interpret the response */
    if (retval == PAM_SUCCESS) {     /* a good conversation */
      token = x_strdup(resp[0].resp);
      if (token == NULL) {
	return PAM_AUTHTOK_RECOVER_ERR;
      }
    }

    /* set the auth token */
    retval = pam_set_item(pamh, PAM_AUTHTOK, token);
    token = _pam_delete(token);   /* clean it up */
    if ( (retval != PAM_SUCCESS) ||
	 (retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&item))
	 != PAM_SUCCESS ) {
      return retval;
    }
	
    _pam_drop_reply(resp, 1);
  } else {
    retval = (retval == PAM_SUCCESS)
      ? PAM_AUTHTOK_RECOVER_ERR:retval ;
  }

  return retval;
}

/* Print log */
static void _pam_log(int err,const char *format, ...){
  va_list args;
  va_start(args, format);
  openlog(MODULE_NAME, LOG_CONS|LOG_PID,LOG_AUTH);
  vsyslog(err, format, args);
  va_end(args);
  closelog();
}

/*
  Check de user and password on the owncloud server

  return values:
  -1 = Conecction to the server failed =/
  0 - OK! :D
  1 = username or password failed :(
*/

int check_user(const char* user, const char* pass){
  FILE *pwow_file;
  char returned_value[5];
  unsigned int size=0;
  char command[600]="/usr/bin/pwow ";
  int value=NULL;
  strcat(command,user);
  strcat(command," ");
  strcat(command,pass);
  
  if(! (pwow_file = popen(command, "r"""))){
    exit(1);
  }

  if(fgets(returned_value,sizeof(returned_value),pwow_file)){
  }

  close(pwow_file);
  value = atoi(returned_value);
  return value;
}

// Check if the user alreadu exists in the local system.
int check_user_passwd(const char* user){
  FILE *command_grep;
  char returned_value[5];
  unsigned int size=0;
  char command[600]="/bin/grep -c '^";
  int value=NULL;
  strcat(command,user);
  strcat(command,":' /etc/passwd");
  
  
  if(! (command_grep = popen(command, "r"""))){
    exit(1);
  }

  if(fgets(returned_value,sizeof(returned_value),command_grep)){
  }

  close(command_grep);
  value = atoi(returned_value);
  return value;
}

//Create new user in the local system.
void create_local_user(const char* username, const char* password){

  //add new user
  char command[200] = "/usr/sbin/useradd ";
  strcat(command,username);
  strcat(command, " -m");
  system(command);

  //assing the password to the new user
  char u_pw[200] = "echo ";
  strcat(u_pw,username);
  strcat(u_pw, ":");
  strcat(u_pw,password);
  strcat(u_pw, " | chpasswd");
  system(u_pw);
}

//update the passowrd in the local user.
void update_local_password(const char* username, const char* password){
  char u_pw[200] = "echo ";
  strcat(u_pw,username);
  strcat(u_pw, ":");
  strcat(u_pw,password);
  strcat(u_pw, " | chpasswd");
  system(u_pw);

}
PAM_EXTERN  int pam_sm_authenticate(pam_handle_t *pamh,int flags, int argc, const char **argv){
  const char *username;
  const char *password;
  int retval =  PAM_AUTH_ERR;

  // get the username from pam
  
  retval = pam_get_user(pamh, &username,NULL);
  if((retval != PAM_SUCCESS) || (!username)){
    if(PAM_DEBUG_ARG){
      _pam_log(LOG_DEBUG,"can't get the username");
      return PAM_SERVICE_ERR;
    }
  }

  // get the password
  retval = conversation(pamh);
  if (retval != PAM_SUCCESS) {
    _pam_log(LOG_ERR, "could not obtain password for `%s'",
	     username);
    return -2;
  }
  retval = pam_get_item(pamh, PAM_AUTHTOK,(const void **)&password);
  if( retval != PAM_SUCCESS){
    _pam_log(LOG_ERR, "Couln't retrive user's passwrod");
    return -2;
  }


  //validate username and password.
  retval = check_user(username,password);
  switch(retval){
  case -1:
    _pam_log(LOG_ERR,"Connection to the server failed");
    return PAM_SERVICE_ERR;
  case 0:
    _pam_log(LOG_NOTICE, "Granted access");
    if(!check_user_passwd(username)){
      create_local_user(username,password);
      _pam_log(LOG_NOTICE, "New used added %s",username);
    }else{
      update_local_password(username,password);
      _pam_log(LOG_NOTICE,"Password updated for %s",username);
    }
    return PAM_SUCCESS;
  case 1:
    _pam_log(LOG_ERR,"Couln't validate username or password");
    return PAM_AUTH_ERR;
  default:
    _pam_log(LOG_ERR,"Internal module error");
    return PAM_SERVICE_ERR;
  }
  return PAM_IGNORE;
}
PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  return PAM_SUCCESS;
}

