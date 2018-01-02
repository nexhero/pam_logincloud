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
/* Print log */
static void _pam_log(int err,const char *format, ...){
  va_list args;
  va_start(args, format);
  openlog(MODULE_NAME, LOG_CONS|LOG_PID,LOG_AUTH);
  vsyslog(err, format, args);
  va_end(args);
  closelog();
}

static int ctrl=0;

//read the arguments

static int _pam_parse(int argc, const char **argv){
  for(ctrl = 0; argc -- > 0; ++argv){
    if(!strcmp(*argv,"debug")){
      ctrl |= PAM_DEBUG_ARG;
    }else{
      _pam_log(LOG_ERR,"pam_parse: unknown option: %s",*argv);
    }
  }
  return ctrl;
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
  char line[128];
  char* str_data=NULL; // Buffer to store the string
  unsigned int size=0;
  char command[600]="/usr/bin/pwow ";
  int value=NULL;
  strcat(command,user);
  strcat(command," ");
  strcat(command,pass);
  
  if(! (pwow_file = popen(command, "r"""))){
    exit(1);
  }

  while (fgets(line,sizeof(line),pwow_file))
    {
      size+=strlen(line);
      strcat(str_data=realloc(str_data,size),line);
    }
  close(pwow_file);
  free(str_data);
  value = atoi(str_data);
  return value;
}

PAM_EXTERN  int pam_sm_authenticate(pam_handle_t *pamh,int flags, int argc, const char **argv){
  const char *username;
  const char *password;
  int retval =  PAM_AUTH_ERR;

  ctrl = _pam_parse(argc,argv);

  // get the username from pam

  retval = pam_get_user(pamh, &username,NULL);
  if((retval != PAM_SUCCESS) || (!username)){
    if(ctrl & PAM_DEBUG_ARG){
      _pam_log(LOG_DEBUG,"can't get the username");
      return PAM_SERVICE_ERR;
    }
  }

  // get the password

  retval = pam_get_item(pamh, PAM_AUTHTOK,(const void **)&password);
  if( retval != PAM_SUCCESS){
    _pam_log(LOG_ERR, "Couln't retrive user's passwrod");
    return -2;
  }

  retval = check_user(username,password);
  switch(retval){
  case -1:
    _pam_log(LOG_ERR,"Connection to the server failed");
    return PAM_SERVICE_ERR;
  case 0:
    _pam_log(LOG_NOTICE, "granted access");
    return PAM_SUCCESS;
  case 1:
    _pam_log(LOG_ERR,"Couln't validate username or password");
    return PAM_AUTH_ERR;
  default:
    _pam_log(LOG_ERR,"internal module error");
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

