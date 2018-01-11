#include <security/pam_appl.h>

// Defie arguments

#define PAM_DEBUG_ARG 0x0001

// Define the name of the module.
#ifndef MODULE_NAME
#define MODULE_NAME "pam_logincloud"
#endif
int conversation(pam_handle_t *);
