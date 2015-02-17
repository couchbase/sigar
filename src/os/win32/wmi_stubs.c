#include "sigar.h"
#include "sigar_private.h"
#include "sigar_pdh.h"
#include "sigar_os.h"
#include "sigar_util.h"
#include "sigar_format.h"

int sigar_proc_args_wmi_get(sigar_t *sigar, sigar_pid_t pid,
                            sigar_proc_args_t *procargs)
{
    return ERROR_NOT_FOUND;
}

int sigar_proc_exe_wmi_get(sigar_t *sigar, sigar_pid_t pid,
                           sigar_proc_exe_t *procexe)
{
    return ERROR_NOT_FOUND;
}
