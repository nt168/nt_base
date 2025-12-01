#include "common.h"
#include "nt_log.h"
#include "nt_mutexs.h"

const char	*progname = NULL;
const char	syslog_app_name[] = "nt_base";
char *CONFIG_PID_FILE = "/tmp/pt_server.pid";

pthread_t tid;
int	CONFIG_LOG_LEVEL = LOG_LEVEL_WARNING;
extern char	*CONFIG_LOG_FILE;
extern int CONFIG_LOG_TYPE;
int main()
{

	char *error = NULL;

	if (SUCCEED != nt_locks_create(&error))
	{
		nt_error("cannot create locks: %s", error);
		nt_free(error);
		exit(EXIT_FAILURE);
	}

	if (SUCCEED != nt_open_log(CONFIG_LOG_TYPE, CONFIG_LOG_LEVEL, CONFIG_LOG_FILE, &error))
	{
		nt_error("cannot open log: %s", error);
		nt_free(error);
		exit(EXIT_FAILURE);
	}

//	nt_log(LOG_LEVEL_TRACE, "Starting Nt Server. Nt %s (revision %s).", "1.5", ".007");
	nt_log(LOG_LEVEL_WARNING, "Starting Nt Server. Nt %s (revision %s).", "1.5", ".007");
	return 0;
}
