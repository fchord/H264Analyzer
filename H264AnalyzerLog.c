#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include "H264AnalyzerLog.h"

#define LOGLEVEL AN_LOG_TRACE //AN_LOG_TRACE//AN_LOG_DEBUG


void an_log(const char *module, int level, const char* format, ...)
{
	va_list args;
	char szDebugBuf[PRINTF_BUF_LEN];

	if(level > LOGLEVEL)
		return ;
	if(NULL != module && NULL != strstr(H264MODULE_UNKOWN, module))
		return ;
	va_start(args, format);
	//va_arg ( args, type ); 
	if(NULL != module)
		printf("%s: ", module);
	vsprintf(szDebugBuf,format, args);	
	va_end(args); 
	printf(szDebugBuf); 
	return ;
}

