/*
*
*   H264Analyzer
*   20170629
*
*
*/

/*
   gcc H264Analyzer.c H264AnalyzerUtils.c H264AnalyzerLog.c -lm -w -o H264Analyzer
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "H264Analyzer.h"
#include "H264AnalyzerUtils.h"
#include "H264AnalyzerLog.h"


//#define TEST

int main(int argc, char* *argv)
{
	FILE *fpInputFile = NULL, *fpOutputTSFile = NULL, *fpOutputNonTsFile = NULL;
	int InputFileSize = 0, offset = 0, nal_number = 0, IDR_number = 0, ret = 0, count = 0, len = 0, i = 0;
	unsigned char *pLargeBuf = NULL, *pDetect = NULL;
	H264_Context *h264_context = NULL;

	if(argc <= 1)
	{
		return 0;
	}

	fpInputFile = fopen(argv[1], "r");
	if(NULL == fpInputFile)
	{
		an_log(H264MODULE_NAL, AN_LOG_INFO, "Open %s fail.\n", argv[1]);		
		return 0;
	}
	//获取文件大小
	fseek(fpInputFile, 0L, SEEK_END);
	InputFileSize = ftell(fpInputFile);
	fseek(fpInputFile, 0L, SEEK_SET);

	pLargeBuf = malloc(InputFileSize);	
	memset(pLargeBuf, 0, InputFileSize);	
	fread(pLargeBuf, InputFileSize, 1, fpInputFile);

	h264_context = malloc(sizeof(H264_Context));
	memset(h264_context, 0, sizeof(H264_Context));
	offset = 0;
	while(offset < InputFileSize)
	{
		/*找nal头*/
		for(	; offset + 3 < InputFileSize; offset++)
		{
			if(0x0 == pLargeBuf[offset]  && 0x0 == pLargeBuf[offset + 1] && 0x0 == pLargeBuf[offset + 2] && 0x1 == pLargeBuf[offset + 3])
				break;
		}

		i = offset + 4;
		if(i + 3 >= InputFileSize)
			/*不足一个nal头的长度*/
			break;
		/*找下一个nal头*/
		for( ; i + 3 < InputFileSize; i++)
		{
			if(0x0 == pLargeBuf[i]  && 0x0 == pLargeBuf[i + 1] && 0x0 == pLargeBuf[i + 2] && 0x1 == pLargeBuf[i + 3])
				break;
		}
		if(i + 3 == InputFileSize)
		{
			/*已经到了码流末尾*/
			len = InputFileSize - offset;
		}
		else
		{
			/*下一个nal头还存在*/
			len = i - offset;
		}
		
		ret = parse_nal(pLargeBuf + offset, len, h264_context);
		an_log(H264MODULE_NAL, AN_LOG_INFO, "parse_nal ret = %d\n", ret);
		if(ret < 0)
		{
			break;
		}
		offset += len;
		nal_number++;
		//sleep(1);
		if(5 == h264_context->nal_unit->nal_unit_type)
			IDR_number++;
#ifdef TEST		
		count++;
		if(count >= 30)
			break;
#endif
	}

	an_log(H264MODULE_NAL, AN_LOG_INFO, "\n IDR_number = %d.\n", IDR_number);
	fclose(fpInputFile);

	return 0;
}
