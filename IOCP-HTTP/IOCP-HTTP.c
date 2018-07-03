// IOCP-HTTP.cpp: 定义控制台应用程序的入口点。
//

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <ws2tcpip.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "http.h"

#define TIMEOUT_KEEPLIVE	1000 * 60		//长连接超时










int main()
{
    HTTP_Init();
    //for (size_t i = 0; i < 1; i++)
    //{
        struct http_request *request = HTTP_Request_New(NULL);
        HTTP_Request_Open(request, "GET", "http://www.baidu.com");
        //HTTP_Request_SetHeader(request, "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.15 Safari/537.36");
        HTTP_Request_Send(request);
    //}

    scanf("%s");
    return 0;
}

