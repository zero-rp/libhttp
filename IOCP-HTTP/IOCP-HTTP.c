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

#include "http_parser.h"
#include "url.h"
#include "sds.h"

#define TIMEOUT_KEEPLIVE	1000 * 60		//长连接超时

static LPFN_CONNECTEX lpfnConnectEx = NULL;
static LPFN_ACCEPTEX  lpfnAcceptEx = NULL;
static struct socket_server *default_server = NULL;
static http_parser_settings parser_settings;
//IOCP回调
typedef void(__stdcall* iocp_callback_dns)(struct socket_server * ss, void *ud, int state, char *ip);
typedef void(__stdcall* iocp_callback_connect)(struct socket_server * ss, void *ud, int state, int fd);
typedef void(__stdcall* iocp_callback_data)(struct socket_server * ss, void *ud, int state, char *data, uint32_t len);
typedef void(__stdcall* iocp_callback_free)(struct socket_server * ss, void *ud);
//HTTP回调
typedef void(__stdcall* http_callback_end)(struct http_request *request, void *ud);
typedef void(__stdcall* http_callback_body)(struct http_request *request, void *ud);
//IO服务定义
struct socket_server {
    //完成端口数据
    HANDLE CompletionPort;
    //socket池
    //定时队列
    HANDLE TimerQueue;
};
//DNS缓冲定义
//长连接池定义
//HTTP协议头定义
struct http_header {
    char *k;
    char *v;
    struct http_header *next;
};
//HTTP请求定义
struct http_request {
    //请求数据
    char *host;
    uint16_t port;

    uint8_t http_major;             //协议版本
    uint8_t http_minor;             //协议版本
    uint8_t ssl;                    //ssl协议
    uint8_t keep;                   //长连接
    char *method;                   //请求类型
    char *path;                     //请求路径
    struct http_header *header;     //请求头
    void *data;                     //提交数据
    uint32_t *dlen;                 //数据长度

    //应答数据
    http_parser parser;                     //http解析器
    struct http_header *response_header;    //请求头

    //内核数据
    HANDLE event;                   //同步事件
    uint8_t sync;                   //同步请求
    http_callback_end cb_end;       //完成回调
    http_callback_body cb_body;     //数据回调
    void *ud;                       //用户数据
    struct socket_server *server;   //执行请求的服务
};
//连接请求
struct request_connect {
    void *ud;
    iocp_callback_connect cb;
    SOCKET fd;
};
//接收数据请求
struct request_recv {
    WSABUF buf;
    size_t RecvBytes;   //实际接收长度
    SOCKET fd;
    void *ud;
    iocp_callback_data cb;
};
//关闭连接请求
struct request_close {
    SOCKET fd;
};
//发送数据请求
struct request_send {
    SOCKET fd;
    WSABUF buf;
    void *ud;
    iocp_callback_free free_cb;
};
//DNS解析
struct request_dns {
    struct socket_server *ss;
    ADDRINFOEX Hints;
    PADDRINFOEX QueryResults;
    HANDLE CancelHandle;
    void *ud;
    iocp_callback_dns cb;
};
//完成结构
typedef struct
{
    OVERLAPPED overlapped;      //系统对象
    uint32_t Type;              //请求类型
    union {
        char buffer[256];
        struct request_connect connect;
        struct request_recv recv;
        struct request_send send;
        struct request_close close;
        struct request_dns dns;
    } u;
}*LIO_DATA, IO_DATA;

//IOCP线程
static int __stdcall IOCP_Thread(struct socket_server * ss) {
    for (; ;)
    {
        void *lpContext = NULL;
        IO_DATA        *pOverlapped = NULL;
        DWORD            dwBytesTransfered = 0;
        BOOL bReturn = GetQueuedCompletionStatus(ss->CompletionPort, &dwBytesTransfered, (LPDWORD)&lpContext, (LPOVERLAPPED *)&pOverlapped, INFINITE);
        if (!pOverlapped)
            return 1;
        if (bReturn == 0) {
            //请求失败
            switch (pOverlapped->Type)
            {
            case 'C': //连接服务器
            {
                //关闭套接字
                closesocket(pOverlapped->u.connect.fd);
                break;
            }
            case 'R'://收到数据
            {
                //关闭套接字
                closesocket(pOverlapped->u.recv.fd);
                //回收缓冲
                free(pOverlapped->u.recv.buf.buf);
                break;
            }
            case 'S'://发送数据
            {
                //
                closesocket(pOverlapped->u.send.fd);

                free(pOverlapped->u.send.buf.buf);
            }
            case 'D': //DNS解析
            {

            }
            default:
                return 0;
                break;
            }
            goto _ret;
        }

        switch (pOverlapped->Type)
        {
        case 'C': //连接服务器
        {
            //连接成功,投递接收请求
            if (pOverlapped->u.connect.cb)
                pOverlapped->u.connect.cb(ss, pOverlapped->u.connect.ud, 0, pOverlapped->u.connect.fd);
            break;
        }
        case 'R'://收到数据
        {
            if (dwBytesTransfered == 0) {
                //被主动断开?

                free(pOverlapped->u.recv.buf.buf);
                closesocket(pOverlapped->u.recv.fd);
                break;
            }
            else {
                if (pOverlapped->u.recv.cb)
                    pOverlapped->u.recv.cb(ss, pOverlapped->u.recv.ud, 0, pOverlapped->u.recv.buf.buf, dwBytesTransfered);
            }


            //投递一个请求
            IO_DATA *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->Type = 'R';
            msg->u.recv.fd = pOverlapped->u.recv.fd;
            msg->u.recv.buf.len = 8192;
            msg->u.recv.buf.buf = malloc(8192);
            msg->u.recv.cb = pOverlapped->u.recv.cb;
            msg->u.recv.ud = pOverlapped->u.recv.ud;

            //投递一个接收请求
            DWORD dwBufferCount = 1, dwRecvBytes = 0, Flags = 0;
            if (WSARecv(pOverlapped->u.recv.fd, &msg->u.recv.buf, 1, &msg->u.recv.RecvBytes, &Flags, (LPWSAOVERLAPPED)msg, NULL) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err != WSA_IO_PENDING)
                {
                    //套接字错误
                    free(msg->u.recv.buf.buf);
                    free(msg);
                    //通知套接字错误

                }
            }
            break;
        }
        case 'S'://发送数据
        {
            if (pOverlapped->u.send.free_cb)
                pOverlapped->u.send.free_cb(ss, pOverlapped->u.send.ud);
            else
                free(pOverlapped->u.send.buf.buf);
            break;
        }


        case 'k'://关闭连接
        {
            closesocket(pOverlapped->u.close.fd);
            break;
        }
        case 'D': //DNS解析
        {

        }
        default:
            break;
        }
    _ret:
        //释放完成数据
        free(pOverlapped);
    }
}
//异步DNS回调
static VOID WINAPI QueryCompleteCallback(DWORD Error, DWORD Bytes, IO_DATA *Overlapped) {
    int ok = 0;
    PADDRINFOEX QueryResults = Overlapped->u.dns.QueryResults;
    while (QueryResults)
    {
        DWORD AddressStringLength = 64;
        CHAR AddrString[64];
        WSAAddressToStringA(QueryResults->ai_addr, (DWORD)QueryResults->ai_addrlen, NULL, AddrString, &AddressStringLength);
        if (AddressStringLength > 0) {
            if (Overlapped->u.dns.cb)
                Overlapped->u.dns.cb(Overlapped->u.dns.ss, Overlapped->u.dns.ud, 0, AddrString);
            ok = 1;
            break;
        }
        QueryResults = QueryResults->ai_next;
    }
    if (ok != 1) {
        if (Overlapped->u.dns.cb)
            Overlapped->u.dns.cb(Overlapped->u.dns.ss, Overlapped->u.dns.ud, -1, NULL);
    }
    if (Overlapped->u.dns.QueryResults)
    {
        FreeAddrInfoExW(Overlapped->u.dns.QueryResults);
    }
    //回收完成结构
    free(Overlapped);
}
//创建服务
__declspec(dllexport) struct socket_server * __stdcall IOCP_New() {
    struct socket_server *server = (struct socket_server *)malloc(sizeof(struct socket_server));
    memset(server, 0, sizeof(struct socket_server));
    //创建完成端口
    server->CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    //创建定时器
    server->TimerQueue = CreateTimerQueue();
    //启动iocp线程
    CreateThread(NULL, NULL, IOCP_Thread, server, NULL, NULL);

    return server;
}
//IOCP初始化
__declspec(dllexport) int __stdcall IOCP_Init() {
    static uint32_t is_init = 0;
    if (is_init)
        return 1;
    //初始化套接字
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(2, 2);
    WSAStartup(wVersionRequested, &wsaData);
    //获取函数地址
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

    DWORD dwBytes = 0;
    GUID GuidConnectEx = WSAID_CONNECTEX;
    if (SOCKET_ERROR == WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidConnectEx, sizeof(GuidConnectEx), &lpfnConnectEx, sizeof(lpfnConnectEx), &dwBytes, 0, 0))
    {
        return;
    }
    dwBytes = 0;
    GUID GuidAcceptEx = WSAID_ACCEPTEX;
    if (SOCKET_ERROR == WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidAcceptEx, sizeof(GuidAcceptEx), &lpfnAcceptEx, sizeof(lpfnAcceptEx), &dwBytes, 0, 0))
    {
        return;
    }
    closesocket(s);
    is_init = 1;
    return 1;
}
//IOCP主机解析
__declspec(dllexport) void __stdcall TOCP_Dns(struct socket_server * ss, char *name, iocp_callback_dns cb, void *ud) {
    //投递一个请求
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'D';
    msg->u.dns.ss = ss;
    msg->u.dns.cb = cb;
    msg->u.dns.ud = ud;
    msg->u.dns.Hints.ai_family = AF_INET;

    int len = MultiByteToWideChar(CP_OEMCP, 0, name, -1, NULL, 0);
    wchar_t *wstr = malloc(sizeof(wchar_t)*(len + 1));
    MultiByteToWideChar(CP_OEMCP, 0, name, -1, wstr, len);
    
    GetAddrInfoExW(wstr, NULL, NS_DNS, NULL, &msg->u.dns.Hints, &msg->u.dns.QueryResults, NULL, msg, QueryCompleteCallback, &msg->u.dns.CancelHandle);
    if (WSAGetLastError() != WSA_IO_PENDING)
    {
        //异常
    }
    free(wstr);
}
//IOCP连接服务器
__declspec(dllexport) void __stdcall TOCP_Connect(struct socket_server * ss, const char *host, int port, iocp_callback_dns cb, void *ud) {
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'C';
    msg->u.connect.ud = ud;
    msg->u.connect.cb = cb;
    //创建套接字
    SOCKET fd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSA_FLAG_OVERLAPPED);
    if (!fd) {


        return;
    }
    //绑定
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    int irt = bind(fd, (struct sockaddr *)(&local_addr), sizeof(struct sockaddr_in));
    //关联到完成端口
    CreateIoCompletionPort((HANDLE)fd, ss->CompletionPort, (ULONG_PTR)fd, 0);
    msg->u.connect.fd = fd;
    //异步连接
    struct sockaddr_in addrPeer;
    memset(&addrPeer, 0, sizeof(struct sockaddr_in));
    addrPeer.sin_family = AF_INET;
    addrPeer.sin_addr.s_addr = inet_addr(host);
    addrPeer.sin_port = htons(port);
    PVOID lpSendBuffer = NULL;
    lpfnConnectEx(fd, (struct sockaddr *)&addrPeer, sizeof(addrPeer), 0, 0, &lpSendBuffer, msg);
    return;
}
//IOCP开始接受数据
__declspec(dllexport) void __stdcall TOCP_Start(struct socket_server *ss, SOCKET fd, iocp_callback_data cb, void *ud) {
    //投递一个请求
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'R';
    msg->u.recv.fd = fd;
    msg->u.recv.buf.len = 8192;
    msg->u.recv.buf.buf = malloc(8192);
    msg->u.recv.cb = cb;
    msg->u.recv.ud = ud;

    //投递一个接收请求
    DWORD dwBufferCount = 1, dwRecvBytes = 0, Flags = 0;
    if (WSARecv(fd, &msg->u.recv.buf, 1, &msg->u.recv.RecvBytes, &Flags, (LPWSAOVERLAPPED)msg, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            //套接字错误
            free(msg->u.recv.buf.buf);
            free(msg);
        }
    }
}
//IOCP发送数据
__declspec(dllexport) void __stdcall TOCP_Send(struct socket_server *ss, SOCKET fd, void *buffer, int sz, iocp_callback_free cb, void *ud) {
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'S';
    msg->u.send.fd = fd;
    msg->u.send.buf.buf = buffer;
    msg->u.send.buf.len = sz;
    msg->u.send.free_cb = cb;
    msg->u.send.ud = ud;
    //投递一个发送请求
    DWORD dwSendBytes = 0, Flags = 0;
    if (WSASend(fd, &msg->u.send.buf, 1, &dwSendBytes, Flags, msg, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            //套接字错误

        }
    }
    return 0;
}
//IOCP反初始化
__declspec(dllexport) void __stdcall IOCP_UnInit() {

}


/* 异步回调处理 */
//事件_回收数据
static void __stdcall HTTP_CB_Free(struct socket_server * ss, sds s) {
    sdsfree(s);
}
//事件_接收
static void __stdcall HTTP_CB_Data(struct socket_server * ss, struct http_request *request, int state, char *data, uint32_t len) {
    uint32_t parsed = http_parser_execute(&request->parser, &parser_settings, data, len);
    if (parsed) {

    }
}
//事件_连接
static void __stdcall HTTP_CB_Connect(struct socket_server * ss, struct http_request *request, int state, int fd) {
    if (state) {
        //异常
    }
    //接收数据
    TOCP_Start(ss, fd, HTTP_CB_Data, request);
    //生成数据
    sds s = sdscatprintf(sdsempty(),
        "%s /%s HTTP/%d.%d\r\n",
        request->method, request->path ? request->path : "", request->http_major, request->http_minor);
    //添加请求头
    struct http_header *header = request->header;
    while (header)
    {
        s = sdscatprintf(s,
            "%s: %s\r\n",
            header->k, header->v);
        header = header->next;
    }
    //请求结束
    s = sdscatprintf(s,
        "\r\n");
    //发送数据
    TOCP_Send(ss, fd, s, sdslen(s), HTTP_CB_Free, s);
}
//事件_DNS
static void __stdcall HTTP_CB_Dns(struct socket_server * ss, struct http_request *request, int state, char *ip) {
    //获取ip
    if (state) {
        //异常

    }
    //连接服务器
    TOCP_Connect(ss, ip, request->port, HTTP_CB_Connect, request);
}

//HTTP解析回调
//消息完毕
static int on_message_complete(http_parser *p) {
    struct http_request *request = (struct http_request *)p->data;
    if (request->cb_end)
        request->cb_end(request, request->ud);
    return 0;
}
//解析到消息体
static int on_body(http_parser *p, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *)p->data;
	printf(buf);
    return 0;
}
//解析到头V
static int on_header_value(http_parser *p, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *)p->data;
    return 0;
}
//解析到头K
static int on_header_field(http_parser *p, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *)p->data;
    return 0;
}
//解析到url
static int on_url(http_parser *p, const char *buf, size_t len) {
    struct http_request *request = (struct http_request *)p->data;
    return 0;
}
//解析开始
static int on_message_begin(http_parser *p) {
    struct http_request *request = (struct http_request *)p->data;
    return 0;
}

//HTTP初始化
__declspec(dllexport) int __stdcall HTTP_Init() {
    static uint32_t is_init = 0;
    if (is_init)
        return 1;

    IOCP_Init();
    default_server = IOCP_New();

    //初始化http解析器
    memset(&parser_settings, 0, sizeof(parser_settings));

    parser_settings.on_message_complete = on_message_complete;
    parser_settings.on_body = on_body;
    parser_settings.on_header_value = on_header_value;
    parser_settings.on_header_field = on_header_field;
    parser_settings.on_url = on_url;
    parser_settings.on_message_begin = on_message_begin;

    is_init = 1;
    return 1;
}

//创建HTTP请求
__declspec(dllexport) struct http_request * __stdcall HTTP_Request_New(void *ud) {
    struct http_request *request = (struct http_request *)malloc(sizeof(struct http_request));
    if (!request)
        return NULL;
    memset(request, 0, sizeof(struct http_request));
    request->server = default_server;

    return request;
}
//调整选项
__declspec(dllexport) void __stdcall HTTP_Request_Option(struct http_request *request, char *k, char *v) {
    if (!request || !k || !v)
        return;

}
//设置请求头
__declspec(dllexport) void __stdcall HTTP_Request_SetHeader(struct http_request *request, char *k, char *v) {
    if (!request || !k || !v)
        return;
    struct http_header *header = request->header;
    struct http_header *header_old = header;
    while (header)
    {
        if (strcmp(header->k, k) == 0) {
            if (header->v)
                free(header->v);
            header->v = strdup(v);
        }
        header_old = header;
        header = header->next;
    }
    if (header_old == NULL)
    {
        request->header = malloc(sizeof(struct http_header));
        request->header->k = strdup(k);
        request->header->v = strdup(v);
        request->header->next = NULL;
    }
    else {
        header_old->next = malloc(sizeof(struct http_header));
        header_old->next->k = strdup(k);
        header_old->next->v = strdup(v);
        header_old->next->next = NULL;
    }
}
//打开请求
__declspec(dllexport) void __stdcall HTTP_Request_Open(struct http_request *request,char * method, char * url) {
    if (!request || !url)
        return;
    //解析地址
    url_field_t * u = url_parse(url);
    request->host = u->host;
    request->ssl = strcmp(u->schema, "https") == 0;
    if (u->port)
        request->port = u->port;
    else
        request->port = request->ssl ? 433 : 80;
    request->path = u->path;
    
    request->http_major = 1;
    request->http_minor = 1;
    request->method = strdup(method);
    
    HTTP_Request_SetHeader(request, "Host", request->host);
}
//发送请求
__declspec(dllexport) void __stdcall HTTP_Request_Send(struct http_request *request) {
    if (!request)
        return;
    //为同步请求创建事件
    if (request->event)
        request->event = CreateEventA(NULL, TRUE, FALSE, NULL);
    //准备解析器
    http_parser_init(&request->parser, HTTP_RESPONSE);
    request->parser.data = request;
    //解析DNS
    TOCP_Dns(request->server, request->host, HTTP_CB_Dns, request);

    //同步请求等待事件
    if (request->event) {
        WaitForSingleObject(request->event, INFINITE);
    }
}

//销毁请求
__declspec(dllexport) struct http_request * __stdcall HTTP_Request_Delete(struct http_request *request) {
    
    if (request->method)
        free(request->method);
    if (request->host)
        free(request->host);
    free(request);
}

//HTTP反初始化
__declspec(dllexport) void __stdcall HTTP_UnInit() {

}


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

