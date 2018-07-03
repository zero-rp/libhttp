#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "socket.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <ws2tcpip.h>

static LPFN_CONNECTEX lpfnConnectEx = NULL;
static LPFN_ACCEPTEX  lpfnAcceptEx = NULL;


//IO服务定义
struct socket_server {
    //完成端口数据
    HANDLE CompletionPort;
    //socket池
    //定时队列
    HANDLE TimerQueue;
};
//连接请求
struct request_connect {
    void *ud;
    socket_callback_connect cb;
    SOCKET fd;
};
//接收数据请求
struct request_recv {
    WSABUF buf;
    size_t RecvBytes;   //实际接收长度
    SOCKET fd;
    void *ud;
    socket_callback_data cb;
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
    socket_callback_free free_cb;
};
//DNS解析
struct request_dns {
    struct socket_server *ss;
    ADDRINFOEX Hints;
    PADDRINFOEX QueryResults;
    HANDLE CancelHandle;
    void *ud;
    socket_callback_dns cb;
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

EXPORT int CALL socket_init() {
    static uint32_t is_init = 0;
    if (is_init)
        return 0;
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
        return -1;
    }
    dwBytes = 0;
    GUID GuidAcceptEx = WSAID_ACCEPTEX;
    if (SOCKET_ERROR == WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidAcceptEx, sizeof(GuidAcceptEx), &lpfnAcceptEx, sizeof(lpfnAcceptEx), &dwBytes, 0, 0))
    {
        return -1;
    }
    closesocket(s);
    is_init = 1;
    return 0;
}

EXPORT void CALL socket_uninit() {

    WSACleanup();
}

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

//IOCP主机解析
EXPORT void CALL socket_dns(struct socket_server * ss, char *name, socket_callback_dns cb, void *ud) {
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
EXPORT void CALL socket_tcp_connect(struct socket_server * ss, const char *host, int port, socket_callback_dns cb, void *ud) {
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
EXPORT void CALL socket_tcp_start(struct socket_server *ss, int fd, socket_callback_data cb, void *ud) {
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
EXPORT void CALL socket_tcp_send(struct socket_server *ss, int fd, void *buffer, int sz, socket_callback_free cb, void *ud) {
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
//创建服务
EXPORT struct socket_server * CALL socket_new() {
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
EXPORT void CALL socket_delete(struct socket_server *server) {
    
    
    CloseHandle(server->CompletionPort);
    DeleteTimerQueue(server->TimerQueue);
    free(server);
}

