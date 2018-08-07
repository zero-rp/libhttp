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
#include <iphlpapi.h>

static LPFN_CONNECTEX lpfnConnectEx = NULL;
static LPFN_ACCEPTEX lpfnAcceptEx = NULL;
static LPFN_DISCONNECTEX lpfnDisconnectEx = NULL;
static struct socket_pool *spool = NULL;
static struct socket_server *default_server = NULL; 
//Socket节点定义
struct socket_node {
    SOCKET fd;
    struct socket_node *next;
};
//Socket池定义
struct socket_pool
{
    int lock;
    struct socket_node *tail;
    struct socket_node *head;
};

//IO服务定义
struct socket_server {
    //完成端口数据
    HANDLE CompletionPort;
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
    socket_callback_alloc alloc_cb;
    socket_callback_data data_cb;
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
    socket_callback_send cb;
};
//接收数据报请求
struct request_recvfrom {
    WSABUF buf;         //
    int fd;
    void *ud;
    socket_callback_alloc alloc_cb;
    socket_callback_data_udp data_cb;
    size_t RecvBytes;   //实际接收长度
    struct sockaddr_in remote_addr;
    int remote_addr_len;      //存储数据来源IP地址长度
};
//发送数据报请求
struct request_sendfrom {
    int fd;
    void *ud;
    socket_callback_send cb;
    struct sockaddr_in remote_addr;
    WSABUF buf;
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
        struct request_recvfrom recvfrom;
        struct request_sendfrom sendfrom;
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
    dwBytes = 0;
    GUID GuidDisconnectEx = WSAID_DISCONNECTEX;
    if (SOCKET_ERROR == WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidDisconnectEx, sizeof(GuidDisconnectEx), &lpfnDisconnectEx, sizeof(lpfnDisconnectEx), &dwBytes, 0, 0))
    {
        return -1;
    }
    closesocket(s);
    //初始化连接池
    spool = (struct socket_pool *)malloc(sizeof(struct socket_pool));
    memset(spool, 0, sizeof(struct socket_pool));

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
                if (pOverlapped->u.recv.data_cb)
                    pOverlapped->u.recv.data_cb(ss, pOverlapped->u.recv.ud, 0, pOverlapped->u.recv.buf.buf, dwBytesTransfered);
            }


            //投递一个请求
            IO_DATA *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->Type = 'R';
            msg->u.recv.fd = pOverlapped->u.recv.fd;
            msg->u.recv.buf.len = 8192;
            msg->u.recv.buf.buf = pOverlapped->u.recv.alloc_cb(ss, 8192);
            msg->u.recv.alloc_cb = pOverlapped->u.recv.alloc_cb;
            msg->u.recv.data_cb = pOverlapped->u.recv.data_cb;
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
        case 'f'://收到UDP数据
        {
            if (pOverlapped->u.recvfrom.data_cb)
                pOverlapped->u.recvfrom.data_cb(ss, pOverlapped->u.recvfrom.ud, 0, pOverlapped->u.recvfrom.buf.buf, dwBytesTransfered);

            //继续投递请求
            IO_DATA *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->Type = 'f';
            msg->u.recvfrom.ud = pOverlapped->u.recvfrom.ud;
            msg->u.recvfrom.fd = pOverlapped->u.recvfrom.fd;
            msg->u.recvfrom.alloc_cb = pOverlapped->u.recvfrom.alloc_cb;
            msg->u.recvfrom.data_cb = pOverlapped->u.recvfrom.data_cb;
            msg->u.recvfrom.buf.len = 8192;
            msg->u.recvfrom.buf.buf = pOverlapped->u.recvfrom.alloc_cb(ss, 8192);
            msg->u.recvfrom.remote_addr_len = sizeof(msg->u.recvfrom.remote_addr);
            DWORD Flags = 0;
            if (WSARecvFrom(pOverlapped->u.recvfrom.fd, &msg->u.recvfrom.buf, 1, &msg->u.recvfrom.RecvBytes, &Flags, (SOCKADDR*)&(msg->u.recvfrom.remote_addr), &(msg->u.recvfrom.remote_addr_len), msg, NULL) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err != WSA_IO_PENDING)
                {
                    //套接字错误
                    free(msg->u.recvfrom.buf.buf);
                    free(msg);
                    //通知套接字错误

                }
            }
            break;
            break;
        }
        case 'S'://发送数据
        {
            if (pOverlapped->u.send.cb)
                pOverlapped->u.send.cb(ss, pOverlapped->u.send.ud);
            else
                free(pOverlapped->u.send.buf.buf);
            break;
        }
        case 't':
        {
            if (pOverlapped->u.sendfrom.cb)
                pOverlapped->u.sendfrom.cb(ss, pOverlapped->u.sendfrom.ud);
            else
                free(pOverlapped->u.sendfrom.buf.buf);
            break;
        }
        case 'k'://关闭连接
        {
            //加入连接池
            struct socket_node * node = (struct socket_node *)malloc(sizeof(struct socket_node));
            node->fd = pOverlapped->u.close.fd;
            node->next = NULL;
            for (; 0 != InterlockedExchange(&spool->lock, 1);) {}
            struct socket_node * tail = spool->tail;
            spool->tail = node;
            if (spool->head == NULL) {
                spool->head = node;
            }
            else {
                tail->next = node;
            }
            InterlockedExchange(&spool->lock, 0);
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
    SOCKET fd = 0;
    struct socket_node *node = NULL;
    //从池内查找
    for (; 0 != InterlockedExchange(&spool->lock, 1);) {}
    if (spool->head) {
        node = spool->head;
        spool->head = node->next;
    }
    InterlockedExchange(&spool->lock, 0);
    if (node != NULL) {
        fd = node->fd;
        free(node);
    }
    //创建套接字
    if (fd == NULL) {
        fd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSA_FLAG_OVERLAPPED);
        if (!fd) {


            return;
        }
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
EXPORT void CALL socket_tcp_start(struct socket_server *ss, int fd, socket_callback_alloc alloc_cb, socket_callback_data data_cb, void *ud) {
    //投递一个请求
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'R';
    msg->u.recv.fd = fd;
    msg->u.recv.buf.len = 8192;
    msg->u.recv.buf.buf = alloc_cb(ss, 8192);
    msg->u.recv.alloc_cb = alloc_cb;
    msg->u.recv.data_cb = data_cb;
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
EXPORT void CALL socket_tcp_send(struct socket_server *ss, int fd, void *buffer, int sz, socket_callback_send cb, void *ud) {
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'S';
    msg->u.send.fd = fd;
    msg->u.send.buf.buf = buffer;
    msg->u.send.buf.len = sz;
    msg->u.send.cb = cb;
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
//IOCP关闭连接
EXPORT void CALL socket_tcp_close(struct socket_server *ss, int fd) {
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'k';
    msg->u.close.fd = fd;
    //投递一个发送请求
    DWORD dwSendBytes = 0, Flags = 0;
    if (lpfnDisconnectEx(fd, msg, Flags, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            //套接字错误

        }
    }
    return 0;
}
//IOCP绑定UDP端口
EXPORT int CALL socket_udp_bind(struct socket_server * ss, const char *host, int port) {
    SOCKET fd = 0;
    struct socket_node *node = NULL;
    //从池内查找
    for (; 0 != InterlockedExchange(&spool->lock, 1);) {}
    if (spool->head) {
        node = spool->head;
        spool->head = node->next;
    }
    InterlockedExchange(&spool->lock, 0);
    if (node != NULL) {
        fd = node->fd;
        free(node);
    }
    //创建套接字
    if (fd == NULL) {
        fd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL, WSA_FLAG_OVERLAPPED);
        if (!fd) {


            return 0;
        }
    }
    //绑定
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    int irt = bind(fd, (struct sockaddr *)(&local_addr), sizeof(struct sockaddr_in));
    //关联到完成端口
    CreateIoCompletionPort((HANDLE)fd, ss->CompletionPort, (ULONG_PTR)fd, 0);

    return fd;
}
//IOCP开始接收UDP数据
EXPORT void CALL socket_udp_start(struct socket_server * ss, int fd, socket_callback_alloc alloc_cb, socket_callback_data_udp data_cb, void *ud) {
    //投递一个接收请求
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 'f';
    msg->u.recvfrom.ud = ud;
    msg->u.recvfrom.fd = fd;
    msg->u.recvfrom.alloc_cb = alloc_cb;
    msg->u.recvfrom.data_cb = data_cb;
    msg->u.recvfrom.buf.len = 8192;
    msg->u.recvfrom.buf.buf = alloc_cb(ss, 8192);
    msg->u.recvfrom.remote_addr_len = sizeof(msg->u.recvfrom.remote_addr);
    DWORD Flags = 0;
    if (WSARecvFrom(fd, &msg->u.recvfrom.buf, 1, &msg->u.recvfrom.RecvBytes, &Flags, (SOCKADDR*)&(msg->u.recvfrom.remote_addr), &(msg->u.recvfrom.remote_addr_len), msg, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            //套接字错误

        }
    }
}
//IOCP发送UDP数据包
EXPORT void CALL socket_udp_sendto(struct socket_server * ss,int fd, const char *host, int port, void *buffer, size_t len, socket_callback_send cb, void *ud) {
    IO_DATA *msg = malloc(sizeof(*msg));
    memset(msg, 0, sizeof(*msg));
    msg->Type = 't';
    msg->u.sendfrom.ud = ud;
    msg->u.sendfrom.fd = fd;
    msg->u.sendfrom.cb = cb;
    msg->u.sendfrom.buf.buf = buffer;
    msg->u.sendfrom.buf.len = len;
    //投递一个发送请求
    DWORD dwSendBytes = 0, Flags = 0;
    msg->u.sendfrom.remote_addr.sin_family = AF_INET;
    msg->u.sendfrom.remote_addr.sin_addr.S_un.S_addr = inet_addr(host);
    msg->u.sendfrom.remote_addr.sin_port = (uint16_t)((((uint16_t)(port) & 0xff00) >> 8) | (((uint16_t)(port) & 0x00ff) << 8));
    if (WSASendTo(fd, &msg->u.sendfrom.buf, 1, &dwSendBytes, Flags, &msg->u.sendfrom.remote_addr, sizeof(msg->u.sendfrom.remote_addr), msg, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING)
        {
            //套接字错误

        }
    }
}
//获取dns列表
EXPORT int CALL socket_getdnsip(uint32_t *list, int size)
{
    DWORD dwRetVal = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 15000;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;

    int pos = 0;
    if (list == NULL)
        return 0;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
        if (pAddresses == NULL) {
            return 0;
        }
        dwRetVal =GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = NULL;
        }
        else {
            break;
        }
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW));

    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            //只处理正常接口
            if (pCurrAddresses->OperStatus != IfOperStatusUp) {
                pCurrAddresses = pCurrAddresses->Next;
                continue;
            }
            pDnServer = pCurrAddresses->FirstDnsServerAddress;
            while (pDnServer)
            {
                //只处理IPV4
                if (pDnServer->Address.lpSockaddr->sa_family == AF_INET)
                    list[pos] = (uint32_t)(((struct sockaddr_in *)pDnServer->Address.lpSockaddr)->sin_addr.S_un.S_addr);
                pos++;
                pDnServer = pDnServer->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    else {
        //没有获取到网卡
    }

    if (pAddresses) {
        free(pAddresses);
    }
    return pos;
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
    for (size_t i = 0; i < 10; i++)
    {
        CreateThread(NULL, NULL, IOCP_Thread, server, NULL, NULL);
    }
    return server;
}
//获取默认服务
EXPORT struct socket_server * CALL socket_default() {
    if (default_server == NULL)
        default_server = socket_new();
    return default_server;
}
//释放服务
EXPORT void CALL socket_delete(struct socket_server *server) {
    
    
    CloseHandle(server->CompletionPort);
    DeleteTimerQueue(server->TimerQueue);
    free(server);
}
