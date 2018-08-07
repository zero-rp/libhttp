#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "tree.h"
#include "dns.h"
#include "sds.h"
#include "socket.h"
#define htons(A) (uint16_t)((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define ntohs htons
//dns缓存
struct dns_cache {
    uint32_t ip;    //
    char *host;     //主机名
};
//DNS请求头
struct header {
    uint16_t    tid;        /* Transaction ID		*/
    uint16_t    flags;      /* Flags			*/
    uint16_t    nqueries;   /* Questions			*/
    uint16_t    nanswers;   /* Answers			*/
    uint16_t    nauth;      /* Authority PRs		*/
    uint16_t    nother;     /* Other PRs			*/
    unsigned char   data[1];/* Data, variable length	*/
};
//DNS查询树
struct dns_query {
    RB_ENTRY(dns_query) entry;
    uint16_t id;
    dns_callback cb;
    void *ud;
    uint16_t	qtype;		//查询类型
};
RB_HEAD(dns_query_tree, dns_query);
//默认socket服务
static struct socket_server *server = NULL;
static int udp_fd = 0;
static char **dns_ip;
static uint32_t dns_num;
static uint16_t dns_id = 1;
struct dns_query_tree query_tree = { 0 };   //查询列表

//QQ对象大小比较函数
static int dns_query_compare(struct dns_query *e1, struct dns_query *e2)
{
    return (e1->id < e2->id ? -1 : e1->id > e2->id);
}
RB_GENERATE_STATIC(dns_query_tree, dns_query, entry, dns_query_compare);

static void *__stdcall DNS_CB_Alloc(struct socket_server * ss, size_t len) {
    return malloc(len);
}
static void __stdcall DNS_CB_Send(struct socket_server * ss, void *ud) {
    free(ud);
}
void __stdcall DNS_CB_Data(struct socket_server * ss, void *ud, int state, char *pkt, uint32_t len) {
    struct header		*header;
    const unsigned char	*p, *e, *s;
    struct query		*q;
    uint32_t		ttl;
    uint16_t		type;
    char			name[1025];
    int			found, stop, dlen, nlen;

    header = (struct header *) pkt;
    if (ntohs(header->nqueries) != 1)
        return;

    //查询活动的查询ID

    struct dns_query the;
    the.id = header->tid;
    struct dns_query * c = RB_FIND(dns_query_tree, &query_tree, &the);
    if (c) {
        RB_REMOVE(dns_query_tree, &query_tree, c);
    }
    /* Received 0 answers */
    if (header->nanswers == 0) {

        return;
    }
    /* Skip host name */
    for (e = pkt + len, nlen = 0, s = p = &header->data[0];
        p < e && *p != '\0'; p++)
        nlen++;

#define	NTOHS(p)	(((p)[0] << 8) | (p)[1])

    /* We sent query class 1, query type 1 */
    if (&p[5] > e || NTOHS(p + 1) != c->qtype)
        return;

    /* Go to the first answer section */
    p += 5;

    /* Loop through the answers, we want A type answer */
    for (found = stop = 0; !stop && &p[12] < e; ) {

        /* Skip possible name in CNAME answer */
        if (*p != 0xc0) {
            while (*p && &p[12] < e)
                p++;
            p--;
        }

        type = htons(((uint16_t *)p)[1]);

        if (type == 5) {
            /* CNAME answer. shift to the next section */
            dlen = htons(((uint16_t *)p)[5]);
            p += 12 + dlen;
        }
        else if (type == c->qtype) {
            found = stop = 1;
        }
        else {
            stop = 1;
        }
    }

    if (found && &p[12] < e) {
        dlen = htons(((uint16_t *)p)[5]);
        p += 12;

        if (p + dlen <= e) {
            /* Add to the cache */
            (void)memcpy(&ttl, p - 6, sizeof(ttl));
            //q->expire = time(NULL) + (time_t)ntohl(ttl);

            ///* Call user */
            //if (q->qtype == DNS_MX_RECORD) {
            //    fetch((uint8_t *)header, p + 2,
            //        len, name, sizeof(name) - 1);
            //    p = (const unsigned char *)name;
            //    dlen = strlen(name);
            //}
            int addrlen = dlen;
            //if (q->addrlen > sizeof(q->addr))
            //    q->addrlen = sizeof(q->addr);
            //(void)memcpy(q->addr, p, q->addrlen);
            char ip[18] = { 0 };
            sprintf(ip, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
            c->cb(c->ud, 0, ip);
        }
    }
    if (c)
        free(c);
}

EXPORT void CALL gethostinfo(char *name, int cache, dns_callback cb, void *ud) {
    //查询缓存

    //生成查询包
    struct dns_query *query = NULL;
    struct header   *header;
    header = (struct header *) malloc(2056);

    for (size_t i = 0; i < 65535; i++)
    {
        struct dns_query the;
        the.id = dns_id;
        struct dns_query * c = RB_FIND(dns_query_tree, &query_tree, &the);
        if (c) {
            dns_id++;
        }
        else {
            //加入成员
            query = (struct dns_query*)malloc(sizeof(struct dns_query));
            memset(query, 0, sizeof(struct dns_query));
            query->id = dns_id;
            query->qtype = 0x01;//A记录
            query->cb = cb;
            query->ud = ud;
            RB_INSERT(dns_query_tree, &query_tree, query);
            dns_id++;
            break;
        }
    }
    header->tid = query->id;
    header->flags = htons(0x100);       /* Haha. guess what it is */
    header->nqueries = htons(1);        /* Just one query */
    header->nanswers = 0;
    header->nauth = 0;
    header->nother = 0;

    /* Encode DNS name */

    int n, i, name_len = strlen(name);
    char *p = (char *)&header->data;	/* For encoding host name into packet */
    const char 	*s;
    do {
        if ((s = strchr(name, '.')) == NULL)
            s = name + name_len;

        n = s - name;           /* Chunk length */
        *p++ = n;               /* Copy length */
        for (i = 0; i < n; i++) /* Copy chunk */
            *p++ = name[i];

        if (*s == '.')
            n++;

        name += n;
        name_len -= n;

    } while (*s != '\0');

    *p++ = 0;           /* Mark end of host name */
    *p++ = 0;           /* Well, lets put this byte as well */
    *p++ = (unsigned char)query->qtype;	/* 查询类型 A记录*/

    *p++ = 0;
    *p++ = 1;           /* Class: inet, 0x0001 */

    n = p - header;     /* 计算包长度 */


    //发送数据
    for (size_t i = 0; i < dns_num; i++)
    {
        char *s = malloc(n);
        memcpy(s, header, n);
        socket_udp_sendto(server, udp_fd, dns_ip[i], 53, s, n, DNS_CB_Send, s);
    }
    free(header);
}
EXPORT int CALL dns_init() {
    static int init = 0;
    if (init == 0) {
        //初始化套接字
        socket_init();
        //获取默认套接字服务
        server = socket_default();
        //获取DNS服务器列表
        uint32_t *list = (uint32_t*)malloc(sizeof(uint32_t) * 100);
        dns_num = socket_getdnsip(list, 100);
        dns_ip = (char **)malloc(sizeof(char *)*dns_num);
        //初始化缓存
        for (size_t i = 0; i < dns_num; i++)
        {
            dns_ip[i] = malloc(32);
            uint8_t *p = &list[i];
            sprintf(dns_ip[i], "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
        }
        //绑定本地DNS查询端口
        udp_fd = socket_udp_bind(server, "0.0.0.0", 0);
        //开始接收udp数据
        socket_udp_start(server, udp_fd, DNS_CB_Alloc, DNS_CB_Data, NULL);
    }
    init++;
}
EXPORT void CALL dns_uninit() {

}
