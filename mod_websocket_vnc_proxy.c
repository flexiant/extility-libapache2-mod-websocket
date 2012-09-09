/*
 * Copyright 2012 Flexiant Ltd
 *
 * Written by Alex Bligh, based upon the dumb_increment_protocol
 * example for apache-websocket, written by self.disconnect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The system OPTIONALLY allows for use with an intermediate proxy (referred
 * to as the 'cluster') which will forward the onbound connection to its
 * ultimate destination (referred to as the 'node'). This feature is
 * activated by the WebSocketTcpProxySendInitialData directive, so called
 * as the outbound session has initial data added which is a cryptographically
 * signed instruction to the cluster proxy as to where to forward the
 * onbound TCP session.
 *
 * The system OPTIONALLY allows for dyanmic configuration of vnc port forwards looked
 * up with an arbitrary key. The key can be composed of any base64 letters plus
 * underscores and minus sigs. 
 *
 * The user can specify a statement (likely to be SELECT
 * in an SQL environment) which returns data providing the vnc proxy paaramters
 * associated with that particular hardware address.
 *
 * The query is the SELECT statement passed to the SQL backend, into which
 * the following are substituted sprintf style paramaters. Currently only
 * one parameter is passed, thus use
 *     %s : the key
 *     %% : a percent sign
 *
 * The query does not need a trailing semicolon. Be careful that quotes in the
 * query do not interfere with quotes in the config file.
 *
 * If no rows are returned, the connection will be rejected. If more than one
 * row is returned, the first row will be used to connect to.
 *
 * Columns returned should be
 *     * the node IP address to connect to - nodehost
 *     * and node port number - nodeport
 *     * the cluster proxy IP address - clusterhost
 *     * the cluster proxy port - cluster port
 *
 * For example, if the table 'vnc' contained columns vncnodehost, vncnodeport
 * vncclusterhost, vncclusterport, and vncclusterkey,  corresponding to ip and port
 * address of the node, the ip and port of the cluster proxy, and the key,
 * the following query might be used:
 *
 *     SELECT vncnodehost AS 'nodehost', vncnodeport AS 'nodeport',
 *            vncclusterhost AS 'clusterhost', vncclusterport AS 'clusterport'
 *            FROM vnc WHERE vnckey='%s'
 */

#include <stdio.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_thread_proc.h"
#include "apr_base64.h"
#include "apr_strings.h"
#include "apr_dbd.h"
#include "apr_random.h"
#include "mod_dbd.h"

#include "websocket_plugin.h"

#define APACHELOG(severity, handle, message...) ap_log_error(APLOG_MARK, APLOG_NOERRNO | severity, 0, handle->server, message)

#define VNCHEADERMAGIC 0xAB15AB1E
#define VNCGREETINGMAGIC 0x564e4321

module AP_MODULE_DECLARE_DATA websocket_vnc_proxy_module;

typedef struct _vncheader {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
} __attribute__ ((packed)) vncheader;

typedef struct
{
    char *location;
    const char *host;
    const char *port;
    const char *protocol;
    const char *secret;
    const char *localip;
    int base64;
    int sendinitialdata;
    int timeout;
    int guacamole;
    char *query;
} websocket_tcp_proxy_config_rec;

typedef struct _TcpProxyData
{
    const WebSocketServer *server;
    apr_pool_t *pool;
    apr_thread_t *thread;
    apr_socket_t *tcpsocket;
    apr_pollset_t *sendpollset;
    apr_pollset_t *recvpollset;
    int active;
    int base64;
    int sendinitialdata;
    int timeout;
    int guacamole;
    char *host;
    char *port;
    char *localip;
    char *initialdata;
    char *secret;
    char *key;
    char *nodehost;
    char *nodeport;
    char *nonce;
    apr_dbd_prepared_t *statement;
    websocket_tcp_proxy_config_rec *conf;
} TcpProxyData;

/* optional functions - look it up once in post_config */
static ap_dbd_t *(*tcp_proxy_dbd_acquire_fn)(request_rec*) = NULL;
static void (*tcp_proxy_dbd_prepare_fn)(server_rec*, const char*, const char*) = NULL;

static const char *tcp_proxy_dbd_prepare(cmd_parms *cmd, void *cfg, const char *query)
{
    static unsigned int label_num = 0;
    char *label;

    if (tcp_proxy_dbd_prepare_fn == NULL) {
        tcp_proxy_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (tcp_proxy_dbd_prepare_fn == NULL) {
            return "You must load mod_dbd to enable DBD functions";
        }
        tcp_proxy_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
    label = apr_psprintf(cmd->pool, "tcp_proxy_dbd_%d", ++label_num);

    tcp_proxy_dbd_prepare_fn(cmd->server, query, label);

    /* save the label here for our own use */
    return ap_set_string_slot(cmd, cfg, label);
}


static apr_status_t tcp_proxy_query_key (request_rec * r, TcpProxyData * tpd, apr_pool_t * mp)
{
    /* Check we have a config and a datbase connection */

    apr_status_t rv;
    const char *dbd_password = NULL;
    apr_dbd_prepared_t *statement = NULL;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    char *c;

    if (!tpd || !tpd->conf)
        return (APR_BADARG);

    websocket_tcp_proxy_config_rec *conf = tpd->conf;

    /* Check we have a real key */
    if (!tpd->key || !*tpd->key)
        return APR_BADARG;

    /* If no query is specified, we are fine */
    if (!conf->query)
        return APR_SUCCESS;

    /* Check the key is valid */
    for (c = tpd->key; *c; c++) {
        if (!isalnum(*c))
            switch (*c) {
            case ',':
            case '-':
            case '+':
            case '=':
            case '/':
            case '_':
                break;
            default:
                APACHELOG(APLOG_DEBUG, r, "DBI: bad key");
                return APR_BADARG;
            }
    }

    ap_dbd_t *dbd = tcp_proxy_dbd_acquire_fn(r);
    if (!dbd) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to acquire database connection to look up "
                      "key '%s'", tpd->key);
        return APR_BADARG;
    }

    statement = apr_hash_get(dbd->prepared, conf->query, APR_HASH_KEY_STRING);
    if (!statement) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A prepared statement could not be found for "
                      "AuthDBDUserPWQuery with the key '%s'", conf->query);
        return APR_BADARG;
    }

    if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                         0, tpd->key) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s' "
                      "in database", tpd->key);
        return APR_BADARG;
    }

    int found = 0;

    APACHELOG(APLOG_DEBUG, r,
              "tcp_proxy_query_key: running through results");

    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Error retrieving results while looking up '%s' "
                          "in database", tpd->key);
            return APR_BADARG;
        }

        APACHELOG(APLOG_DEBUG, r,
                  "tcp_proxy_query_key: found a matching line");
                
        if (!found) {
            char *nodehost = NULL;
            char *nodeport = NULL;
            char *clusterhost = NULL;
            char *clusterport = NULL;
            const char *fieldname;
            int i = 0;
            for (fieldname = apr_dbd_get_name(dbd->driver, res, i);
                 fieldname != NULL;
                 fieldname = apr_dbd_get_name(dbd->driver, res, i)) {
                
                const char *fieldvalue = apr_dbd_get_entry(dbd->driver, row, i++);

                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_query_key: found field '%s'='%s'",
                          fieldname,
                          fieldvalue);
                
                if (fieldvalue) {
                    if (!strcmp(fieldname, "nodehost"))
                        nodehost = apr_pstrdup(mp, fieldvalue);
                    else if (!strcmp(fieldname, "nodeport"))
                        nodeport = apr_pstrdup(mp, fieldvalue);
                    else if (!strcmp(fieldname, "clusterhost"))
                        clusterhost = apr_pstrdup(mp, fieldvalue);
                    else if (!strcmp(fieldname, "clusterport"))
                        clusterport = apr_pstrdup(mp, fieldvalue);
                }
            }
            if (clusterhost && clusterport) {
                tpd->host = clusterhost;
                tpd->port = clusterport;
                if (nodehost)
                    tpd->nodehost = nodehost;
                if (nodeport)
                    tpd->nodeport = nodeport;
                found = 1;
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_query_key: found parm nodehost=%s nodeport=%s, clusterhost=%s clusterport=%s",
                          tpd->nodehost?tpd->nodehost:"(none)",
                          tpd->nodeport?tpd->nodeport:"(none)",
                          tpd->host?tpd->host:"(none)",
                          tpd->port?tpd->port:"(none)");
                /* we can't break out here or row won't get cleaned up */
            }

        }

        
    }

    APACHELOG(APLOG_DEBUG, r,
              "tcp_proxy_query_key: found=%d", found);

    if (!found)
        return APR_BADARG;

    return APR_SUCCESS;
}


/**
 * return the 'key=XXX' parameter
 */

static char *tcp_proxy_get_key(request_rec * r,
                                     TcpProxyData * tpd, apr_pool_t * mp)
{
    const char *args = r->args;
    const char *param;

    if (!args)
        return NULL;

    while (*args) {
        /* get the next parameter */
        param = ap_getword(mp, &args, '&');
        if (!param)
            return NULL;
        if (!strncmp(param, "key=", 4)) {
            return apr_pstrdup(mp, param + 4);
        }
    }
    return NULL;
}

/**
 * Authenticate the connection. This can modify tpd to change (for instance)
 * the host or port to connect to, or set up initialdata. For now it is a stub.
 */

static apr_status_t tcp_proxy_do_authenticate(request_rec * r,
                                              TcpProxyData * tpd,
                                              apr_pool_t * mp)
{
    if (!tpd->conf)
        return APR_BADARG;

    tpd->key = tcp_proxy_get_key(r, tpd, mp);
    if (!tpd->key) {
        APACHELOG(APLOG_DEBUG, r,
                  "tcp_proxy_do_authenticate: no key");
        return APR_BADARG;
    }

    APACHELOG(APLOG_DEBUG, r,
              "tcp_proxy_do_authenticate: key is '%s'",
              tpd->key);

    /* Look up tpd->host, tpd->port, nodehost, nodeport using key */
    if (APR_SUCCESS != tcp_proxy_query_key(r, tpd, mp)) {
        APACHELOG(APLOG_DEBUG, r,
                  "tcp_proxy_do_authenticate: query_key failed");
        return APR_BADARG;
    }

    if (!( ((tpd->nodehost && tpd->nodeport) || !(tpd->sendinitialdata)) && tpd->host && tpd->port)) {
        APACHELOG(APLOG_DEBUG, r,
                  "tcp_proxy_do_authenticate: missing parm nodehost=%s nodeport=%s, clusterhost=%s clusterport=%s",
                  tpd->nodehost?tpd->nodehost:"(none)",
                  tpd->nodeport?tpd->nodeport:"(none)",
                  tpd->host?tpd->host:"(none)",
                  tpd->port?tpd->port:"(none)"
            );
        return APR_BADARG;
    }

    return APR_SUCCESS;
}

/**
 * Send the initial data - this would normally be generated by tcp_proxy_do_authenticate
 */

static apr_status_t tcp_proxy_send_initial_data(request_rec * r,
                                                TcpProxyData * tpd,
                                                apr_pool_t * mp)
{
    vncheader header;
    apr_status_t rv;
    apr_size_t hlen = sizeof (vncheader);
    apr_size_t len;

    if (!tpd->sendinitialdata)
        return APR_SUCCESS;

    rv = apr_socket_recv(tpd->tcpsocket, (void *)&header, &hlen);
    if (rv != APR_SUCCESS)
        return rv;

    if (hlen != sizeof (vncheader)) {
        APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: could not read whole header");
        return APR_BADARG;
    }

    if (ntohl (header.magic) != VNCGREETINGMAGIC) {
        APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: bad magic");
        return APR_BADARG;
    }

    if (ntohs (header.version) != 1) {
        APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: bad version");
        return APR_BADARG;
    }

    len = ntohs (header.length);

    if (len>1024) {
        APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: bad length");
        return APR_BADARG;
    }

    if (NULL == (tpd->nonce = apr_palloc(mp, len+1)))
        return APR_BADARG;

    tpd->nonce[len] = 0; /* zero terminate */

    rv = apr_socket_recv(tpd->tcpsocket, (void *)tpd->nonce, &len);
    if (rv != APR_SUCCESS)
        return rv;

    if (len != ntohs (header.length)) {
        APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: could not read whole header (2)");
        return APR_BADARG;
    }

    /* ignore /r /n and anything after whitespace */
    char *p;
    for (p=tpd->nonce; *p; p++) {
        if (isspace(*p)) {
            *p=0;
            break;
        }
    }

    APACHELOG (APLOG_DEBUG, r, "tcp_proxy_do_authenticate: read nonce of '%s'", tpd->nonce);

    if (!(tpd->nodehost && tpd->nodeport && tpd->host && tpd->port && tpd->nonce)) {
        APACHELOG(APLOG_DEBUG, r,
                  "tcp_proxy_do_authenticate: missing parm nodehost=%s nodeport=%s, clusterhost=%s clusterport=%s nonce=%s",
                  tpd->nodehost?tpd->nodehost:"(none)",
                  tpd->nodeport?tpd->nodeport:"(none)",
                  tpd->host?tpd->host:"(none)",
                  tpd->port?tpd->port:"(none)",
                  tpd->nonce?tpd->nonce:"(none)"
            );
        return APR_BADARG;
    }

    char *tohash =
        apr_psprintf(mp, "%s %s %s %s %s", tpd->key, tpd->nodehost, tpd->nodeport, tpd->secret, tpd->nonce);

    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_do_authenticate: Data to hash is '%s'", tohash);
    
    char hashdata[32];
    apr_crypto_hash_t *h = apr_crypto_sha256_new(mp);
    h->init(h);
    h->add(h, tohash, strlen(tohash));
    h->finish(h, hashdata);
    char hash[32*2+1];
    int i;
    for (i=0; i<32; i++) {
        sprintf(hash+i*2, "%02hhx", hashdata[i]);
    }
    hash[32*2]=0;

    tpd->initialdata = apr_psprintf(mp, "<vncconnection>"
                                    "<key>%s</key><node>%s</node><port>%s</port><hash>%s</hash>"
                                    "</vncconnection>",
                                    tpd->key, tpd->nodehost, tpd->nodeport, hash);

    if (!tpd->initialdata) {
        APACHELOG(APLOG_ERR, r,
                  "tcp_proxy_send_initial_data: could not generate initial data");
        return APR_BADARG;
    }

    len = strlen(tpd->initialdata);
    APACHELOG(APLOG_DEBUG, r,
              "tcp_proxy_send_initial_data: initial data is '%s'",
              tpd->initialdata);

    header.magic = htonl(VNCHEADERMAGIC);
    header.version = htons(1);
    header.length = htons(len);
    hlen = sizeof (vncheader);

    rv = apr_socket_send(tpd->tcpsocket, (void *)&header, &hlen);
    if (rv != APR_SUCCESS)
        return rv;

    return apr_socket_send(tpd->tcpsocket, tpd->initialdata, &len);
}

/**
 * Shutdown the tcpsocket which will cause further read/writes
 * in either direction to fail
 */

static void tcp_proxy_shutdown_socket(TcpProxyData * tpd)
{
    if (tpd && tpd->tcpsocket)
        apr_socket_shutdown(tpd->tcpsocket, APR_SHUTDOWN_READWRITE);
}

/**
 * Connect to the remote host
 */
static apr_status_t tcp_proxy_do_tcp_connect(request_rec * r,
                                             TcpProxyData * tpd,
                                             apr_pool_t * mp)
{
    apr_sockaddr_t *sa;
    apr_socket_t *s;
    apr_status_t rv;

    APACHELOG(APLOG_DEBUG, r,
              "tcp_proxy_do_tcp_connect: connect to host %s port %s",
              tpd->host, tpd->port);

    int port = atoi(tpd->port);
    rv = apr_sockaddr_info_get(&sa, tpd->host, APR_INET, port, 0, mp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (!port) {
        rv = apr_getservbyname(sa, tpd->port);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    rv = apr_socket_create(&s, sa->family, SOCK_STREAM, APR_PROTO_TCP, mp);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_interval_time_t timeout = APR_USEC_PER_SEC * ((tpd->timeout)?tpd->timeout:30);

    if (tpd->localip) {
        apr_sockaddr_t *localsa;
        rv = apr_sockaddr_info_get(&localsa, tpd->localip, APR_UNSPEC, 0 /*port*/, 0, mp);
        if (rv != APR_SUCCESS) {
            APACHELOG(APLOG_DEBUG, r,
                      "tcp_proxy_do_tcp_connect: could not get addr to bind to local address %s",
                      tpd->localip);
            apr_socket_close(s);
            return rv;
        }       
        if ((rv = apr_socket_bind(s, localsa)) != APR_SUCCESS) {
            APACHELOG(APLOG_DEBUG, r,
                      "tcp_proxy_do_tcp_connect: could not bind to local address %s",
                      tpd->localip);
            apr_socket_close(s);
            return rv;
        }
    }

    /* it is a good idea to specify socket options explicitly.
     * in this case, we make a blocking socket with timeout. */
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
    apr_socket_opt_set(s, APR_SO_KEEPALIVE, 1);
    apr_socket_timeout_set(s, timeout);

    rv = apr_socket_connect(s, sa);
    if (rv != APR_SUCCESS) {
        apr_socket_close(s);
        return rv;
    }

    /* Set it to be blocking to start off with */
    apr_socket_opt_set(s, APR_SO_NONBLOCK, 0);
    apr_socket_opt_set(s, APR_SO_KEEPALIVE, 1);
    apr_socket_timeout_set(s, timeout);

    tpd->tcpsocket = s;
    return APR_SUCCESS;
}


void guacdump (request_rec * r, char * msg, char * buf, size_t start, size_t end)
{
    size_t s = end-start+1;
    char * b = malloc(s);
    if (b) {
        memcpy(b, buf+start, s-1);
        b[s-1]=0;
        APACHELOG(APLOG_DEBUG, r, "%s: '%s'", msg, b);
        free (b);
    }
}

/* This function READS from the tcp socket and WRITES to the web socket */

void *APR_THREAD_FUNC tcp_proxy_run(apr_thread_t * thread, void *data)
{
    char buffer[64];
    TcpProxyData *tpd = (TcpProxyData *) data;

    if (!tpd)
        return NULL;

    request_rec *r = (tpd->server)->request(tpd->server);

    apr_interval_time_t timeout = APR_USEC_PER_SEC * ((tpd->timeout)?tpd->timeout:30);

    if (!tpd->guacamole) {
        /* Non-guacamole mode - buffer as much as we can */

        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run start");

#define WSTCPBUFSIZ 16384
#define WSTCPCBUFSIZ ((WSTCPBUFSIZ*4/3)+5)
#define GUARDBYTES 64
        char buf[WSTCPBUFSIZ];
        char cbuf[WSTCPCBUFSIZ];
        apr_size_t got=0;

        /* Keep sending messages as long as the connection is active */
        while (tpd->active && tpd->tcpsocket) {

            /* we can read an entire buffer length, less what we have got so far */
            apr_size_t len = sizeof(buf) - got;

            const apr_pollfd_t *ret_pfd = NULL;
            apr_int32_t num = 0;
            apr_status_t rv;

            rv = apr_pollset_poll(tpd->recvpollset, got?1000:timeout, &num, &ret_pfd);

            if (!(tpd->active && tpd->tcpsocket)) {
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_run quitting as connection has been marked inactive");
                break;
            }

            if (num<=0) {
                /* We've got nothing to do */
                if (APR_STATUS_IS_TIMEUP(rv)) {
                    len=0;
                    goto disgorgeandcontinue;
                }

                if (rv == APR_SUCCESS) {
                    /* Poll returned success, but no descriptors were ready. Very odd */
                    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: sleeping 2");
                    usleep(10000);      /* this should not happen */
                }

                APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: poll returned an error");
                break;
            }

            rv = apr_socket_recv(tpd->tcpsocket, buf+got, &len);
            
            /* recv can return data *AND* an error - deal with data first*/
            got+=len;
            
          disgorgeandcontinue:
            /* if the buffer is more than half full, or we had nothing to read */
            if ((got > WSTCPBUFSIZ/2) || (num<=0)) {

                size_t towrite = got;

                char *wbuf = buf;
                
                /* Base64 encode it if necessary */
                if (tpd->base64) {
                    towrite = apr_base64_encode(cbuf, buf, towrite);
                    wbuf = cbuf;
                }
                
                size_t written =
                    tpd->server->send(tpd->server, MESSAGE_TYPE_TEXT /* FIXME */ ,
                                      (unsigned char *) wbuf, towrite);
                if (written != towrite) {
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run send failed, wrote %lu bytes of %lu",
                              (unsigned long) written, (unsigned long) got);
                    break;
                }
                got=0;
            }
            
            if (APR_STATUS_IS_TIMEUP(rv))
                continue;

            if (rv == APR_SUCCESS) {
                if (!len) {
                    /* Hmm, we got success, or timeup in which case we want to loop
                     * but we might get no data again, so we wait just in case - there seem
                     * to be conditions where this happens in a circumstance where a repeat
                     * read produces the same error, so sleep so we don't busy-wait CPU
                     */
                    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: sleeping");
                    usleep(10000);      /* this should not happen */
                }
                continue;
            }
                
            char s[1024];
            apr_strerror(rv, s, sizeof(s));
            APACHELOG(APLOG_DEBUG, r,
                      "tcp_proxy_run apr_socket_recv failed len=%lu rv=%d, %s",
                      (unsigned long) len, rv, s);
            
            break;
        }

        tcp_proxy_shutdown_socket(tpd);
        tpd->server->close(tpd->server);

        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run stop");

    } else {

        /* We're in guacamole mode. Guacamole (unfortunately) requires that its messages
         * are not broken across websocket frames. This means we need to understand the
         * underlying protocol as we have no idea what tcp buffering might have done on
         * the way.
         *
         * For now we will use one websocket message per guacamole instruction.
         *
         * Guacamole protocol is described at
         *   http://guac-dev.org/Guacamole%20Protocol
         *
         * In essence it is a text base protocol made up of instructions. Each instruction is
         * a comma delimited list followed by a terminating semicolon. This semicolon is
         * immediately followed by the next instruction. Each instruction takes the form
         *    OPCODE,ARG1,ARG2,...;
         * Each OPCADE and ARG can contain any character (including a semicolon) so we can't
         * just look for semicolos. But fortunately each OPCODE or ARG takes the form
         *    LENGTH.VALUE
         * where LENGTH is a decimal integer length of the VALUE field (excluding the
         * dot). The VALUE field is not null terminated. So, for instance:
         *    4.size,1.0,4.1024,3.768;
         *
         * We don't use apache memory handling here because of the lack of realloc and/or
         * explicit free.
         */
        
        /*
         * Buffer arrangement
         *
         * 0             bufwritep         bufreadp    bufsize
         * V             V                 V           V  
         * XXXXXXXXXXXXXXDDDDDDDDDDDDDDDDDD------------|
         * |   |            |                 |
         * |   |            |                 \_ Free memory
         * |   \            \  
         * |    \            \_____ Data yet to be written to websocket
         * |     \         
         * buf    \______ Data already written to websocket
         */

        size_t bufsize = 0;
        size_t bufwritep = 0;
        size_t bufreadp = 0;
        const size_t minread = 1024;
        const size_t maxbufsize = 16*1024*1024;
        char * buf = NULL;


        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run start guacamole mode");

        /* Keep sending messages as long as the connection is active */
        while (tpd->active && tpd->tcpsocket) {

            if ((bufreadp > bufsize) || (bufwritep > bufreadp)) {
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_run guacamole pointer error, buf=%lx bufsize=%lu bufreadp=%lu bufwritep=%lu", (intptr_t)buf, bufsize, bufreadp, bufwritep);
                goto guacerror;
            }
                
            /* First let's see if we've got a completely empty buffer */
            if (bufreadp == bufwritep) {
                /* If so, junk all the data written to the websocket without
                 * reallocating the buffer */
                bufreadp = 0;
                bufwritep = 0;
                if (bufsize > minread) {
                    /* The buffer was grown, and now is empty, so we might as well free it
                     * up to free memory, which means it will be reallocated down below
                     */
                    free(buf);
                    buf = NULL;
                    bufsize=0;
                }
            }

            /* We know we need to read at least minread bytes
             * so the easy case is that they just fit in the current buffer
             */
            if (bufsize-bufreadp < minread) {
                /* Right, we can't fit it in the current buffer. Where
                 * bufindex > 0 we've got current data, so we'll
                 * reallocate and expunge that first
                 */
                if (bufwritep > 0) {
                    char * newbuf = malloc(bufsize + GUARDBYTES);
                    if (!newbuf) {
                        APACHELOG(APLOG_DEBUG, r,
                                  "tcp_proxy_run could not allocate guacamole buffer");
                        goto guacerror;
                    }
                    if (buf && (bufreadp > bufwritep))
                        memcpy(newbuf, buf+bufwritep, bufreadp-bufwritep);
                    bufreadp -= bufwritep;
                    bufwritep = 0;
                    if (buf)
                        free (buf);
                    buf = newbuf;
                }
                
                /* We now know bufwritep is zero, i.e. there is no data that has
                 * already been written hanging around. So lets see whether we
                 * can do a read of length minread now
                 */
                if (bufsize-bufreadp < minread) {
                    /* No we can't, so we straightforwardly need a larger buffer.
                     * (a buffer might not have been allocated yet)
                     */
                    size_t newbufsize = bufsize * 2; /* make sure we double the size of the buffer */
                    if (newbufsize > maxbufsize)
                        newbufsize = maxbufsize; /* but don't make it larger than the maximum */
                    if (newbufsize < bufreadp + minread) /* Make it large enough for the read we need */
                        newbufsize = bufreadp + minread; /* Note this is how the initial size is set */
                    if ((newbufsize > maxbufsize) || (newbufsize < bufsize))
                        {
                            APACHELOG(APLOG_DEBUG, r,
                                      "tcp_proxy_run guacamole buffer grew to illegal size");
                            goto guacerror;
                        }
		    /*
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run expanding guacamole buffer to %lu bytes", newbufsize);
		    */
                    char * newbuf = realloc (buf, newbufsize + GUARDBYTES); /* realloc when buf in NULL is a malloc */
                    if (!newbuf) {
                        /* remember to free buf */
                        APACHELOG(APLOG_DEBUG, r,
                                  "tcp_proxy_run could not reallocate guacamole buffer");
                        goto guacerror;
                    }
                    buf = newbuf;
                    bufsize = newbufsize;
                }
            }

            /* Check we now have a buffer and sace to read into - this should always be the case */
            if (!buf || (bufsize-bufreadp < minread)) {
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_run guacamole logic error, buf=%lx bufsize=%lu bufread=%lu minread=%lu", (intptr_t)buf, bufsize, bufreadp, minread);
                goto guacerror;
            }

            apr_size_t len;

            while (1) {
                /* Of course we may be able to read far more than minread, so let's go for that */
                len = bufsize - bufreadp;
                
                const apr_pollfd_t *ret_pfd = NULL;
                apr_int32_t num = 0;
                apr_status_t rv;
                
                rv = apr_pollset_poll(tpd->recvpollset, timeout, &num, &ret_pfd);
                
                if (!(tpd->active && tpd->tcpsocket)) {
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run quitting guacamole mode as connection has been marked inactive");
                    goto guacdone;
                }
                
                if (APR_STATUS_IS_TIMEUP(rv)) {
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run quitting guacamole mode as ws poll has timed out");
                    goto guacdone;
                }

                if (rv != APR_SUCCESS) {
                    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: poll returned an error");
                    goto guacerror;
                }

                if (num<=0) {
                    /* Poll returned success, but no descriptors were ready. Very odd */
                    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: sleeping guac 2");
                    usleep(10000);      /* this should not happen */
                    continue;
                }

                rv = apr_socket_recv(tpd->tcpsocket, buf+bufreadp, &len);
                if (APR_STATUS_IS_EAGAIN(rv)) { /* we have no data to read yet, we should try rereading */
                    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run: sleeping guac 3");
                    usleep(10000);
                    continue;
                }

                if (APR_STATUS_IS_EOF(rv) || !len) {
                    /* we lost the TCP session */
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run quitting guacamole mode as TCP connection closed");
                    goto guacdone;
                }

                /* We have data */
                break;
            }

            bufreadp += len;

	    /*
            APACHELOG(APLOG_DEBUG, r,
		      "tcp_proxy_run ***guac read bytes len=%lu bufwrirep=%lu bufreadpp=%lu", len, bufreadp, bufwritep);
	    */

            /* So now we have an instruction starting at bufwritep, and terminating either before
             * bufreadp (in which case we can write it and look for more) or possibly not terminating
             * in which case we need to loop around again to read more data
             */

            size_t p = bufwritep;
            while (p < bufreadp) {

                /* Skip along until we find a semicolon */
                int write=0;
                while (!write) {
		  /*
                    APACHELOG(APLOG_DEBUG, r,
                              "tcp_proxy_run ***guac decode loop p=%lu bufwrirep=%lu bufreadpp=%lu", p, bufreadp, bufwritep);
                    guacdump(r, "tcp_proxy_run ***guac string is", buf, p, bufreadp);
		  */

                    if (p >= bufreadp)
                        goto readmore;
                    size_t arglen = 0;
                    while (isdigit(buf[p])) {
                        arglen = arglen * 10 + ( buf[p++] - '0');
                        if (p >= bufreadp)
                            goto readmore;
                    }
                    /* arglen must be non-zero, and we know buf[p] is valid (as p<bufreadp) and must point
                     * to the dot
                     */
                    if (!arglen || (buf[p] != '.')) {
                        APACHELOG(LOG_DEBUG, r,
                                  "tcp_proxy_run bad guacamole length");
                        goto guacerror;
                    }
                    /* So, consider, to step to the comma we need to add arglen+1
                     * 4.size,
                     *  ^
                     *  p
                     */
                    p+=arglen+1;
                    if (p >= bufreadp)
                        goto readmore;
                    switch (buf[p++]) {
                    case ',':
                        continue;
                    case ';':
                        write = 1;
                        break;
                    default:
                        APACHELOG(LOG_DEBUG, r,
                                  "tcp_proxy_run bad guacamole terminator");
                        goto guacerror;
                        break;
                    }
                }

                /* So now we know we can write bufwritep ... p */

                /* FIXME: support base64 - actually guacamole doesn't use it */

                size_t towrite = p - bufwritep;
		/*
		APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_run ***guac writing %lu bytes", towrite);
		*/

		if (towrite <= 0) {
                    APACHELOG(APLOG_DEBUG, r,
			      "tcp_proxy_run guacamole logic error: zero length instruction");
		    goto guacerror;
		}

                size_t written =
                    tpd->server->send(tpd->server, MESSAGE_TYPE_TEXT,
                                      (unsigned char *) (buf + bufwritep), towrite);
                if (written != towrite) {
                    APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_run guacamole send failed, wrote %lu bytes of %lu",
                          (unsigned long) written, (unsigned long) len);
                    goto guacerror;
                }

                /* Step forward past the bit we've just written */
                bufwritep = p;
                
                /* And loop to see whether we have any more instructions */
            }
          readmore:
            continue; /* to avoid 'label at end of compound statement' error */
        }

      guacdone:
        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_run stop guacamole mode");
      guacerror:
	if (buf)
	  free (buf);
        tcp_proxy_shutdown_socket(tpd);
        tpd->server->close(tpd->server);
        return NULL;
    }

    return NULL;

}

/* this routine takes data FROM the web socket and writes it to the tcp socket */

static size_t CALLBACK tcp_proxy_on_message(void *plugin_private,
                                            const WebSocketServer * server,
                                            const int type,
                                            unsigned char *buffer,
                                            const size_t buffer_size)
{
    TcpProxyData *tpd = (TcpProxyData *) plugin_private;

    request_rec *r = server->request(server);

    if (tpd && tpd->tcpsocket) {
        apr_size_t len = buffer_size;
        apr_status_t rv;
        unsigned char *towrite = buffer;

        if (len<=0)
            return 0;

        if (tpd->base64) {
            /* Unfortunately we cannot guarantee our buffer is 0 terminated, which irritatingly
             * means we have to copy it
             */
            towrite = NULL;
            unsigned char *ztbuf = calloc(1, len + 1);
            if (!ztbuf)
                goto fail;
            towrite = calloc(1, len + 1);
            if (!towrite) {
                free(ztbuf);
                goto fail;
            }
            memcpy(ztbuf, buffer, len);
            len = apr_base64_decode_binary(towrite, ztbuf);
            free(ztbuf);
            if (len <= 0) {
                free(towrite);
                towrite = NULL;
            }
          fail:
            if (!towrite) {
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_on_message: apr_base64_decode_binary failed");
                tcp_proxy_shutdown_socket(tpd);
                tpd->server->close(tpd->server);
                return 0;
            }
        }

        apr_interval_time_t timeout = APR_USEC_PER_SEC * ((tpd->timeout)?tpd->timeout:30);
        rv = APR_SUCCESS;
        unsigned char * p = towrite;
        apr_size_t l = len;

        while (l>0) {

            if (!(tpd->active && tpd->tcpsocket)) {
                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_on_message quitting as connection has been marked inactive");
                rv = APR_BADARG;
                break;
            }

            const apr_pollfd_t *ret_pfd = NULL;
            apr_int32_t num = 0;

            rv = apr_pollset_poll(tpd->sendpollset, timeout, &num, &ret_pfd);
        
            if (num>0) {
                apr_size_t lw = l;
                rv = apr_socket_send(tpd->tcpsocket, p, &lw);

                /* move past data written */
                l -= lw;
                p += lw;

                if (APR_STATUS_IS_TIMEUP(rv))
                    continue;

                if (rv == APR_SUCCESS) {
                    if (!lw) {
                        /* check for success, but successfully wrote nothing */
                        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_on_message: sleeping");
                        usleep(10000);      /* this should not happen */
                    }
                    continue;
                }
                /* so the send errored, break with rv set correctly */
                break;
            }
            
            /*
             * Here we're checking rv from poll
             */
            if (APR_STATUS_IS_TIMEUP(rv))
                continue;

            if (rv == APR_SUCCESS) {
                /* Hmmm... we polled, it said success (not timeout) but nothing was
                 * ready
                 */
                APACHELOG(APLOG_DEBUG, r, "tcp_proxy_on_message: sleeping 2");
                usleep(10000);      /* this should not happen */
                continue;
            }

            /* OK, poll errored in a peculiar way */
            break;
        }

        if (tpd->base64)
            free(towrite);

        if (rv != APR_SUCCESS) {
            char s[1024];
            apr_strerror(rv, s, sizeof(s));
            APACHELOG(APLOG_DEBUG, r,
                      "tcp_proxy_on_message: apr_socket_send failed, rv=%d, sent=%lu, %s",
                      rv, (unsigned long) len, s);
            tcp_proxy_shutdown_socket(tpd);
            tpd->server->close(tpd->server);
            return 0;
        }
    }

    return 0;
}

void *CALLBACK tcp_proxy_on_connect(const WebSocketServer * server)
{
    TcpProxyData *tpd = NULL;

    if ((server != NULL) && (server->version == WEBSOCKET_SERVER_VERSION_1)) {
        /* Get access to the request_rec strucure for this connection */
        request_rec *r = server->request(server);

        APACHELOG(APLOG_DEBUG, r, "tcp_proxy_on_connect starting");

        if (r != NULL) {

            apr_pool_t *pool = NULL;
            size_t i = 0, count = server->protocol_count(server);

            websocket_tcp_proxy_config_rec *conf =
                (websocket_tcp_proxy_config_rec *)
                ap_get_module_config(r->per_dir_config,
                                     &websocket_vnc_proxy_module);
            const char *requiredprotocol = conf ? conf->protocol : NULL;

            if (requiredprotocol) {
                for (i = 0; i < count; i++) {
                    const char *protocol = server->protocol_index(server, i);

                    if (protocol && (strcmp(protocol, requiredprotocol) == 0)) {
                        /* If the client can speak the protocol, set it in the response */
                        server->protocol_set(server, protocol);
                        break;
                    }
                }
            }
            else {
                count = 1;      /* ensure i<count */
            }

            /* If the protocol negotiation worked, create a new memory pool */
            if ((i < count) &&
                (apr_pool_create(&pool, r->pool) == APR_SUCCESS)) {

                APACHELOG(APLOG_DEBUG, r,
                          "tcp_proxy_on_connect protocol correct");

                /* Allocate memory to hold the tcp proxy state */
                if ((tpd =
                     (TcpProxyData *) apr_palloc(pool,
                                                 sizeof(TcpProxyData))) !=
                    NULL) {
                    apr_thread_t *thread = NULL;
                    apr_threadattr_t *thread_attr = NULL;

                    tpd->server = server;
                    tpd->pool = pool;
                    tpd->thread = NULL;
                    tpd->tcpsocket = NULL;
                    tpd->active = 1;
                    tpd->base64 = 0;
                    tpd->sendinitialdata = 0;
                    tpd->timeout = 30;
                    tpd->guacamole = 0;
                    tpd->port = "echo";
                    tpd->host = "127.0.0.1";
                    tpd->secret = "none";
                    tpd->initialdata = NULL;
                    tpd->nonce = NULL;
                    tpd->sendpollset = NULL;
                    tpd->recvpollset = NULL;
                    tpd->key = NULL;
                    tpd->conf = conf;
                    tpd->nodehost = NULL;
                    tpd->nodeport = NULL;
                    tpd->statement = NULL;
                    tpd->localip = NULL;
                    
                    if (conf) {
                        tpd->base64 = conf->base64;
                        tpd->sendinitialdata = conf->sendinitialdata;
                        tpd->timeout = conf->timeout;
                        tpd->guacamole = conf->guacamole;
                        if (conf->host)
                            tpd->host = apr_pstrdup(pool, conf->host);
                        if (conf->port)
                            tpd->port = apr_pstrdup(pool, conf->port);
                        if (conf->secret)
                            tpd->secret = apr_pstrdup(pool, conf->secret);
                        if (conf->localip)
                            tpd->localip = apr_pstrdup(pool, conf->localip);
                        APACHELOG(APLOG_DEBUG, r,
                                  "tcp_proxy_on_connect: base64 is %d",
                                  conf->base64);
                    }
                    else {
                        APACHELOG(APLOG_DEBUG, r,
                                  "tcp_proxy_on_connect: no config");
                    }

                    /* Check we can authenticate the incoming user (this is a hook for others to add to)
                     * Check we can connect
                     * And if we have initial data to send, then send that
                     */
                    if ((APR_SUCCESS ==
                         tcp_proxy_do_authenticate(r, tpd, pool))
                        && (APR_SUCCESS ==
                            tcp_proxy_do_tcp_connect(r, tpd, pool))
                        && (APR_SUCCESS ==
                            tcp_proxy_send_initial_data(r, tpd, pool))) {

                        /* see the tutorial about the reason why we have to specify options again */
                        apr_socket_opt_set(tpd->tcpsocket, APR_SO_NONBLOCK, 1);
                        apr_socket_opt_set(tpd->tcpsocket, APR_SO_KEEPALIVE, 1);
                        apr_socket_timeout_set(tpd->tcpsocket, 0);

                        apr_pollset_create (&tpd->recvpollset, 32, pool, APR_POLLSET_THREADSAFE);
                        apr_pollfd_t recvpfd = { pool, APR_POLL_SOCKET, APR_POLLIN, 0, { NULL }, NULL };
                        recvpfd.desc.s = tpd->tcpsocket;
                        apr_pollset_add(tpd->recvpollset, &recvpfd);

                        apr_pollset_create(&tpd->sendpollset, 32, r->pool, APR_POLLSET_THREADSAFE);
                        apr_pollfd_t sendpfd = { r->pool, APR_POLL_SOCKET, APR_POLLOUT, 0, { NULL }, NULL };
                        sendpfd.desc.s = tpd->tcpsocket;
                        apr_pollset_add(tpd->sendpollset, &sendpfd);

                        /* Create a non-detached thread that will perform the work */
                        if ((apr_threadattr_create(&thread_attr, pool) ==
                             APR_SUCCESS)
                            && (apr_threadattr_detach_set(thread_attr, 0) ==
                                APR_SUCCESS)
                            &&
                            (apr_thread_create
                             (&thread, thread_attr, tcp_proxy_run, tpd,
                              pool) == APR_SUCCESS)) {
                            tpd->thread = thread;
                            /* Success */
                            pool = NULL;
                        }
                        else {
                            tpd = NULL;
                        }
                    }
                    else
                        tpd = NULL;
                }
                if (pool != NULL) {
                    apr_pool_destroy(pool);
                }
            }
        }
    }
    return tpd;
}

void CALLBACK tcp_proxy_on_disconnect(void *plugin_private,
                                      const WebSocketServer * server)
{
    TcpProxyData *tpd = (TcpProxyData *) plugin_private;

    request_rec *r = server->request(server);
    APACHELOG(APLOG_DEBUG, r, "tcp_proxy_on_disconnect");

    if (tpd != 0) {
        /* When disconnecting, inform the thread that it is time to stop */
        tpd->active = 0;
        tcp_proxy_shutdown_socket(tpd);
        if (tpd->thread) {
            apr_status_t status;

            /* Wait for the thread to finish */
            status = apr_thread_join(&status, tpd->thread);
        }
        tcp_proxy_shutdown_socket(tpd);

        if (tpd->tcpsocket) {
            apr_socket_close(tpd->tcpsocket);
            tpd->tcpsocket = NULL;
        }

        apr_pool_destroy(tpd->pool);
    }
}

/*
 * Since we are returning a pointer to static memory, there is no need for a
 * "destroy" function.
 */

static WebSocketPlugin s_plugin = {
    sizeof(WebSocketPlugin),
    WEBSOCKET_PLUGIN_VERSION_0,
    NULL,                       /* destroy */
    tcp_proxy_on_connect,
    tcp_proxy_on_message,
    tcp_proxy_on_disconnect
};

extern EXPORT WebSocketPlugin *CALLBACK vnc_proxy_init()
{
    return &s_plugin;
}

static const char *mod_websocket_tcp_proxy_conf_base64(cmd_parms * cmd,
                                                       void *config, int flag)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->base64 = flag;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_guacamole(cmd_parms * cmd,
                                                       void *config, int flag)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->guacamole = flag;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_sendinitialdata(cmd_parms * cmd,
                                                                void *config, int flag)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->sendinitialdata = flag;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_host(cmd_parms * cmd,
                                                     void *config,
                                                     const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->host = arg;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_port(cmd_parms * cmd,
                                                     void *config,
                                                     const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->port = arg;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_protocol(cmd_parms * cmd,
                                                         void *config,
                                                         const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->protocol = strcmp(arg, "any") ? arg : NULL;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_timeout(cmd_parms * cmd,
                                                        void *config,
                                                        const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->timeout = atoi(arg);
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_secret(cmd_parms * cmd,
                                                       void *config,
                                                       const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->secret = arg;
    return NULL;
}

static const char *mod_websocket_tcp_proxy_conf_localip(cmd_parms * cmd,
                                                        void *config,
                                                        const char *arg)
{
    websocket_tcp_proxy_config_rec *cfg =
        (websocket_tcp_proxy_config_rec *) config;
    cfg->localip = arg;
    return NULL;
}

static const command_rec mod_websocket_tcp_proxy_cmds[] = {
    AP_INIT_FLAG("WebSocketTcpProxyBase64",
                 mod_websocket_tcp_proxy_conf_base64, NULL, OR_AUTHCFG,
                 "Flag to indicate use of base64 encoding; defaults to off"),
    AP_INIT_FLAG("WebSocketTcpProxyGuacamole",
                 mod_websocket_tcp_proxy_conf_guacamole, NULL, OR_AUTHCFG,
                 "Flag to indicate use of guacamole protocol; defaults to off"),
    AP_INIT_FLAG("WebSocketTcpProxySendInitialData",
                 mod_websocket_tcp_proxy_conf_sendinitialdata, NULL, OR_AUTHCFG,
                 "Flag to indicate need to send initial data; defaults to off"),
    AP_INIT_TAKE1("WebSocketTcpProxyHost", mod_websocket_tcp_proxy_conf_host,
                  NULL, OR_AUTHCFG,
                  "Host to connect WebSockets TCP proxy to; default 127.0.0.1"),
    AP_INIT_TAKE1("WebSocketTcpProxyPort", mod_websocket_tcp_proxy_conf_port,
                  NULL, OR_AUTHCFG,
                  "Port to connect WebSockets TCP proxy to; default echo"),
    AP_INIT_TAKE1("WebSocketTcpProxyProtocol",
                  mod_websocket_tcp_proxy_conf_protocol, NULL, OR_AUTHCFG,
                  "WebSockets protocols to accept, or 'any'; default 'any'"),
    AP_INIT_TAKE1("WebSocketTcpProxyTimeout",
                  mod_websocket_tcp_proxy_conf_timeout, NULL, OR_AUTHCFG,
                  "WebSockets proxy connection timeout in seconds; default 30"),
    AP_INIT_TAKE1("WebSocketTcpProxySecret",
                  mod_websocket_tcp_proxy_conf_secret,
                  NULL, OR_AUTHCFG,
                  "WebSockets connection secret; default none"),
    AP_INIT_TAKE1("WebSocketTcpProxyLocalIP",
                  mod_websocket_tcp_proxy_conf_localip,
                  NULL, OR_AUTHCFG,
                  "WebSockets connection local IP for outbound connections; default unset"),
    AP_INIT_TAKE1("WebSocketTcpProxyQuery", tcp_proxy_dbd_prepare,
                  (void *)APR_OFFSETOF(websocket_tcp_proxy_config_rec, query), OR_AUTHCFG,
                  "Query used to fetch password for user"),
    {NULL}
};

static void *mod_websocket_tcp_proxy_create_dir_config(apr_pool_t * p,
                                                       char *path)
{
    websocket_tcp_proxy_config_rec *conf = NULL;

    if (path != NULL) {
        conf = apr_pcalloc(p, sizeof(websocket_tcp_proxy_config_rec));
        if (conf != NULL) {
            conf->location = apr_pstrdup(p, path);
            conf->base64 = 0;
            conf->sendinitialdata = 0;
            conf->guacamole = 0;
            conf->host = apr_pstrdup(p, "127.0.0.1");
            conf->port = apr_pstrdup(p, "echo");
            conf->secret = apr_pstrdup(p, "none");
            conf->localip = NULL;
            conf->protocol = NULL;
            conf->timeout = 30;
            conf->query = NULL;
        }
    }
    return (void *) conf;
}

static int mod_websocket_tcp_proxy_method_handler(request_rec * r)
{
    return DECLINED;
}

static void mod_websocket_tcp_proxy_register_hooks(apr_pool_t * p)
{
    ap_hook_handler(mod_websocket_tcp_proxy_method_handler, NULL, NULL,
                    APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA websocket_vnc_proxy_module = {
    STANDARD20_MODULE_STUFF,
    mod_websocket_tcp_proxy_create_dir_config,  /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create server config structure */
    NULL,                       /* merge server config structures */
    mod_websocket_tcp_proxy_cmds,       /* command table */
    mod_websocket_tcp_proxy_register_hooks,     /* hooks */
};
