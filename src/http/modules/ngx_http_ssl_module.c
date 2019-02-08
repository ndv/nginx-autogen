
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s);


#define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_DEFAULT_ECDH_CURVE  "auto"

#define NGX_HTTP_NPN_ADVERTISE  "\x08http/1.1"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
static int ngx_http_ssl_npn_advertised(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg);
#endif

static ngx_int_t ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ssl_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_ssl_init(ngx_conf_t *cf);


static ngx_conf_bitmask_t  ngx_http_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_ssl_verify[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("optional"), 2 },
    { ngx_string("optional_no_ca"), 3 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_ssl_enable,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificates),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_keys),
      NULL },

    { ngx_string("ssl_password_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_password_file,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, dhparam),
      NULL },

    { ngx_string("ssl_ecdh_curve"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { ngx_string("ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, protocols),
      &ngx_http_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify),
      &ngx_http_ssl_verify },

    { ngx_string("ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_session_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_ssl_session_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_tickets"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_tickets),
      NULL },

    { ngx_string("ssl_session_ticket_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_ticket_keys),
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { ngx_string("ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, crl),
      NULL },

	{ ngx_string("ssl_generated_cert_path"),
		  NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
		  ngx_conf_set_str_slot,
		  NGX_HTTP_SRV_CONF_OFFSET,
		  offsetof(ngx_http_ssl_srv_conf_t, generatedCertPath),
		  NULL },
    { ngx_string("ssl_autogen_subject"),
		  NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
		  ngx_conf_set_str_slot,
		  NGX_HTTP_SRV_CONF_OFFSET,
		  offsetof(ngx_http_ssl_srv_conf_t, certSubject),
		  NULL },
	{ ngx_string("ssl_autogen"),
		  NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
		  ngx_conf_set_flag_slot,
		  NGX_HTTP_SRV_CONF_OFFSET,
		  offsetof(ngx_http_ssl_srv_conf_t, autogen),
		  NULL },

    { ngx_string("ssl_stapling"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling),
      NULL },

    { ngx_string("ssl_stapling_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { ngx_string("ssl_stapling_responder"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { ngx_string("ssl_stapling_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_verify),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_module_ctx = {
    ngx_http_ssl_add_variables,            /* preconfiguration */
    ngx_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_module_ctx,              /* module context */
    ngx_http_ssl_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_ssl_vars[] = {

    { ngx_string("ssl_protocol"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_cipher"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_cipher_name, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_ciphers"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_ciphers, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_curves"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_curves, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_session_id"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_session_id, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_session_reused"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_session_reused, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_server_name"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_server_name, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_certificate, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_raw_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_raw_certificate,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_escaped_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_escaped_certificate,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_s_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_i_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_s_dn_legacy"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_i_dn_legacy"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn_legacy, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_serial"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_serial_number, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_fingerprint"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_fingerprint, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_verify"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_verify, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_start"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_start, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_end"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_end, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_v_remain"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_v_remain, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
ngx_http_ssl_alpn_select(ngx_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int            srvlen;
    unsigned char          *srv;
#if (NGX_DEBUG)
    unsigned int            i;
#endif
#if (NGX_HTTP_V2)
    ngx_http_connection_t  *hc;
#endif
#if (NGX_HTTP_V2 || NGX_DEBUG)
    ngx_connection_t       *c;

    c = ngx_ssl_get_connection(ssl_conn);
#endif

#if (NGX_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

#if (NGX_HTTP_V2)
    hc = c->data;

    if (hc->addr_conf->http2) {
        srv =
           (unsigned char *) NGX_HTTP_V2_ALPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(NGX_HTTP_V2_ALPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE) - 1;

    } else
#endif
    {
        srv = (unsigned char *) NGX_HTTP_NPN_ADVERTISE;
        srvlen = sizeof(NGX_HTTP_NPN_ADVERTISE) - 1;
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef TLSEXT_TYPE_next_proto_neg

static int
ngx_http_ssl_npn_advertised(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg)
{
#if (NGX_HTTP_V2 || NGX_DEBUG)
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "SSL NPN advertised");
#endif

#if (NGX_HTTP_V2)
    {
    ngx_http_connection_t  *hc;

    hc = c->data;

    if (hc->addr_conf->http2) {
        *out =
            (unsigned char *) NGX_HTTP_V2_NPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE;
        *outlen = sizeof(NGX_HTTP_V2_NPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE) - 1;

        return SSL_TLSEXT_ERR_OK;
    }
    }
#endif

    *out = (unsigned char *) NGX_HTTP_NPN_ADVERTISE;
    *outlen = sizeof(NGX_HTTP_NPN_ADVERTISE) - 1;

    return SSL_TLSEXT_ERR_OK;
}

#endif


static ngx_int_t
ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    size_t     len;
    ngx_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    ngx_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->trusted_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers = { 0, NULL };
     *     sscf->shm_zone = NULL;
     *     sscf->stapling_file = { 0, NULL };
     *     sscf->stapling_responder = { 0, NULL };
     */

    sscf->enable = NGX_CONF_UNSET;
    sscf->prefer_server_ciphers = NGX_CONF_UNSET;
    sscf->buffer_size = NGX_CONF_UNSET_SIZE;
    sscf->verify = NGX_CONF_UNSET_UINT;
    sscf->verify_depth = NGX_CONF_UNSET_UINT;
    sscf->certificates = NGX_CONF_UNSET_PTR;
    sscf->certificate_keys = NGX_CONF_UNSET_PTR;
    sscf->passwords = NGX_CONF_UNSET_PTR;
    sscf->builtin_session_cache = NGX_CONF_UNSET;
    sscf->session_timeout = NGX_CONF_UNSET;
    sscf->session_tickets = NGX_CONF_UNSET;
    sscf->session_ticket_keys = NGX_CONF_UNSET_PTR;
	sscf->autogen = NGX_CONF_UNSET;
    sscf->stapling = NGX_CONF_UNSET;
    sscf->stapling_verify = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;

    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == NGX_CONF_UNSET) {
            conf->enable = 0;

        } else {
            conf->enable = prev->enable;
            conf->file = prev->file;
            conf->line = prev->line;
        }
    }

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                          |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                         NGX_SSL_BUFSIZE);

    ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    ngx_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    ngx_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");

    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NGX_DEFAULT_ECDH_CURVE);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);

	ngx_conf_merge_str_value(conf->generatedCertPath, prev->generatedCertPath, "");
	ngx_conf_merge_value(conf->autogen, prev->autogen, 0);

	ngx_conf_merge_value(conf->stapling, prev->stapling, 0);
    ngx_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    ngx_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    ngx_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

    conf->ssl.log = cf->log;

    if (conf->enable) {

        if (conf->certificates == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_keys == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_keys->nelts < conf->certificates->nelts) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\" and "
                          "the \"ssl\" directive in %s:%ui",
                          ((ngx_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1,
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

    } else {

        if (conf->certificates == NULL) {
            return NGX_CONF_OK;
        }

        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((ngx_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return NGX_CONF_ERROR;
        }
    }

	// check if generatedCertPath exists and is a directory
	if (conf->autogen) {
		if (!conf->generatedCertPath.len) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ssl_generated_cert_path is not set");
			return NGX_CONF_ERROR;
		}
		struct stat sb;
		stat((char*)conf->generatedCertPath.data, &sb);
		if (!S_ISDIR(sb.st_mode)) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" is not a directory", &conf->generatedCertPath);
			return NGX_CONF_ERROR;
		}
	}

	if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               ngx_http_ssl_servername)
        == 0)
    {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
            "nginx was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }

#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, ngx_http_ssl_alpn_select, NULL);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(conf->ssl.ctx,
                                          ngx_http_ssl_npn_advertised, NULL);
#endif

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (ngx_ssl_certificates(cf, &conf->ssl, conf->certificates,
                             conf->certificate_keys, conf->passwords)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    conf->ssl.buffer_size = conf->buffer_size;

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_client_verify");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
                                    &conf->trusted_certificate,
                                    conf->verify_depth)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (ngx_ssl_session_cache(&conf->ssl, &ngx_http_ssl_sess_id_ctx,
                              conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    ngx_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (ngx_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->stapling) {

        if (ngx_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    ngx_str_t  *value;

    if (sscf->passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (sscf->passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NO_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            sscf->shm_zone->init = ngx_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
        sscf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_ssl_init(ngx_conf_t *cf)
{
    ngx_uint_t                   s;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL || !sscf->stapling) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

// autogenerate ssl certificates

#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define SERIAL_RAND_BITS        64

void log_error(const char *str)
{
	fputs(str, stderr);
	fputc('\n', stderr);
}

static BIO *dup_bio_in()
{
	return BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
}

static BIO *dup_bio_out()
{
	BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
	return b;
}

static int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
	int rv;
	char *stmp, *vtmp = NULL;
	stmp = OPENSSL_strdup(value);
	if (!stmp)
		return -1;
	vtmp = strchr(stmp, ':');
	if (vtmp) {
		*vtmp = 0;
		vtmp++;
	}
	rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
	OPENSSL_free(stmp);
	return rv;
}

static const char *modestr(char mode)
{
	assert(mode == 'a' || mode == 'r' || mode == 'w');

	switch (mode) {
	case 'a':
		return "a";
	case 'r':
		return "r";
	case 'w':
		return "w";
	}
	/* The assert above should make sure we never reach this point */
	return NULL;
}
static const char *modeverb(char mode)
{
	switch (mode) {
	case 'a':
		return "appending";
	case 'r':
		return "reading";
	case 'w':
		return "writing";
	}
	return "(doing something)";
}

static BIO *bio_open_default_(const char *filename, char mode, int quiet)
{
	BIO *ret;

	if (filename == NULL || strcmp(filename, "-") == 0) {
		ret = mode == 'r' ? dup_bio_in() : dup_bio_out();
		if (quiet) {
			ERR_clear_error();
			return ret;
		}
		if (ret != NULL)
			return ret;
		fprintf(stderr, "Can't open %s, %s\n", mode == 'r' ? "stdin" : "stdout", strerror(errno));
	}
	else {
		ret = BIO_new_file(filename, modestr(mode));
		if (quiet) {
			ERR_clear_error();
			return ret;
		}
		if (ret != NULL)
			return ret;
		fprintf(stderr, "Can't open %s for %s, %s\n", filename, modeverb(mode), strerror(errno));
	}
	return NULL;
}

static BIO *bio_open_default(const char *filename, char mode)
{
	return bio_open_default_(filename, mode, 0);
}

static int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
	BIGNUM *btmp;
	int ret = 0;

	if (b)
		btmp = b;
	else
		btmp = BN_new();

	if (btmp == NULL)
		return 0;

	if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
		goto error;
	if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
		goto error;

	ret = 1;

error:

	if (btmp != b)
		BN_free(btmp);

	return ret;
}

static int set_cert_times(X509 *x, const char *startdate, const char *enddate, int days)
{
	if (startdate == NULL || strcmp(startdate, "today") == 0) {
		if (X509_gmtime_adj(X509_getm_notBefore(x), -1000) == NULL)
			return 0;
	}
	else {
		if (!ASN1_TIME_set_string(X509_getm_notBefore(x), startdate))
			return 0;
	}
	if (enddate == NULL) {
		if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL) == NULL)
			return 0;
	}
	else if (!ASN1_TIME_set_string(X509_getm_notAfter(x), enddate)) {
		return 0;
	}
	return 1;
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
	const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
	EVP_PKEY_CTX *pkctx = NULL;
	int i;

	if (ctx == NULL)
		return 0;
	if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
		return 0;
	for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
		char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
		if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
			fprintf(stderr, "parameter error \"%s\"\n", sigopt);
			return 0;
		}
	}
	return 1;
}

static int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
	STACK_OF(OPENSSL_STRING) *sigopts)
{
	int rv;
	EVP_MD_CTX *mctx = EVP_MD_CTX_new();

	rv = do_sign_init(mctx, pkey, md, sigopts);
	if (rv > 0)
		rv = X509_sign_ctx(x, mctx);
	EVP_MD_CTX_free(mctx);
	return rv > 0 ? 1 : 0;
}

static int x509_certify(ngx_log_t *log, X509_STORE *ctx, const EVP_MD *digest,
	X509 *x, X509 *xca, EVP_PKEY *pkey,
	STACK_OF(OPENSSL_STRING) *sigopts,
	const char *serialfile, int create,
	int days, int clrext, CONF *conf, const char *section,
	ASN1_INTEGER *sno, int reqfile)
{
	int ret = 0;
	ASN1_INTEGER *bs = NULL;
	X509_STORE_CTX *xsc = NULL;
	EVP_PKEY *upkey;

	upkey = X509_get0_pubkey(xca);
	if (upkey == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error obtaining CA X509 public key");
		goto end;
	}
	EVP_PKEY_copy_parameters(upkey, pkey);

	xsc = X509_STORE_CTX_new();
	if (xsc == NULL || !X509_STORE_CTX_init(xsc, ctx, x, NULL)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error initialising X509 store");
		goto end;
	}
	if (sno)
		bs = sno;
	else {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot read serial");
		goto end;
	}

	/*
	* NOTE: this certificate can/should be self signed, unless it was a
	* certificate request in which case it is not.
	*/
	X509_STORE_CTX_set_cert(xsc, x);
	X509_STORE_CTX_set_flags(xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
	if (!reqfile && X509_verify_cert(xsc) <= 0)
		goto end;

	if (!X509_check_private_key(xca, pkey)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "CA certificate and CA private key do not match");
		goto end;
	}

	if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
		goto end;
	if (!X509_set_serialNumber(x, bs))
		goto end;

	if (!set_cert_times(x, NULL, NULL, days))
		goto end;

	if (clrext) {
		while (X509_get_ext_count(x) > 0)
			X509_delete_ext(x, 0);
	}

	if (conf) {
		X509V3_CTX ctx2;
		X509_set_version(x, 2); /* version 3 certificate */
		X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
		X509V3_set_nconf(&ctx2, conf);
		if (!X509V3_EXT_add_nconf(conf, &ctx2, section, x)) {
			char buf[1000];
			ERR_error_string_n(ERR_peek_error(), buf, sizeof(buf));
			ngx_log_error(NGX_LOG_EMERG, log, 0, "error in X509V3_EXT_add_nconf: %s", buf);
			goto end;
		}
	}

	if (!do_X509_sign(x, pkey, digest, sigopts))
		goto end;
	ret = 1;
end:
	//if (upkey) EVP_PKEY_free(upkey);
	X509_STORE_CTX_free(xsc);
	if (!sno)
		ASN1_INTEGER_free(bs);
	return ret;
}

static CONF *app_load_config(ngx_log_t *log, BIO *in)
{
	long errorline = -1;
	CONF *conf;
	int i;

	conf = NCONF_new(NULL);
	i = NCONF_load_bio(conf, in, &errorline);
	if (i > 0)
		return conf;

	if (errorline <= 0) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Can't load config file");
	} 
	else {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error on line %ld of config", errorline);
	}
	NCONF_free(conf);
	return NULL;
}

static char *append(char *ptr, ngx_str_t s)
{
	memcpy(ptr, s.data, s.len);
	ptr[s.len] = 0;
	return ptr + s.len;
}

static char *appends(char *ptr, const char *s)
{
	int l = strlen(s);
	memcpy(ptr, s, l);
	ptr[l] = 0;
	return ptr + l;
}

/*
* name is expected to be in the format /type0=value0/type1=value1/type2=...
* where characters may be escaped by \
*/
static X509_NAME *parse_name(ngx_log_t *log, const char *cp, int canmulti)
{
	int nextismulti = 0;
	char *work;
	X509_NAME *n;

	if (*cp++ != '/') {
		ngx_log_error(NGX_LOG_EMERG, log, 0,
			"ssl_autogen_subject is expected to be in the format "
			"/type0=value0/type1=value1/type2=... where characters may "
			"be escaped by \\. This name is not in that format: '%s'\n",
			--cp);
		return NULL;
	}

	n = X509_NAME_new();
	if (n == NULL)
		return NULL;
	work = OPENSSL_strdup(cp);
	if (work == NULL)
		goto err;

	while (*cp) {
		char *bp = work;
		char *typestr = bp;
		unsigned char *valstr;
		int nid;
		int ismulti = nextismulti;
		nextismulti = 0;

		/* Collect the type */
		while (*cp && *cp != '=')
			*bp++ = *cp++;
		if (*cp == '\0') {
			ngx_log_error(NGX_LOG_EMERG, log, 0,
				"Hit end of string before finding the equals.");
			goto err;
		}
		*bp++ = '\0';
		++cp;

		/* Collect the value. */
		valstr = (unsigned char *)bp;
		for (; *cp && *cp != '/'; *bp++ = *cp++) {
			if (canmulti && *cp == '+') {
				nextismulti = 1;
				break;
			}
			if (*cp == '\\' && *++cp == '\0') {
				ngx_log_error(NGX_LOG_EMERG, log, 0,
					" escape character at end of string");
				goto err;
			}
		}
		*bp++ = '\0';

		/* If not at EOS (must be + or /), move forward. */
		if (*cp)
			++cp;

		/* Parse */
		nid = OBJ_txt2nid(typestr);
		if (nid == NID_undef) {
			ngx_log_error(NGX_LOG_EMERG, log, 0, "Skipping unknown attribute \"%s\"",
				typestr);
			continue;
		}
		if (*valstr == '\0') {
			ngx_log_error(NGX_LOG_EMERG, log, 0,
				"No value provided for Subject Attribute %s, skipped",
				typestr);
			continue;
		}
		if (!X509_NAME_add_entry_by_NID(n, nid, MBSTRING_ASC,
			valstr, strlen((char *)valstr),
			-1, ismulti ? -1 : 0))
			goto err;
	}

	OPENSSL_free(work);
	return n;

err:
	X509_NAME_free(n);
	OPENSSL_free(work);
	return NULL;
}

int ngx_get_cert(ngx_log_t *log, ngx_pool_t *pool, ngx_http_ssl_srv_conf_t *sscf, char *serverName, char **certPath, char **certKey, 
	X509 *xca, EVP_PKEY *caKey)
{
	int days = 1825;
	//char *caCertFile = "rootCA.pem";
	//char *caKeyFile = "rootCA.key";
	//char *caKeyPass = "";
	//char *dnsName = "test-server.com:8443";

	if (strchr(serverName, '/') || strchr(serverName, '\\')) {
		// security check
		return 0;
	}

	int sl = strlen(serverName);
	*certPath = ngx_palloc(pool, sscf->generatedCertPath.len + 1 + sl + 4 + 1);
	*certKey = ngx_palloc(pool, sscf->generatedCertPath.len + 1 + sl + 4 + 1);

	char *ptr = *certPath;

	ptr = append(ptr, sscf->generatedCertPath);
	ptr = appends(ptr, "/");
	ptr = appends(ptr, serverName);
	ptr = appends(ptr, ".crt");

	ptr = *certKey;
	ptr = append(ptr, sscf->generatedCertPath);
	ptr = appends(ptr, "/");
	ptr = appends(ptr, serverName);
	ptr = appends(ptr, ".key");

	struct stat sb;
	stat(*certPath, &sb);
	long now = time(NULL);
	if (S_ISREG(sb.st_mode) && (now - sb.st_mtim.tv_sec) < (days-1)*24*3600) {
		stat(*certKey, &sb);
		if (S_ISREG(sb.st_mode)) return 1;
	}

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0, "Generate cert \"%s\" and key \"%s\" for domain %s", *certPath, *certKey, serverName);

	char extBuf[1000];
	snprintf(extBuf, sizeof(extBuf), "authorityKeyIdentifier=keyid,issuer\n"
		"basicConstraints=CA:FALSE\n"
		"keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n"
		"subjectAltName = @alt_names\n"
		"[alt_names]\n"
		"DNS.1 = %s\n", serverName);

	ENGINE *keygen_engine = NULL;// ENGINE_by_id("dynamic");
	EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, keygen_engine);
	EVP_PKEY *pkey = NULL;

	if (EVP_PKEY_keygen_init(gctx) <= 0) {
		EVP_PKEY_CTX_free(gctx);
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error initializing keygen context");
		return 0;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, 2048) <= 0) {
		EVP_PKEY_CTX_free(gctx);
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error setting RSA keysize");
		return 0;
	}
	if (EVP_PKEY_keygen(gctx, &pkey) <= 0) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error Generating Key");
		return 0;
	}

	EVP_PKEY_CTX_free(gctx);
	gctx = NULL;

	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	const EVP_MD *digest = EVP_get_digestbyname("sha256");
	X509_REQ *req = NULL;

	FILE *privateKey = fopen(*certKey, "wb");
	if (!privateKey) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot open private key file %s for writing", *certKey);
		return 0;
	}
	if (!PEM_write_PrivateKey(privateKey, pkey, cipher, (unsigned char*)"", 0, NULL, NULL)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot write private key %s", *certKey);
		return 0;
	}
	fclose(privateKey);

	if ((req = X509_REQ_new()) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot create request");
		return 0;
	}
	if (!X509_REQ_set_version(req, 0L)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error setting request version");
		return 0;
	}
	if (!X509_REQ_set_pubkey(req, pkey)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error setting pubkey");
		return 0;
	}

	X509_NAME *subj;
	char *str = ngx_palloc(pool, sscf->certSubject.len + 1);
	memcpy(str, sscf->certSubject.data, sscf->certSubject.len);
	sscf->certSubject.data[sscf->certSubject.len] = 0;
	if ((subj = parse_name(log, str, 1)) == NULL) {
		ngx_pfree(pool, str);
		return 0;
	}
	ngx_pfree(pool, str);

	if (!X509_REQ_set_subject_name(req, subj)) {
		X509_NAME_free(subj);
		return 0;
	}
	X509_NAME_free(subj);

	EVP_MD_CTX *mctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX *pkctx = NULL;
	if (!EVP_DigestSignInit(mctx, &pkctx, digest, NULL, pkey)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error initializing sign digest");
		return 0;
	}

	X509_REQ_sign_ctx(req, mctx);
	EVP_MD_CTX_free(mctx);

	// create cert
	X509 *x = NULL;
	if ((x = X509_new()) == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot create a X509 cert");
		return 0;
	}
	ASN1_INTEGER *sno = ASN1_INTEGER_new();
	if (sno == NULL || !rand_serial(NULL, sno)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot generate random");
		return 0;
	}

	if (!X509_set_serialNumber(x, sno)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot set random");
		return 0;
	}
	//ASN1_INTEGER_free(sno);
	//sno = NULL;

	if (!X509_set_issuer_name(x, X509_REQ_get_subject_name(req))) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot set issuer");
		return 0;
	}
	if (!X509_set_subject_name(x, X509_REQ_get_subject_name(req))) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot set subject");
		return 0;
	}
	if (!set_cert_times(x, NULL, NULL, days)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot set expiration");
		return 0;
	}

	X509_set_pubkey(x, pkey);

	/*
	BIO *caCert = bio_open_default(caCertFile, 'r');
	if (caCert == NULL) {
		log_error("Cannot open CA cert");
		return -1;
	}
	xca = PEM_read_bio_X509_AUX(caCert, NULL, NULL, NULL);
	BIO_free(caCert);
	if (xca == NULL) {
		log_error("Cannot parse CA cert");
		return -1;
	}*/

	BIO *out = bio_open_default(*certPath, 'w');
	if (out == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Cannot open %s for writing", *certPath);
		return 0;
	}

	//EVP_PKEY *caPKey = load_key(caKeyFile, caKeyPass, keygen_engine, "CA Private Key");

	X509_STORE *ctx = X509_STORE_new();
	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error creating the certificate store");
		return 0;
	}
	BIO *ext = BIO_new_mem_buf(extBuf, strlen(extBuf));

	CONF *extconf;
	if ((extconf = app_load_config(log, ext)) == NULL) {
		return 0;
	}
	BIO_free(ext);

	X509V3_CTX ctx2;
	char *extsect = NCONF_get_string(extconf, "default", "extensions");
	if (!extsect) {
		ERR_clear_error();
		extsect = "default";
	}
	X509V3_set_ctx_test(&ctx2);
	X509V3_set_nconf(&ctx2, extconf);
	if (!X509V3_EXT_add_nconf(extconf, &ctx2, extsect, NULL)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0,"Error Loading extension section %s\n", extsect);
		return 0;
	}

	if (!x509_certify(log, ctx, digest, x, xca,
			caKey, NULL,
			NULL, 1, days, 0,
			extconf, extsect, sno, 1)) {
		ngx_log_error(NGX_LOG_EMERG, log, 0, "Error signing the certificate");
		return 0;
	}

	PEM_write_bio_X509(out, x);

	NCONF_free(extconf);
	BIO_free_all(out);
	X509_STORE_free(ctx);
	X509_REQ_free(req);
	X509_free(x);
	EVP_PKEY_free(pkey);

	//int status = 0;
	//status |= X509_NAME_add_entry_by_NID(n, nid, MBSTRING_ASC, (unsigned char *)buf, -1, -1, mval))

	return 1;
}
