/*
 * Copyright (C) Sogou, Inc
 */

#include "ngx_http_req_status_module.h"

static ngx_int_t ngx_http_req_status_init_zone(ngx_shm_zone_t *shm_zone,
        void *data);
static void ngx_http_req_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_req_status_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_req_status_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_set_header_helper(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value,
    ngx_table_elt_t **output_header, ngx_flag_t no_create);
static void *ngx_http_req_status_lookup(void *conf, ngx_uint_t hash,
        ngx_str_t *key);
static void ngx_http_req_status_expire(void *conf);

static void *ngx_http_req_status_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_req_status_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_req_status_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_req_status_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);

static char *ngx_http_req_status_zone(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_req_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_req_status_show(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_req_status_prometheus(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_req_status_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_req_status_show_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_req_status_prometheus_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_req_status_check_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_req_status_write_filter(ngx_http_request_t *r,
        off_t bsent);

static ngx_int_t ngx_http_req_status_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_req_status_init_process(ngx_cycle_t *cycle);
static ngx_msec_t ngx_http_req_status_current_msec(void);

static ngx_int_t ngx_http_req_status_restore(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_req_status_pre_dump(ngx_event_t *ev);
static ngx_int_t ngx_http_req_status_dump(ngx_event_t *ev);
static void ngx_http_req_status_dump_handler(ngx_event_t *ev);

typedef struct ngx_http_req_status_loc_conf_s ngx_http_req_status_loc_conf_t;


typedef struct {
    ngx_msec_t       time;
    ngx_uint_t       version;
} ngx_http_req_status_dump_header_t;

typedef struct {
    ngx_uint_t                      requests;
    ngx_uint_t                      traffic;

    ngx_uint_t                      bandwidth;
    ngx_uint_t                      max_bandwidth;

    ngx_uint_t                      max_active;
} ngx_http_req_status_data_t;

typedef struct {
    ngx_rbtree_node_t               node;
    ngx_queue_t                     queue;

    ngx_uint_t                      count; // ref count

    ngx_http_req_status_data_t      data;

    ngx_uint_t                      active;
    ngx_uint_t                      active_post;
    ngx_uint_t                      last_traffic;
    ngx_msec_t                      last_traffic_start;
    ngx_msec_t                      last_traffic_update;

    ngx_uint_t                      len;
    u_char                          key[0];
} ngx_http_req_status_node_t;

typedef struct {
    ngx_rbtree_t                    rbtree;
    ngx_rbtree_node_t               sentinel;
    ngx_queue_t                     queue;
    time_t                          expire_lock;
} ngx_http_req_status_sh_t;

typedef struct {
    ngx_str_t                       *zone_name;
    ngx_http_req_status_node_t      *node;
    ngx_http_req_status_data_t      *pdata;
    ngx_http_req_status_data_t       data[0];
} ngx_http_req_status_print_item_t;

typedef struct {
    ngx_http_req_status_sh_t        *sh;
    ngx_slab_pool_t                 *shpool;
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_complex_value_t         key;
} ngx_http_req_status_zone_t;

typedef struct {
    ngx_http_req_status_zone_t      *zone;
    ngx_http_req_status_node_t      *node;
} ngx_http_req_status_zone_node_t;

typedef struct {
    ngx_array_t                     req_zones;
    ngx_flag_t                      is_active;
    ngx_http_request_t             *request;
} ngx_http_req_status_ctx_t;

typedef struct {
    ngx_array_t                     zones;
    ngx_uint_t                      check_limit;

    ngx_msec_t                      interval;
    time_t                          lock_time;
    ngx_flag_t                      restore;
    ngx_msec_t                      dump_period;
    size_t                          dump_size;
    u_char                         *dump_buf;
    ngx_str_t                       dump_file;
    ngx_str_t                       dump_dir;
    ngx_path_t                     *dump_path;
    ngx_event_t                     dump_event;
} ngx_http_req_status_main_conf_t;

struct ngx_http_req_status_loc_conf_s {
    ngx_flag_t                      enabled;
    ngx_msec_t                      start_msec;
    ngx_array_t                     req_zones;
    ngx_http_req_status_loc_conf_t *parent;
};

static ngx_int_t ngx_http_req_status_parse_item(ngx_http_req_status_data_t *data,
        u_char *b, size_t len);

static ngx_http_module_t ngx_http_req_status_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_http_req_status_init,             /* postconfiguration */

    ngx_http_req_status_create_main_conf, /* create main configuration */
    ngx_http_req_status_init_main_conf,   /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_req_status_create_loc_conf,  /* create location configration */
    ngx_http_req_status_merge_loc_conf    /* merge location configration */
};


static ngx_command_t ngx_http_req_status_commands[] = {
    { ngx_string("req_status_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_req_status_zone,
      0,
      0,
      NULL
    },

    { ngx_string("req_status_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_http_req_status_main_conf_t, interval),
      NULL },

    { ngx_string("req_status_dump_period"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_http_req_status_main_conf_t, dump_period),
      NULL },

    { ngx_string("req_status_lock_time"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      0,
      offsetof(ngx_http_req_status_main_conf_t, lock_time),
      NULL },

    { ngx_string("req_status_check_limit"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_http_req_status_main_conf_t, check_limit),
      NULL
    },

    { ngx_string("req_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_req_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL
    },

    { ngx_string("req_status_restore"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_http_req_status_main_conf_t, restore),
      NULL
    },

    { ngx_string("req_status_show"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_req_status_show,
      0,
      0,
      NULL
    },

    { ngx_string("req_status_prometheus"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_req_status_prometheus,
      0,
      0,
      NULL
    },

    { ngx_string("req_status_check"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_req_status_check,
      0,
      0,
      NULL
    },

    { ngx_string("req_status_on"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_req_status_loc_conf_t, enabled),
      NULL
    },

    ngx_null_command
};


ngx_module_t ngx_http_req_status_module = {
    NGX_MODULE_V1,
    &ngx_http_req_status_module_ctx,
    ngx_http_req_status_commands,
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    ngx_http_req_status_init_module,          /* init module */
    ngx_http_req_status_init_process,         /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_req_status_init_module(ngx_cycle_t *cycle)
{
    ngx_http_req_status_main_conf_t        *rmcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "req status init module");

    rmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_req_status_module);

    if (rmcf->restore) {
        ngx_http_req_status_restore(cycle);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_req_status_init_process(ngx_cycle_t *cycle)
{
    ngx_event_t                            *dump_event;
    ngx_http_req_status_main_conf_t        *rmcf;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "req status init process");

    rmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_req_status_module);

    if (rmcf->restore) {
        /* dumper */
        dump_event = &rmcf->dump_event;
        dump_event->handler = ngx_http_req_status_dump_handler;
        dump_event->log = ngx_cycle->log;
        dump_event->data = rmcf;
        ngx_add_timer(dump_event, rmcf->dump_period);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_req_status_write_filter(ngx_http_request_t *r, off_t bsent)
{
    off_t                                   bytes;
    ngx_flag_t                              is_active;
    ngx_uint_t                              i, bw;
    ngx_msec_t                              td;
    ngx_http_req_status_ctx_t              *rctx;
    ngx_http_req_status_node_t             *node;
    ngx_http_req_status_data_t             *data;
    ngx_http_req_status_zone_node_t        *pzn;
    ngx_http_req_status_main_conf_t        *rmcf;

    rctx = ngx_http_get_module_ctx(r, ngx_http_req_status_module);
    if (rctx == NULL || rctx->req_zones.nelts == 0) {
        return NGX_DECLINED;
    }

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);

    pzn = rctx->req_zones.elts;
    bytes = r->connection->sent - bsent;
    is_active = 0;
    if (!rctx->is_active && r->headers_out.status == NGX_HTTP_OK) {
        is_active = 1;
    }

    for (i = 0; i < rctx->req_zones.nelts; i++) {
        node = pzn[i].node;
        data = &node->data;

        ngx_shmtx_lock(&pzn[i].zone->shpool->mutex);

        data->traffic += bytes;
        td = ngx_current_msec - node->last_traffic_start;

        if (node->last_traffic_start == 0) {
            node->last_traffic_start = ngx_current_msec;

        } else if (td > 0) {
            if (td >= rmcf->interval || (!data->bandwidth && td >= rmcf->interval / 2)) {
                bw = node->last_traffic * 1024 / td;
                if (bw > 0) {
                    data->bandwidth = bw;
                }
                if (data->bandwidth > data->max_bandwidth) {
                    data->max_bandwidth = data->bandwidth;
                }

                node->last_traffic = 0;
                node->last_traffic_start = ngx_current_msec;
            }
        }

        node->last_traffic += bytes;

        if (ngx_current_msec > node->last_traffic_update) {
            node->last_traffic_update = ngx_current_msec;
        }
        if (is_active) {
            node->active ++;
            if (node->active > node->data.max_active) {
                node->data.max_active = pzn[i].node->active;
            }
        }

        ngx_shmtx_unlock(&pzn[i].zone->shpool->mutex);
    }
    if (is_active) {
        rctx->is_active = 1;
    }

    return NGX_DECLINED;
}

static void
ngx_http_req_status_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_req_status_node_t      *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (ngx_http_req_status_node_t *) node;
            cnt = (ngx_http_req_status_node_t *) temp;

            p = (ngx_memn2cmp(cn->key, cnt->key, cn->len, cnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void
ngx_http_req_status_cleanup(void *data)
{
    ngx_uint_t                          i;
    ngx_http_req_status_ctx_t          *rctx = data;
    ngx_http_req_status_zone_node_t    *pzn;

#if (NGX_DEBUG)
    ngx_log_error(NGX_LOG_NOTICE, rctx->request->connection->log, 0, "req status cleanup %ui:%d:%ui",
                    rctx->request->method, rctx->is_active, rctx->req_zones.nelts);
#endif

    if (rctx->req_zones.nelts == 0)
        return;

    pzn = rctx->req_zones.elts;

    for (i = 0; i < rctx->req_zones.nelts; i++) {
        ngx_shmtx_lock(&pzn[i].zone->shpool->mutex);

        pzn[i].node->count --;
        if (rctx->is_active) {
            pzn[i].node->active --;
        }
        if (rctx->request && NGX_HTTP_POST == rctx->request->method) {
            pzn[i].node->active_post --;
        }

        ngx_shmtx_unlock(&pzn[i].zone->shpool->mutex);
    }
}

static ngx_int_t
ngx_http_set_header_helper(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value,
    ngx_table_elt_t **output_header, ngx_flag_t no_create)
{
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i, hash;
    ngx_flag_t                   matched = 0;

    hash = ngx_hash_key(value->data, value->len);
    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == key->len
            && ngx_strncasecmp(h[i].key.data, key->data,
                               h[i].key.len) == 0)
        {
            goto matched;
        }

        if (h[i].key.len >= key->len - 1
            && ngx_strncasecmp(h[i].key.data, key->data,
                               key->len - 1) == 0)
        {
            goto matched;
        }

        /* not matched */
        continue;

matched:

        if (value->len == 0 || matched) {

            h[i].value.len = 0;
            h[i].hash = 0;

        } else {
            h[i].value = *value;
            h[i].hash = hash;
        }

        if (output_header) {
            *output_header = &h[i];
        }

        matched = 1;
    }

    if (matched){
        return NGX_OK;
    }

    if (no_create && value->len == 0) {
        return NGX_OK;
    }

    /* XXX we still need to create header slot even if the value
     * is empty because some builtin headers like Last-Modified
     * relies on this to get cleared */

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        h->hash = 0;

    } else {
        h->hash = hash;
    }

    h->key = *key;
    h->value = *value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_req_status_handler(ngx_http_request_t *r)
{
    size_t                              len;
    uint32_t                            hash;
    ngx_str_t                           key;
    ngx_uint_t                          i;
    ngx_shm_zone_t                    **pzone;
    ngx_pool_cleanup_t                 *cln;
    ngx_http_req_status_ctx_t          *rctx;
    ngx_http_req_status_zone_t         *ctx;
    ngx_http_req_status_node_t         *ssn;
    ngx_http_req_status_loc_conf_t     *rlcf;
    ngx_http_req_status_zone_node_t    *pzn;

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_req_status_module);

    if (!rlcf->enabled) {
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_GET) {
        return NGX_DECLINED;
    }

    rctx = ngx_http_get_module_ctx(r, ngx_http_req_status_module);

    do {
        pzone = rlcf->req_zones.elts;

        for (i = 0; i < rlcf->req_zones.nelts; i++) {
            ctx = pzone[i]->data;

            if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
                continue;
            }

            if (key.len == 0) {
                continue;
            }

            if (key.len > 65535) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "req-status, the value of the \"%V\" variable "
                        "is more than 65535 bytes: \"%v\"",
                        &ctx->key.value, &key);
                continue;
            }

            if (rctx == NULL) {

                rctx = ngx_pcalloc(r->pool, sizeof(ngx_http_req_status_ctx_t));
                if (rctx == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rctx->request = r;
                if (ngx_array_init(&rctx->req_zones, r->pool, 2,
                            sizeof(ngx_http_req_status_zone_node_t))
                        != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                cln = ngx_pool_cleanup_add(r->pool, 0);
                if (cln == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                cln->handler = ngx_http_req_status_cleanup;
                cln->data = rctx;

                ngx_http_set_ctx(r, rctx, ngx_http_req_status_module);
            }

            hash = ngx_crc32_short(key.data, key.len);

            ngx_shmtx_lock(&ctx->shpool->mutex);

            ssn = ngx_http_req_status_lookup(ctx, hash, &key);

            if (ssn == NULL) {
                len  = sizeof(ngx_http_req_status_node_t) + key.len + 1;
                ssn = ngx_slab_calloc_locked(ctx->shpool, len);
                if (ssn == NULL) {
                    ngx_http_req_status_expire(ctx);

                    ssn = ngx_slab_calloc_locked(ctx->shpool, len);
                    if (ssn == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "req-status, slab alloc fail, zone = \"%V\", "
                                "key = \"%V\", size = %uz",
                                &ctx->shm_zone->shm.name, &key, len);

                        ngx_shmtx_unlock(&ctx->shpool->mutex);

                        continue;
                    }
                }

                ssn->node.key = hash;
                ssn->len = key.len;
                ssn->count = 1;

                ngx_memcpy(ssn->key, key.data, key.len);
                ssn->key[key.len] = '\0';

                ngx_rbtree_insert(&ctx->sh->rbtree, &ssn->node);
            }

            ssn->data.requests ++;
            if (NGX_HTTP_POST == r->method) {
                ssn->active_post ++;
            }

            ngx_queue_insert_head(&ctx->sh->queue, &ssn->queue);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            pzn = ngx_array_push(&rctx->req_zones);
            if (pzn == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            pzn->node = ssn;
            pzn->zone = ctx;
        }

        rlcf = rlcf->parent;
    } while (rlcf);

    return NGX_DECLINED;
}

static void *
ngx_http_req_status_lookup(void *conf, ngx_uint_t hash, ngx_str_t *key)
{
    ngx_int_t                       rc;
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_http_req_status_node_t     *ssn;
    ngx_http_req_status_zone_t     *ctx = conf;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        ssn = (ngx_http_req_status_node_t *)node;

        rc = ngx_memn2cmp(key->data, ssn->key, key->len, ssn->len);
        if (rc == 0) {
            ngx_queue_remove(&ssn->queue);

            ssn->count ++;

            return ssn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static void
ngx_http_req_status_expire(void *conf)
{
    ngx_queue_t                     *q;
    ngx_http_req_status_zone_t      *ctx = conf;
    ngx_http_req_status_node_t      *ssn;

    if (ngx_queue_empty(&ctx->sh->queue)) {
        return;
    }

    if (ctx->sh->expire_lock > ngx_time()) {
        return;
    }

    q =  ngx_queue_last(&ctx->sh->queue);

    ssn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);

    if (!ssn->data.requests || (ngx_current_msec > ssn->last_traffic_update &&
                ngx_current_msec - ssn->last_traffic_update >= 10 * 1000)) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                "req-status, release node, zone = \"%V\", key = \"%s\"",
                &ctx->shm_zone->shm.name, ssn->key);

        ngx_queue_remove(q);

        ngx_rbtree_delete(&ctx->sh->rbtree, &ssn->node);

        ngx_slab_free_locked(ctx->shpool, ssn);
    }
}


static u_char *
ngx_http_req_status_format_size(u_char *buf, ngx_uint_t v)
{
    u_char              scale;
    ngx_uint_t          size;

    if (v > 1024 * 1024 * 1024 - 1) {
        size = v / (1024 * 1024 * 1024);
        if ((v % (1024 * 1024 * 1024)) > (1024 * 1024 * 1024 / 2 - 1)) {
            size++;
        }
        scale = 'G';
    } else if (v > 1024 * 1024 - 1) {
        size = v / (1024 * 1024);
        if ((v % (1024 * 1024)) > (1024 * 1024 / 2 - 1)) {
            size++;
        }
        scale = 'M';
    } else if (v > 9999) {
        size = v / 1024;
        if (v % 1024 > 511) {
            size++;
        }
        scale = 'K';
    } else {
        size = v;
        scale = '\0';
    }

    if (scale) {
        return ngx_sprintf(buf, "%ui%c", size, scale);
    }

    return ngx_sprintf(buf, "%ui", size);
}

static int ngx_libc_cdecl
ngx_http_req_status_cmp_items(const void *one, const void *two)
{
    ngx_http_req_status_print_item_t *first = (ngx_http_req_status_print_item_t*) one;
    ngx_http_req_status_print_item_t *second = (ngx_http_req_status_print_item_t*) two;

    return (int)(first->zone_name == second->zone_name) ?
        ngx_strcmp(first->node->key, second->node->key) :
        ngx_strncmp(first->zone_name->data, second->zone_name->data, first->zone_name->len);
}



ngx_uint_t
ngx_http_req_status_get_current_bw(ngx_http_request_t *r)
{
    ngx_uint_t                          bw;
    ngx_queue_t                        *q;
    ngx_http_req_status_zone_t        **pzone;
    ngx_http_req_status_node_t         *rsn;
    ngx_http_req_status_main_conf_t    *rmcf;

    if (r == NULL) {
        rmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                    ngx_http_req_status_module);
    } else {
        rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
    }

    bw = 0;
    pzone = rmcf->zones.elts;

    if (rmcf->zones.nelts > 0) {
        ngx_shmtx_lock(&pzone[0]->shpool->mutex);

        for (q = ngx_queue_last(&pzone[0]->sh->queue);
                q != ngx_queue_sentinel(&pzone[0]->sh->queue);
                q = ngx_queue_prev(q))
        {
            rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);
            bw += rsn->data.bandwidth * 8 / 1024;
        }

        ngx_shmtx_unlock(&pzone[0]->shpool->mutex);
    }

    return bw;
}


ngx_uint_t
ngx_http_req_status_get_current_conns(ngx_http_request_t *r)
{
    ngx_uint_t                          n;
    ngx_queue_t                        *q;
    ngx_http_req_status_zone_t        **pzone;
    ngx_http_req_status_node_t         *rsn;
    ngx_http_req_status_main_conf_t    *rmcf;

    if (r == NULL) {
        rmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                    ngx_http_req_status_module);
    } else {
        rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
    }

    n = 0;
    pzone = rmcf->zones.elts;

    if (rmcf->zones.nelts > 0) {
        ngx_shmtx_lock(&pzone[0]->shpool->mutex);

        for (q = ngx_queue_last(&pzone[0]->sh->queue);
                q != ngx_queue_sentinel(&pzone[0]->sh->queue);
                q = ngx_queue_prev(q))
        {
            rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);
            n += rsn->active;
        }

        ngx_shmtx_unlock(&pzone[0]->shpool->mutex);
    }

    return n;
}


void
ngx_http_req_status_file_lock(ngx_file_t *file)
{
    ngx_err_t  err = ngx_lock_fd(file->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, file->log, err,
                  ngx_lock_fd_n " \"%s\" failed", file->name.data);
}


void
ngx_http_req_status_file_unlock(ngx_file_t *file)
{
    ngx_err_t  err = ngx_unlock_fd(file->fd);

    if (err == 0) {
        return;
    }

    ngx_log_error(NGX_LOG_ALERT, file->log, err,
                  ngx_unlock_fd_n " \"%s\" failed", file->name.data);
}


void
ngx_http_req_status_file_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}

static ngx_int_t
ngx_http_req_status_dump(ngx_event_t *ev)
{
    u_char                             *name, *last, *b;
    ssize_t                             n;
    ngx_fd_t                            fd;
    ngx_file_t                          file;
    ngx_uint_t                          i;
    ngx_queue_t                        *q;
    ngx_http_req_status_zone_t        **pzone;
    ngx_http_req_status_node_t         *rsn;
    ngx_http_req_status_main_conf_t    *rmcf;
    ngx_http_req_status_dump_header_t   file_header;

    ngx_log_error(NGX_LOG_DEBUG_CORE, ev->log, 0,
                      "req status dump");
    rmcf = (ngx_http_req_status_main_conf_t *) ev->data;

    b = rmcf->dump_buf;
    name = rmcf->dump_file.data;

    fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_TRUNCATE, 0666);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    file.fd = fd;
    file.name = rmcf->dump_file;
    file.log = ev->log;
    pzone = rmcf->zones.elts;

    ngx_http_req_status_file_lock(&file);

    ngx_memzero(&file_header, sizeof(ngx_http_req_status_dump_header_t));

    file_header.time = ngx_http_req_status_current_msec();
    file_header.version = nginx_version;

    n = ngx_write_fd(file.fd, &file_header, sizeof(ngx_http_req_status_dump_header_t));
    if (n != sizeof(ngx_http_req_status_dump_header_t)) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "req status dump header failed");

        ngx_http_req_status_file_unlock(&file);
        ngx_http_req_status_file_close(&file);

        return NGX_ERROR;
    }

    for (i = 0; i < rmcf->zones.nelts; i++) {
        ngx_shmtx_lock(&pzone[i]->shpool->mutex);

        q = ngx_queue_last(&pzone[i]->sh->queue);
        if (q == ngx_queue_sentinel(&pzone[i]->sh->queue)) {
            ngx_shmtx_unlock(&pzone[i]->shpool->mutex);
            continue;
        }

        last = ngx_sprintf(b, "\n%V;", &pzone[i]->shm_zone->shm.name);
        (void) ngx_write_fd(file.fd, b, last - b);

        for (;
                q != ngx_queue_sentinel(&pzone[i]->sh->queue);
                q = ngx_queue_prev(q))
        {
            rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);

            last = ngx_sprintf(b, "%s,%ui,%ui,%ui,%ui;",
                            rsn->key, rsn->data.traffic, rsn->data.max_bandwidth, rsn->data.requests, rsn->data.max_active);
            (void) ngx_write_fd(file.fd, b, last - b);
        }

        ngx_shmtx_unlock(&pzone[i]->shpool->mutex);
    }

    ngx_http_req_status_file_unlock(&file);
    ngx_http_req_status_file_close(&file);

    return NGX_OK;
}


static ngx_msec_t
ngx_http_req_status_current_msec(void)
{
    time_t           sec;
    ngx_uint_t       msec;
    struct timeval   tv;

    ngx_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (ngx_msec_t) sec * 1000 + msec;
}

static ngx_int_t
ngx_http_req_status_pre_dump(ngx_event_t *ev)
{
    ssize_t                                      n;
    ngx_fd_t                                     fd;
    ngx_int_t                                    rc;
    ngx_msec_t                                   current_msec;
    ngx_file_t                                   file;
    ngx_http_req_status_main_conf_t             *rmcf;
    ngx_http_req_status_dump_header_t            file_header;

    rmcf = (ngx_http_req_status_main_conf_t *) ev->data;

    fd = ngx_open_file(rmcf->dump_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, ngx_errno,
                       ngx_open_file_n " \"%s\" failed", rmcf->dump_file.data);
        return NGX_OK;
    }

    file.fd = fd;
    file.name = rmcf->dump_file;
    file.log = ev->log;

    ngx_memzero(&file_header, sizeof(ngx_http_req_status_dump_header_t));

    n = ngx_read_file(&file, (u_char *) &file_header,
                      sizeof(ngx_http_req_status_dump_header_t), 0);
    ngx_http_req_status_file_close(&file);

    if (n != sizeof(ngx_http_req_status_dump_header_t)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                      "req status header size:%z mismatch", n);
        return NGX_OK;
    }

    current_msec = ngx_http_req_status_current_msec();

    rc = ((current_msec - file_header.time) > rmcf->dump_period) ? NGX_OK : NGX_ERROR;

    return rc;
}

static ngx_int_t
ngx_http_req_status_parse_item(ngx_http_req_status_data_t *data, u_char *b, size_t len)
{
    size_t           n;
    u_char          *start, value[NGX_MAX_PATH];

    start = b;
    n = sscanf((const char *)start, "%[^,]", value);
    if (n != 1) {
        return NGX_ERROR;
    }
    data->traffic = ngx_atosz(value, ngx_strlen(value));
    start += ngx_strlen(value) + 1;

    n = sscanf((const char *)start, "%[^,]", value);
    if (n != 1) {
        return NGX_ERROR;
    }
    data->max_bandwidth = ngx_atosz(value, ngx_strlen(value));
    start += ngx_strlen(value) + 1;

    n = sscanf((const char *)start, "%[^,]", value);
    if (n != 1) {
        return NGX_ERROR;
    }
    data->requests = ngx_atosz(value, ngx_strlen(value));
    start += ngx_strlen(value) + 1;

    n = sscanf((const char *)start, "%[^;]", value);
    if (n != 1) {
        return NGX_ERROR;
    }
    data->max_active = ngx_atosz(value, ngx_strlen(value));

    return NGX_OK;
}


static ngx_int_t
ngx_http_req_status_restore(ngx_cycle_t *cycle)
{
    off_t                               offset;
    u_char                             *pos, *filename, *start, *end, *buffer;
    u_char                              tmp[NGX_MAX_PATH], name[NGX_MAX_PATH];
    ssize_t                             n, size;
    uint32_t                            hash;
    ngx_fd_t                            fd;
    ngx_str_t                           zone_name, key;
    ngx_uint_t                          i, is_start, new_line;
    ngx_file_t                          file;
    ngx_msec_t                          current_msec;
    ngx_http_req_status_zone_t        **pzones, *zone;
    ngx_http_req_status_node_t         *ssn;
    ngx_http_req_status_data_t          data;
    ngx_http_req_status_main_conf_t    *rmcf;
    ngx_http_req_status_dump_header_t   file_header;

    rmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_req_status_module);

    ngx_log_error(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "req status restore");

    buffer = rmcf->dump_buf;
    size = rmcf->dump_size;
    filename = rmcf->dump_file.data;

    fd = ngx_open_file(filename, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        return NGX_OK;
    }

    file.fd = fd;
    file.name = rmcf->dump_file;
    file.log = cycle->log;

    ngx_memzero(&file_header, sizeof(ngx_http_req_status_dump_header_t));

    n = ngx_read_file(&file, (u_char *) &file_header,
                      sizeof(ngx_http_req_status_dump_header_t), 0);

    if (n != sizeof(ngx_http_req_status_dump_header_t)) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "req status restore header size:%z mismatch", n);
        return NGX_OK;
    }

    if (file_header.version != nginx_version) {
        return NGX_OK;
    }

    current_msec = ngx_http_req_status_current_msec();

    if (current_msec - file_header.time > 1800000) {
        return NGX_OK;
    }

    offset = n;
    is_start = 1;
    new_line = 0;
    ngx_str_set(&zone_name, "");

    for ( ;; ) {
        n = ngx_read_file(&file, buffer, size, offset);
        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                          "req status restore read file error");
            break;
        }

        start = buffer;
        end = ngx_strlchr(start, start + n, '\n');
        if (end == NULL) {
            new_line = 0;
            end = start + n;
        } else if (end == start) {
            offset += 1;
            continue;
        } else {
            new_line = 1;
            if (end[-1] == '\r') {
                end--;
            }
        }

        if (is_start) {
            pos = ngx_strlchr(start, end, ';');
            if (pos == NULL) {
                break;
            }
            ngx_memmove(tmp, start, pos - start);
            zone_name.data = tmp;
            zone_name.len = pos - start;
            start = pos + 1;
        }

        ssn = NULL;
        zone = NULL;
        pzones = rmcf->zones.elts;

        for (i = 0; i < rmcf->zones.nelts; i++) {

            if (ngx_strncmp(zone_name.data, pzones[i]->shm_zone->shm.name.data, zone_name.len) != 0) {
                continue;
            }
            zone = pzones[i];
            break;
        }

        for ( ;start < end; ) {
            pos = ngx_strlchr(start, end, ';');
            if (pos == NULL) {
                break;
            }

            if (zone == NULL) {
                start = pos + 1;
                continue;
            }

            n = sscanf((const char *)start, "%[^,]", name);
            if (n != 1) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                                "req status restore failed get name");
                goto done;
            }
            n = ngx_strlen(name) + 1;
            ngx_memzero(&data, sizeof(ngx_http_req_status_data_t));
            if (ngx_http_req_status_parse_item(&data, start + n, pos - start - n) != NGX_OK) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                                "req status restore failed get data");
                goto done;
            }

            start = pos + 1;
            key.data = name;
            key.len = ngx_strlen(name);
            hash = ngx_crc32_short(key.data, key.len);
            ssn = ngx_http_req_status_lookup(zone, hash, &key);

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                            "req status restore '%V':'%V'", &zone->shm_zone->shm.name, &key);
            if (ssn == NULL) {
                n  = sizeof(ngx_http_req_status_node_t) + key.len + 1;
                ssn = ngx_slab_calloc_locked(zone->shpool, n);
                if (ssn == NULL) {
                    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                            "req-status, slab alloc fail, zone = \"%V\", "
                            "key = \"%V\", size = %uz",
                            &zone->shm_zone->shm.name, &key, n);
                    continue;
                }

                ssn->node.key = hash;
                ssn->len = key.len;
                ssn->count = 1;

                ngx_memcpy(ssn->key, key.data, key.len);
                ssn->key[key.len] = '\0';

                ngx_rbtree_insert(&zone->sh->rbtree, &ssn->node);
            }

            if (!ssn) {
                continue;
            }
            ngx_memcpy(&ssn->data, &data, sizeof(ngx_http_req_status_data_t));
            ngx_queue_insert_head(&zone->sh->queue, &ssn->queue);
        }

        offset += start - buffer;
        if (!new_line) {
            is_start = 0;
        } else {
            is_start = 1;
        }
    }

done:
    ngx_http_req_status_file_close(&file);

    return NGX_OK;
}

static void
ngx_http_req_status_dump_handler(ngx_event_t *ev)
{
    ngx_http_req_status_main_conf_t    *rmcf;

    if (ngx_exiting) {
        return;
    }

    if (ngx_http_req_status_pre_dump(ev) != NGX_OK) {
        goto finished;
    }

    ngx_http_req_status_dump(ev);

finished:

    rmcf = (ngx_http_req_status_main_conf_t *) ev->data;
    ngx_add_timer(ev, rmcf->dump_period);
}

#define NGX_HTTP_REQ_STATUS_PROMETHEUS_HEADER                                   \
    "# HELP nginx_req_status Nginx status\n"                                    \
    "# TYPE nginx_req_status gauge\n"                                           \
    "nginx_req_status{hostname=\"%V\",version=\"%s\"} 1\n"                      \
    "# HELP nginx_req_start_time_seconds Nginx start time\n"                    \
    "# TYPE nginx_req_start_time_seconds gauge\n"                               \
    "nginx_req_start_time_seconds %.3f\n"                                       \
    "# HELP nginx_req_filter_bytes_total The response bytes\n"                 \
    "# TYPE nginx_req_filter_bytes_total counter\n"                            \
    "# HELP nginx_req_filter_requests_total The requests counter\n"            \
    "# TYPE nginx_req_filter_requests_total counter\n"                         \
    "# HELP nginx_req_filter_bandwidth_bytes The request bandwidth\n"          \
    "# TYPE nginx_req_filter_bandwidth_bytes gauge\n"                          \
    "# HELP nginx_req_filter_active_total The request bandwidth \n"            \
    "# TYPE nginx_req_filter_active_total gauge\n"

static ngx_int_t
ngx_http_req_status_prometheus_handler(ngx_http_request_t *r)
{
    size_t                              size, item_size;
    ngx_int_t                           rc;
    ngx_buf_t                          *b;
    ngx_msec_t                          start_msec;
    ngx_uint_t                          i, bw;
    ngx_array_t                         items;
    ngx_queue_t                        *q;
    ngx_chain_t                         out;
    ngx_http_req_status_zone_t         *ctx;
    ngx_http_req_status_loc_conf_t     *rlcf;
    ngx_shm_zone_t                    **pzone;
    ngx_http_req_status_node_t         *rsn;
    ngx_http_req_status_main_conf_t    *rmcf;
    ngx_http_req_status_print_item_t   *item;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

#define NGX_STRCHR(s, u)  \
    (ngx_strlchr((s)->data, (s)->data + (s)->len, u) != NULL)

    item_size = sizeof(ngx_http_req_status_print_item_t);

    if (ngx_array_init(&items, r->pool, 40, item_size) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_req_status_module);

    item = NULL;
    start_msec = rlcf->start_msec;
    size = sizeof(NGX_HTTP_REQ_STATUS_PROMETHEUS_HEADER) + ngx_cycle->hostname.len + sizeof(NGINX_VERSION) + NGX_INT64_LEN;

    do {
        pzone = rlcf->req_zones.elts;

        for (i = 0; i < rlcf->req_zones.nelts; i++) {
            ctx = pzone[i]->data;
            ngx_shmtx_lock(&ctx->shpool->mutex);

            size += ctx->shm_zone->shm.name.len * 5;
            for (q = ngx_queue_last(&ctx->sh->queue);
                    q != ngx_queue_sentinel(&ctx->sh->queue);
                    q = ngx_queue_prev(q))
            {
                rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);

                item = ngx_array_push(&items);
                if (item == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                item->zone_name = &ctx->shm_zone->shm.name;
                item->node = rsn;
                item->pdata = &rsn->data;

                size += rsn->len +
                        (sizeof("nginx_req_filter_active_total{filter=\"%V\",filter_name=\"%s\",direction=\"out\"} %ui")
                            + NGX_INT64_LEN
                            + ngx_strlen(&rsn->key)) * 5;
            }

            ctx->sh->expire_lock = ngx_time() + rmcf->lock_time;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
        }

        rlcf = rlcf->parent;
    } while (rlcf);

    if (items.nelts > 1) {
        ngx_qsort(items.elts, (size_t) items.nelts, item_size,
                ngx_http_req_status_cmp_items);
    }

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_sprintf(b->last, NGX_HTTP_REQ_STATUS_PROMETHEUS_HEADER,
                        &ngx_cycle->hostname,
                        NGINX_VERSION,
                        (double) (ngx_http_req_status_current_msec() - start_msec) / 1000);

    item = items.elts;
    for (i = 0; i < items.nelts; i++) {
        if (i) {
            item = (ngx_http_req_status_print_item_t *)
                ((u_char *)item + item_size);
        }

        /* set pdata here because of qsort above */
        if (item->pdata == NULL) {
            item->pdata = &item->data[0];
        }

        bw = item->node->active ? item->pdata->bandwidth : 0;

        b->last = ngx_sprintf(b->last, "nginx_req_filter_bytes_total{filter=\"%V\",filter_name=\"%s\"} %ui\n",
                                        item->zone_name, item->node->key, item->pdata->traffic);
        b->last = ngx_sprintf(b->last, "nginx_req_filter_requests_total{filter=\"%V\",filter_name=\"%s\"} %ui\n",
                                        item->zone_name, item->node->key, item->pdata->requests);
        b->last = ngx_sprintf(b->last, "nginx_req_filter_bandwidth_bytes{filter=\"%V\",filter_name=\"%s\"} %ui\n",
                                        item->zone_name, item->node->key, bw * 8);
        b->last = ngx_sprintf(b->last, "nginx_req_filter_active_total{filter=\"%V\",filter_name=\"%s\",direction=\"in\"} %ui\n",
                                        item->zone_name, item->node->key, item->node->active_post);
        b->last = ngx_sprintf(b->last, "nginx_req_filter_active_total{filter=\"%V\",filter_name=\"%s\",direction=\"out\"} %ui\n",
                                        item->zone_name, item->node->key, item->node->active);
    }

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


#define NGX_HTTP_REQ_STATUS_HEADER   \
    "\"start_time\":%ui,"  \
    "\"header\":[\"url\",\"total_traffic\",\"max_bandwidth\",\"bandwidth\",\"total_request\",\"max_active\",\"active\",\"active_post\"]"

static ngx_int_t
ngx_http_req_status_show_handler(ngx_http_request_t *r)
{
    size_t                              size, item_size;
    u_char                              long_num, clear_status;
    ngx_int_t                           rc;
    ngx_buf_t                          *b;
    ngx_uint_t                          i, bw, start_time;
    ngx_array_t                         items;
    ngx_queue_t                        *q;
    ngx_chain_t                         out;
    ngx_http_req_status_zone_t         *ctx;
    ngx_http_req_status_loc_conf_t     *rlcf;
    ngx_shm_zone_t                    **pzone;
    ngx_http_req_status_node_t         *rsn;
    ngx_http_req_status_main_conf_t    *rmcf;
    ngx_http_req_status_print_item_t   *item;
    ngx_str_t                          *last_zone_name = NULL;
    static u_char                       json_data[] =  "data";

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_set(&r->headers_out.content_type, "application/json");

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

#define NGX_STRCHR(s, u)  \
    (ngx_strlchr((s)->data, (s)->data + (s)->len, u) != NULL)

    if (r->args.data) {
        long_num = (ngx_strstr(r->args.data, "sizeformat=true") == NULL);
        clear_status = (ngx_strstr(r->args.data, "clear=true") != NULL);
    } else {
        long_num = 1;
        clear_status = 0;
    }

    item_size = sizeof(ngx_http_req_status_print_item_t) +
        (clear_status ? sizeof(ngx_http_req_status_data_t) : 0);

    if (ngx_array_init(&items, r->pool, 40, item_size) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_req_status_module);
    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_req_status_module);

    start_time = rlcf->start_msec / 1000;
    size = sizeof(NGX_HTTP_REQ_STATUS_HEADER) + NGX_INT64_LEN + sizeof(json_data) + 2 * 4;

    do {
        pzone = rlcf->req_zones.elts;

        for (i = 0; i < rlcf->req_zones.nelts; i++) {
            ctx = pzone[i]->data;
            ngx_shmtx_lock(&ctx->shpool->mutex);

            size += ctx->shm_zone->shm.name.len + 1 * 4;
            for (q = ngx_queue_last(&ctx->sh->queue);
                    q != ngx_queue_sentinel(&ctx->sh->queue);
                    q = ngx_queue_prev(q))
            {
                rsn = ngx_queue_data(q, ngx_http_req_status_node_t, queue);

                size += rsn->len + (NGX_INT64_LEN) * 7 + 8 * 3;
                item = ngx_array_push(&items);
                if (item == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                item->zone_name = &ctx->shm_zone->shm.name;
                item->node = rsn;

                if (clear_status) {
                    item->pdata = NULL;
                    ngx_memcpy(&item->data[0], &rsn->data, sizeof(ngx_http_req_status_data_t));
                    ngx_memzero(&rsn->data, sizeof(ngx_http_req_status_data_t));
                } else {
                    item->pdata = &rsn->data;
                }
            }

            ctx->sh->expire_lock = ngx_time() + rmcf->lock_time;
            ngx_shmtx_unlock(&ctx->shpool->mutex);
        }

        rlcf = rlcf->parent;
    } while (rlcf);

    if (items.nelts > 1) {
        ngx_qsort(items.elts, (size_t) items.nelts, item_size,
                ngx_http_req_status_cmp_items);
    }

    ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "status json buffer size: %d", size);
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    item = items.elts;
    b->last = ngx_sprintf(b->last, "{");
    b->last = ngx_sprintf(b->last, NGX_HTTP_REQ_STATUS_HEADER, start_time);
    b->last = ngx_sprintf(b->last, ",\"%s\":{", json_data);

    for (i = 0; i < items.nelts; i++) {
        if (i) {
            item = (ngx_http_req_status_print_item_t *)
                ((u_char *)item + item_size);
        }
        if (last_zone_name == item->zone_name) {
            *b->last ++ = ',';
        } else if (last_zone_name) {
            b->last = ngx_sprintf(b->last, "],");
        }
        if (!last_zone_name || (last_zone_name != item->zone_name)) {
            last_zone_name = item->zone_name;
            b->last = ngx_sprintf(b->last, "\"%V\":[", item->zone_name);
        }

        /* set pdata here because of qsort above */
        if (item->pdata == NULL) {
            item->pdata = &item->data[0];
        }

        b->last = ngx_sprintf(b->last, "[\"%s\",", item->node->key);
        bw = item->node->active ? item->pdata->bandwidth : 0;

        if (long_num) {
            b->last = ngx_sprintf(b->last, "%ui,%ui,%ui,%ui,%ui,%ui,%ui",
                    item->pdata->traffic / 1024 / 1024, // MB
                    item->pdata->max_bandwidth * 8 / 1024, // kbps
                    bw * 8 / 1024, // kbps
                    item->pdata->requests,
                    item->pdata->max_active,
                    item->node->active,
                    item->node->active_post);
        } else {
            *b->last ++ = '\"';
            b->last = ngx_http_req_status_format_size(b->last, item->pdata->traffic);
            b->last = ngx_sprintf(b->last, "\",\"");
            b->last = ngx_http_req_status_format_size(b->last, item->pdata->max_bandwidth);
            b->last = ngx_sprintf(b->last, "\",\"");
            b->last = ngx_http_req_status_format_size(b->last, bw * 8);
            b->last = ngx_sprintf(b->last, "\",\"%ui\",\"%ui\",\"%ui\",\"%ui\"",
                            item->pdata->requests,
                            item->pdata->max_active,
                            item->node->active,
                            item->node->active_post);
        }
        *b->last ++ = ']';
        if (i + 1 >= items.nelts)
            b->last = ngx_sprintf(b->last, "]");
    }
    b->last = ngx_sprintf(b->last, "}}");

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}



static ngx_int_t
ngx_http_req_status_check_handler(ngx_http_request_t *r)
{
    u_char                             *pos;
    ngx_int_t                           rc;
    ngx_uint_t                          conns, bw;
    ngx_str_t                           key, value;
    ngx_buf_t                          *b;
    ngx_chain_t                         out;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_OK;

    conns = ngx_http_req_status_get_current_conns(r);
    bw = ngx_http_req_status_get_current_bw(r);

    ngx_str_set(&key, "Conns");
    value.data = ngx_pnalloc(r->pool, sizeof(ngx_uint_t) + 1);
    if (value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    pos = ngx_sprintf(value.data, "%ui", conns);
    value.len = pos - value.data;
    ngx_http_set_header_helper(r, &key, &value, NULL, 0);

    ngx_str_set(&key, "Bandwidth");
    value.data = ngx_pnalloc(r->pool, sizeof(ngx_uint_t) + 1);
    if (value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    pos = ngx_sprintf(value.data, "%ui", bw);
    value.len = pos - value.data;
    ngx_http_set_header_helper(r, &key, &value, NULL, 0);

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, sizeof(ngx_uint_t) * 2 + 2);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last = ngx_sprintf(b->last, "%ui;%ui;", conns, bw);

    out.buf = b;
    out.next = NULL;

    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_req_status_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_req_status_main_conf_t   *rmcf;

    rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_main_conf_t));
    if (rmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&rmcf->zones, cf->pool, 4,
                sizeof(ngx_http_req_status_zone_t *)) != NGX_OK)
    {
        return NULL;
    }

    rmcf->interval = NGX_CONF_UNSET_MSEC;
    rmcf->lock_time = NGX_CONF_UNSET;
    rmcf->check_limit = NGX_CONF_UNSET_UINT;
    rmcf->restore = NGX_CONF_UNSET;
    rmcf->dump_period = NGX_CONF_UNSET_MSEC;

    return rmcf;
}

static char *
ngx_http_req_status_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_req_status_main_conf_t *rmcf = conf;

    ngx_conf_init_msec_value(rmcf->interval, 3000);
    ngx_conf_init_value(rmcf->lock_time, 10);
    ngx_conf_init_uint_value(rmcf->check_limit, NGX_MAX_UINT32_VALUE);
    ngx_conf_init_msec_value(rmcf->dump_period, 15000);

    ngx_str_set(&rmcf->dump_dir, NGX_PREFIX"data");
    ngx_str_set(&rmcf->dump_file, NGX_PREFIX"data/req_status.db");
    ngx_create_dir(rmcf->dump_dir.data, 0775);

    rmcf->dump_size = NGX_INT64_LEN * 4 + NGX_MAX_PATH + 5;

    rmcf->dump_buf = ngx_palloc(cf->cycle->pool, rmcf->dump_size);
    if (rmcf->dump_buf == NULL) {
        return NGX_CONF_ERROR;
    }

    rmcf->dump_path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (rmcf->dump_path == NULL) {
        return NGX_CONF_ERROR;
    }

    rmcf->dump_path->name = rmcf->dump_dir;
    rmcf->dump_path->conf_file = cf->conf_file->file.name.data;
    rmcf->dump_path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &rmcf->dump_path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_req_status_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_req_status_loc_conf_t *rlcf;

    rlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_loc_conf_t));
    if (rlcf == NULL) {
        return NULL;
    }

    rlcf->enabled = NGX_CONF_UNSET;
    rlcf->start_msec = ngx_http_req_status_current_msec();
    rlcf->parent = NGX_CONF_UNSET_PTR;

    return rlcf;
}

static char *
ngx_http_req_status_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_req_status_loc_conf_t *prev = parent;
    ngx_http_req_status_loc_conf_t *conf = child;
    ngx_http_req_status_loc_conf_t *rlcf;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    if (conf->parent == NGX_CONF_UNSET_PTR) {
        rlcf = prev;

        if (rlcf->parent == NGX_CONF_UNSET_PTR) {
            rlcf->parent = NULL;
        } else {
            while (rlcf->parent && rlcf->req_zones.nelts == 0) {
                rlcf = rlcf->parent;
            }
        }

        conf->parent = rlcf->req_zones.nelts ? rlcf : NULL;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_req_status_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                      len;
    ngx_http_req_status_zone_t *ctx = shm_zone->data;
    ngx_http_req_status_zone_t *octx = data;

    if (octx) {
        if (ngx_strcmp(&octx->key.value, &ctx->key.value) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                    "req_status \"%V\" uses the \"%V\" variable "
                    "while previously it used the \"%V\" variable",
                    &shm_zone->shm.name, &ctx->key.value, &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_calloc(ctx->shpool, sizeof(ngx_http_req_status_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
            ngx_http_req_status_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    ctx->sh->expire_lock = 0;

    len = sizeof("in req_status zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_calloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in req_status zone \"%V\"%Z",
            &shm_zone->shm.name);

    return NGX_OK;
}

static char *
ngx_http_req_status_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                             size;
    ngx_str_t                          *value;
    ngx_http_req_status_zone_t         *ctx, **pctx;
    ngx_http_req_status_main_conf_t    *rmcf;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    size = ngx_parse_size(&value[3]);

    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid size of %V \"%V\"", &cmd->name, &value[3]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%V \"%V\" is too small", &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_req_status_zone_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ctx->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
            &ngx_http_req_status_module);
    if (ctx->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ctx->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%V \"%V\" is already bound",
                &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx->shm_zone->init = ngx_http_req_status_init_zone;
    ctx->shm_zone->data = ctx;

    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_req_status_module);

    pctx = ngx_array_push(&rmcf->zones);

    if (pctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *pctx = ctx;

    return NGX_CONF_OK;
}

static char *
ngx_http_req_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_req_status_loc_conf_t *rlcf = conf;

    ngx_str_t                      *value;
    ngx_uint_t                      i, m;
    ngx_shm_zone_t                 *shm_zone, **zones, **pzone;

    value = cf->args->elts;

    zones = rlcf->req_zones.elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].data[0] == '@') {
            rlcf->parent = NULL;

            if (value[i].len == 1) {
                continue;
            }

            value[i].data ++;
            value[i].len --;
        }

        shm_zone = ngx_shared_memory_add(cf, &value[i], 0,
                &ngx_http_req_status_module);
        if (shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }

        if (zones == NULL) {
            if (ngx_array_init(&rlcf->req_zones, cf->pool, 2, sizeof(ngx_shm_zone_t *))
                    != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

            zones = rlcf->req_zones.elts;
        }

        for (m = 0; m < rlcf->req_zones.nelts; m++) {
            if (shm_zone == zones[m]) {
                return "is duplicate";
            }
        }

        pzone = ngx_array_push(&rlcf->req_zones);
        if (pzone == NULL) {
            return NGX_CONF_ERROR;
        }

        *pzone = shm_zone;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_req_status_show(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_req_status_show_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_req_status_prometheus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_req_status_prometheus_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_req_status_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_req_status_check_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_req_status_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt               *h;
    ngx_http_core_main_conf_t         *cmcf;
    ngx_http_req_status_main_conf_t   *rmcf;

    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_req_status_module);

    if (rmcf->zones.nelts == 0) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_req_status_handler;

    ngx_http_top_write_filter = ngx_http_req_status_write_filter;

    return NGX_OK;
}
