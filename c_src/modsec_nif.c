#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"
#include <assert.h>
#include <erl_nif.h>
#include "modsec_nif.h"

// to supress no previous prototype warnings
void free_task(task_t *);
task_t *alloc_init_task(ErlNifEnv *, ModSecurity *, RulesSet *);
void msc_logdata(void *, const void *);

void free_task(task_t *task)
{
    if (task->env != NULL)
        enif_free_env(task->env);
    enif_free(task);
}

task_t *alloc_init_task(ErlNifEnv *env, ModSecurity *modsec, RulesSet *rules)
{
    task_t *task = enif_alloc(sizeof(task_t));
    if (task == NULL)
        return NULL;
    memset(task, 0, sizeof(task_t));
    task->env = env;
    task->modsec = modsec;
    task->rules = rules;
    task->logs = enif_make_list(task->env, 0);
    if (task->env == NULL)
    {
        free_task(task);
        return NULL;
    }
    return task;
}

void msc_logdata(void *cb_data, const void *data)
{
    task_t *task = (task_t *)cb_data;
    size_t len = strlen((const char *)data); // to make sure that trailing NULL (aka \0) is also copied
    ErlNifBinary bin;
    enif_alloc_binary(len, &bin);
    memcpy(bin.data, data, len);
    ERL_NIF_TERM log_binary = enif_make_binary(task->env, &bin);
    task->logs = enif_make_list_cell(task->env, log_binary, task->logs);
    return;
}

static int process_intervention(task_t *task, Transaction *transaction, char *log_str)
{
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    if (msc_intervention(transaction, &intervention) == 0)
    {
        return 0;
    };

    if (intervention.log == NULL)
    {
        msc_logdata((void *)task, "(no log message was specified)");
    }
    else
    {
        msc_logdata((void *)task, intervention.log);
        // FIXME This may cause segfault or even worse memory corruptions
        // since intervention.log allocation didn't happen in this scope!
        free(intervention.log);
    }

    return 1;
}

static ERL_NIF_TERM check_request(ErlNifEnv *env, ModSecurity *modsec, RulesSet *rules, ErlNifBinary method, ErlNifBinary uri, ERL_NIF_TERM headers, ErlNifBinary body)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;

    task_t *task = alloc_init_task(env, modsec, rules);

    transaction = msc_new_transaction(modsec, rules, (void *)task);
    while (enif_get_list_cell(env, headers, &head, (ERL_NIF_TERM *)&headers))
    {
        if (!enif_get_tuple(env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(env, tuple[0], &header_name) ||
            !enif_inspect_binary(env, tuple[1], &header_value))
        {
            return enif_make_tuple2(
                env,
                enif_make_atom(env, "error"),
                enif_make_string(env, "invalid request headers", ERL_NIF_LATIN1));
        }
        msc_add_n_request_header(transaction,
                                 (const unsigned char *)header_name.data, header_name.size,
                                 (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_request_body(transaction, (unsigned char *)body.data, body.size);
    msc_process_connection(transaction, "127.0.0.1", 80, "127.0.0.1", 80);
    int i1 = process_intervention(task, transaction, "process connection %i\n");
    msc_process_uri(transaction, (const char *)uri.data, (const char *)method.data, "1.1");
    int i2 = process_intervention(task, transaction, "process uri %i\n");
    msc_process_request_headers(transaction);
    int i3 = process_intervention(task, transaction, "process request headers %i\n");
    msc_process_request_body(transaction);
    int i4 = process_intervention(task, transaction, "process request body %i\n");
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2 | i3 | i4)
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            task->logs);
    }
    else
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            task->logs);
    }
}

static ERL_NIF_TERM check_response(ErlNifEnv *env, ModSecurity *modsec, RulesSet *rules, ERL_NIF_TERM headers, ErlNifBinary body)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary header_name, header_value;
    int tuple_arity = 2;
    task_t *task = alloc_init_task(env, modsec, rules);

    transaction = msc_new_transaction(modsec, rules, (void *)task);
    while (enif_get_list_cell(env, headers, &head, (ERL_NIF_TERM *)&headers))
    {
        if (!enif_get_tuple(env, head, &tuple_arity, (const ERL_NIF_TERM **)&tuple) ||
            !enif_inspect_binary(env, tuple[0], &header_name) ||
            !enif_inspect_binary(env, tuple[1], &header_value))
        {
            return enif_make_tuple2(
                env,
                enif_make_atom(env, "error"),
                enif_make_string(env, "invalid response headers", ERL_NIF_LATIN1));
        }

        msc_add_n_response_header(transaction,
                                  (const unsigned char *)header_name.data, header_name.size,
                                  (const unsigned char *)header_value.data, header_value.size);
    }
    msc_append_response_body(transaction, (unsigned char *)body.data, body.size);
    msc_process_response_headers(transaction, 200, "HTTP 2.0");
    int i1 = process_intervention(task, transaction, "response headers %i\n");
    msc_process_response_body(transaction);
    int i2 = process_intervention(task, transaction, "response body %i\n");
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    if (i1 | i2)
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            task->logs);
    }
    else
    {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            task->logs);
    }
}

static ERL_NIF_TERM modsec_check_request(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ctx_t *ctx;

    if (argc != 5)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], priv->modsec_rt, (void **)(&ctx)))
        return enif_make_badarg(env);

    ErlNifBinary method, uri, body;
    enif_inspect_binary(env, argv[1], &method);
    enif_inspect_binary(env, argv[2], &uri);
    enif_inspect_binary(env, argv[4], &body);

    return check_request(env, ctx->modsec, ctx->rules, method, uri, argv[3], body);
}

static ERL_NIF_TERM modsec_check_response(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ctx_t *ctx;

    if (argc != 3)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], priv->modsec_rt, (void **)(&ctx)))
        return enif_make_badarg(env);

    ErlNifBinary body;
    enif_inspect_binary(env, argv[2], &body);

    return check_response(env, ctx->modsec, ctx->rules, argv[1], body);
}

static ERL_NIF_TERM modsec_create_ctx(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{

    const char *modsec_error = NULL;
    ERL_NIF_TERM ret, head;

    if (argc != 1)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);
    ctx_t *ctx = (ctx_t *)enif_alloc_resource(priv->modsec_rt, sizeof(ctx_t));
    if (ctx == NULL)
        return enif_make_badarg(env);

    ctx->modsec = msc_init();
    msc_set_log_cb(ctx->modsec, msc_logdata);
    ctx->rules = msc_create_rules_set();
    ERL_NIF_TERM list = argv[0];
    while (enif_get_list_cell(env, list, &head, (ERL_NIF_TERM *)&list))
    {
        ErlNifBinary conf_file;
        if (!enif_inspect_binary(env, head, &conf_file))
        {
            return enif_make_badarg(env);
        }
        msc_rules_add_file(ctx->rules, (const char *)conf_file.data, &modsec_error);
        fprintf(stdout, "loading file %s\n", conf_file.data);
    }
    if (modsec_error != NULL)
    {
        fprintf(stderr, "init error %s\n", modsec_error);
    }

    ret = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return ret;
}

static ErlNifFunc modsec_nif_funcs[] =
    {
        {"check_request", 5, modsec_check_request, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"check_response", 3, modsec_check_response, ERL_NIF_DIRTY_JOB_CPU_BOUND},
        {"create_ctx", 1, modsec_create_ctx},
};

static void modsec_rt_dtor(ErlNifEnv *env, void *obj)
{
    ctx_t *ctx = (ctx_t *)obj;
    msc_rules_cleanup(ctx->rules);
    msc_cleanup(ctx->modsec);
    return;
}

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    const char *mod = "modsec_nif";

    ErlNifResourceFlags flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_alloc(sizeof(modsec_privdata_t));
    priv->modsec_rt = enif_open_resource_type(env, mod, "modsec_rt", modsec_rt_dtor, flags, NULL);
    if (priv->modsec_rt == NULL)
        return -1;

    *priv_data = priv;
    return 0;
}

ERL_NIF_INIT(modsec_nif, modsec_nif_funcs, &on_load, NULL, NULL, NULL);