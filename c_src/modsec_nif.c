#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"
#include <assert.h>
#include <erl_nif.h>
#include "modsec_nif.h"

void free_task(task_t *task)
{
    if (task->env != NULL)
        enif_free_env(task->env);
    enif_free(task);
}

task_t *alloc_task(task_type_t type)
{
    task_t *task = (task_t *)enif_alloc(sizeof(task_t));
    if (task == NULL)
        return NULL;
    (void)memset(task, 0, sizeof(task_t));
    task->type = type;
    return task;
}

task_t *alloc_init_task(task_type_t type, ModSecurity *modsec, RulesSet *rules, ERL_NIF_TERM ref, ErlNifPid pid, int num_orig_terms, const ERL_NIF_TERM orig_terms[])
{
    task_t *task = alloc_task(type);
    task->pid = pid;
    task->env = enif_alloc_env();
    task->modsec = modsec;
    task->rules = rules;
    if (task->env == NULL)
    {
        free_task(task);
        return NULL;
    }

    if (type == MODSEC_CHECK)
    {
        assert(num_orig_terms == 3);
        task->data.request.headers = enif_make_copy(task->env, orig_terms[1]);
        if (
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[0]), &task->data.request.uri) ||
            !enif_get_list_length(task->env, task->data.request.headers, &task->data.request.num_headers) ||
            !enif_inspect_binary(task->env, enif_make_copy(task->env, orig_terms[2]), &task->data.request.body))
        {
            free_task(task);
            return NULL;
        }
    }

    task->ref = enif_make_copy(task->env, ref);
    return task;
}

void msc_logdata(void *log, const void *data)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    printf("CustomLogger --- %lu.%lu %s\n", tv.tv_sec, tv.tv_usec, (char *)data);

    return;
}

static ERL_NIF_TERM check(task_t *task)
{
    Transaction *transaction = NULL;
    ERL_NIF_TERM head;
    ERL_NIF_TERM *tuple;
    ErlNifBinary req_header, req_header_val;
    int rc;
    int tuple_arity = 2;

    transaction = msc_new_transaction(task->modsec, task->rules, NULL);
    ERL_NIF_TERM list = task->data.request.headers;
    while (enif_get_list_cell(task->env, list, &head, (ERL_NIF_TERM *)&list))
    {
        if (!enif_get_tuple(task->env, head, &tuple_arity, &tuple) ||
            !enif_inspect_binary(task->env, tuple[0], &req_header) ||
            !enif_inspect_binary(task->env, tuple[1], &req_header_val))
        {
            return enif_make_tuple3(
                task->env,
                enif_make_atom(task->env, "error"),
                task->ref,
                enif_make_string(task->env, "invalid request headers", ERL_NIF_LATIN1));
        }

        msc_add_request_header(transaction, (unsigned char *)req_header.data, (unsigned char *)req_header_val.data);
    }
    msc_append_request_body(transaction, (unsigned char *)task->data.request.body.data, task->data.request.body.size);
    msc_process_connection(transaction, "127.0.0.1", 80, "127.0.0.1", 80);
    msc_process_uri(transaction, (char *)task->data.request.uri.data, "CONNECT", "1.1");
    msc_process_request_headers(transaction);
    msc_process_request_body(transaction);
    msc_process_logging(transaction);
    msc_transaction_cleanup(transaction);

    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    int inter = msc_intervention(transaction, &intervention);

    if (inter)
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "error"),
            task->ref);
    }
    else
    {
        return enif_make_tuple2(
            task->env,
            enif_make_atom(task->env, "ok"),
            task->ref);
    }
}

void *async_worker(void *arg)
{
    ctx_t *ctx;
    task_t *task;

    ERL_NIF_TERM result;

    ctx = (ctx_t *)arg;

    while (1)
    {
        task = (task_t *)async_queue_pop(ctx->queue);

        if (task->type == SHUTDOWN)
        {
            free_task(task);
            break;
        }
        else if (task->type == MODSEC_CHECK)
        {
            result = check(task);
        }
        else
        {
            errx(1, "Unexpected task type: %i", task->type);
        }

        enif_send(NULL, &task->pid, task->env, result);
        free_task(task);
    }

    return NULL;
}

static ERL_NIF_TERM modsec_check(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ctx_t *ctx;
    task_t *task;
    ErlNifPid pid;

    if (argc != 6)
        return enif_make_badarg(env);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], priv->modsec_rt, (void **)(&ctx)))
        return enif_make_badarg(env);

    if (!enif_is_ref(env, argv[1]))
        return enif_make_badarg(env);

    if (!enif_get_local_pid(env, argv[2], &pid))
        return enif_make_badarg(env);

    ERL_NIF_TERM orig_terms[] = {argv[3], argv[4], argv[5]};
    task = alloc_init_task(MODSEC_CHECK, ctx->modsec, ctx->rules, argv[1], pid, 3, orig_terms);

    if (!task)
        return enif_make_badarg(env);

    async_queue_push(ctx->queue, task);

    return enif_make_atom(env, "ok");
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
    ctx->rules = msc_create_rules_set();
    msc_set_log_cb(ctx->modsec, msc_logdata);
    ERL_NIF_TERM list = argv[0];
    while (enif_get_list_cell(env, list, &head, (ERL_NIF_TERM *)&list))
    {
        ErlNifBinary conf_file;
        if (!enif_inspect_binary(env, head, &conf_file))
        {
            return enif_make_badarg(env);
        }
        unsigned char conf_file_string[conf_file.size + 1];
        memcpy(conf_file_string, conf_file.data, conf_file.size);
        conf_file_string[conf_file.size] = '\0';
        msc_rules_add_file(ctx->rules, conf_file_string, &modsec_error);
        fprintf(stdout, "loading file %s\n", conf_file_string);
    }
    if (modsec_error != NULL)
    {
        fprintf(stderr, "init error %s\n", modsec_error);
    }

    ctx->queue = async_queue_create("modsec_queue_mutex", "modsec_queue_condvar");
    ctx->topts = enif_thread_opts_create("modsec_thread_opts");
    if (enif_thread_create("modsec_worker", &ctx->tid, async_worker, ctx, ctx->topts) != 0 || modsec_error != NULL)
    {
        enif_release_resource(ctx);
        return enif_make_badarg(env);
    }
    ret = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return ret;
}

static ErlNifFunc modsec_nif_funcs[] =
    {
        {"check", 6, modsec_check},
        {"create_ctx", 1, modsec_create_ctx},
};

static void modsec_rt_dtor(ErlNifEnv *env, void *obj)
{
    ctx_t *ctx = (ctx_t *)obj;
    task_t *task = alloc_task(SHUTDOWN);
    void *result = NULL;

    async_queue_push(ctx->queue, task);
    enif_thread_join(ctx->tid, &result);
    async_queue_destroy(ctx->queue);
    enif_thread_opts_destroy(ctx->topts);
}

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    const char *mod = "modsec_nif";
    const char *name = "nif_resource";

    ErlNifResourceFlags flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

    modsec_privdata_t *priv = (modsec_privdata_t *)enif_alloc(sizeof(modsec_privdata_t));
    priv->modsec_rt = enif_open_resource_type(env, mod, name, modsec_rt_dtor, flags, NULL);
    if (priv->modsec_rt == NULL)
        return -1;
    *priv_data = priv;
    return 0;
}

ERL_NIF_INIT(modsec_nif, modsec_nif_funcs, &on_load, NULL, NULL, NULL);