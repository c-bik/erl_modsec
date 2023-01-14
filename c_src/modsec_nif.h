#ifndef ERLANG_MODSEC_MODSEC_NIF_H
#define ERLANG_MODSEC_MODSEC_NIF_H

typedef unsigned char byte;

typedef struct
{
    ErlNifResourceType *modsec_rt;
} modsec_privdata_t;

typedef struct
{
    RulesSet *rules;
    ModSecurity *modsec;
} ctx_t;

typedef struct
{
    ErlNifEnv *env;
    ErlNifPid pid;
    ERL_NIF_TERM ref;
    ModSecurity *modsec;
    RulesSet *rules;
    ERL_NIF_TERM logs;
    union
    {
        struct
        {
            ErlNifBinary method;
            ErlNifBinary uri;
            ErlNifBinary body;
            ERL_NIF_TERM headers;
        } d;
    } data;
} task_t;

#endif // ERLANG_MODSEC_MODSEC_NIF_H