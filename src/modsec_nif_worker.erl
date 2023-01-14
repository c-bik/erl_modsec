-module(modsec_nif_worker).
-behaviour(gen_server).

-export([start_link/1, start_link/2]).
-export([check_request/4, check_request/5, check_response/2, check_response/3]).

%% gen_server
-export([
    init/1,
    code_change/3,
    terminate/2,
    handle_call/3,
    handle_cast/2,
    handle_info/2
]).

-record(state, {
    waiting = [],
    running = maps:new(),
    num_workers,
    context
}).

start_link(ConfDirectoryPattern) ->
    NumWorkers = erlang:system_info(schedulers),
    start_link(ConfDirectoryPattern, NumWorkers).
start_link(ConfDirectoryPattern, NumWorkers) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [ConfDirectoryPattern, NumWorkers], []).

check_request(RequestMethod, RequestUri, RequestHeaders, RequestBody) ->
    check_request(?MODULE, RequestMethod, RequestUri, RequestHeaders, RequestBody).

check_request(NameOrPid, RequestMethod, RequestUri, RequestHeaders, RequestBody) ->
    %% RequestMethod and RequestUri must be 0 terminated
    gen_server:call(
        NameOrPid,
        {check_request, <<RequestMethod/binary, 0>>, <<RequestUri/binary, 0>>, RequestHeaders,
            RequestBody},
        infinity
    ).

check_response(ResponseHeaders, ResponseBody) ->
    check_response(?MODULE, ResponseHeaders, ResponseBody).

check_response(NameOrPid, ResponseHeaders, ResponseBody) ->
    gen_server:call(
        NameOrPid, {check_response, ResponseHeaders, ResponseBody}, infinity
    ).

init([ConfDirectoryPattern, NumWorkers]) ->
    ConfFiles = lists:filtermap(
        fun(F) ->
            case filelib:is_regular(F) of
                true ->
                    Filename = erlang:list_to_binary(F),
                    {true, <<Filename/binary, 0>>};
                false ->
                    false
            end
        end,
        filelib:wildcard(binary_to_list(ConfDirectoryPattern))
    ),
    Ctx = modsec_nif:create_ctx(ConfFiles),
    {ok, #state{context = Ctx, num_workers = NumWorkers}}.

terminate(shutdown, _) -> ok.

handle_call(Check, From, #state{waiting = Waiting} = State) ->
    {noreply, run(State#state{waiting = [{Check, From} | Waiting]})}.
handle_cast(Msg, _) -> exit({unknown_cast, Msg}).
handle_info({'DOWN', MRef, _, _, _}, #state{running = Running0} = State) ->
    Running1 = maps:remove(MRef, Running0),
    {noreply, run(State#state{running = Running1})};
handle_info(Msg, _) ->
    exit({unknown_info, Msg}).
code_change(_OldVsn, State, _Extra) -> {ok, State}.

run(
    #state{
        waiting = [{Check, From} | Waiting],
        num_workers = NumWorkers,
        running = Running0,
        context = Ctx
    } = State
) when map_size(Running0) < NumWorkers ->
    {RunPid, RunRef} = run_check(Check, From, Ctx),
    Running1 = maps:put(RunRef, RunPid, Running0),
    run(State#state{waiting = Waiting, running = Running1});
run(State) ->
    State.

run_check(
    {check_request, RequestMethod, RequestUri, RequestHeaders, RequestBody},
    From,
    Ctx
) ->
    spawn_monitor(fun() ->
        case
            modsec_nif:check_request(
                Ctx, RequestMethod, RequestUri, RequestHeaders, RequestBody
            )
        of
            {ok, Logs} ->
                gen_server:reply(From, {ok, Logs});
            {error, Logs} ->
                gen_server:reply(From, {error, Logs})
        end
    end);
run_check({check_response, ResponseHeaders, ResponseBody}, From, Ctx) ->
    spawn_monitor(fun() ->
        case modsec_nif:check_response(Ctx, ResponseHeaders, ResponseBody) of
            {ok, Logs} ->
                gen_server:reply(From, {ok, Logs});
            {error, Logs} ->
                gen_server:reply(From, {error, Logs})
        end
    end).
