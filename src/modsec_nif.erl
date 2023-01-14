-module(modsec_nif).
-export([init/0, check_request/5, check_response/3, create_ctx/1]).

-on_load(init/0).

init() ->
    Dir =
        case code:priv_dir(erl_modsec) of
            {error, bad_name} ->
                case code:which(modsec) of
                    Filename when is_list(Filename) ->
                        filename:join(
                            [filename:dirname(Filename), "../priv"]
                        );
                    _ ->
                        "../priv"
                end;
            Priv ->
                Priv
        end,
    erlang:load_nif(filename:join(Dir, "erl_modsec"), 0).

create_ctx(_ConfFiles) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

check_request(_Ctx, _Method, _URI, _Headers, _Body) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

check_response(_Ctx, _Headers, _Body) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).
