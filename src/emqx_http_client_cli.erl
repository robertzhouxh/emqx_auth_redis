-module(emqx_http_client_cli).

-include("emqx_auth_redis.hrl").

-export([ request/6
        , feedvar/2
        , feedvar/3
        ]).

%%--------------------------------------------------------------------
%% HTTP Request
%%--------------------------------------------------------------------

request(PoolName, get, Path, Headers, _Params, Timeout) ->
    %% NewPath = Path ++ "?" ++ binary_to_list(cow_qs:qs(bin_kw(Params))),
    do_request(get, PoolName, {Path, Headers}, Timeout);

request(PoolName, post, Path, Headers, Params, Timeout) ->
    %% Body = case proplists:get_value(<<"content-type">>, Headers) of
    %%            <<"application/x-www-form-urlencoded">> ->
    %%                cow_qs:qs(bin_kw(Params));
    %%            <<"application/json">> -> 
    %%                emqx_json:encode(bin_kw(Params))
    %%        end,
    do_request(post, PoolName, {Path, Headers, emqx_json:encode(Params)}, Timeout).

do_request(Method, PoolName, Req, Timeout) ->
    do_request(Method, PoolName, Req, Timeout, 3).

%% Only retry when connection closed by keepalive
do_request(_Method, _PoolName, _Req, _Timeout, 0) ->
    {error, normal};
do_request(Method, PoolName, Req, Timeout, Retry) ->
    ?LOG_GLD("[HTTP] ==> method:[~s], poolName:[~s], Req:~p~n", [Method, PoolName, Req]),
    case emqx_http_client:request(Method, PoolName, Req, Timeout) of
        {error, normal} ->
            do_request(Method, PoolName, Req, Timeout, Retry - 1);
        {error, Reason} ->
            {error, Reason};
        {ok, StatusCode, _Headers} ->
            {ok, StatusCode, <<>>};
        {ok, StatusCode, _Headers, Body} ->
            {ok, StatusCode, Body}
    end.

%% TODO: move this conversion to cuttlefish config and schema
bin_kw(KeywordList) when is_list(KeywordList) ->
    [{bin(K), bin(V)} || {K, V} <- KeywordList].

bin(Atom) when is_atom(Atom) ->
    list_to_binary(atom_to_list(Atom));
bin(Int) when is_integer(Int) ->
    integer_to_binary(Int);
bin(Float) when is_float(Float) ->
    float_to_binary(Float, [{decimals, 12}, compact]);
bin(List) when is_list(List)->
    list_to_binary(List);
bin(Binary) when is_binary(Binary) ->
    Binary.

%%--------------------------------------------------------------------
%% Feed Variables
%%--------------------------------------------------------------------

feedvar(Params, ClientInfo = #{clientid := ClientId}) ->
    lists:map(fun({Param, "%u"}) -> {Param, maps:get(username, ClientInfo, null)};
                 ({Param, "%c"}) -> {Param, ClientId};
                 ({Param, "%P"}) -> {Param, maps:get(password, ClientInfo, null)};
                 ({Param, "%m"}) -> {Param, maps:get(mountpoint, ClientInfo, null)};
                 ({Param, Var})  -> {Param, Var}
              end, Params);
feedvar(Params, _ClientInfo) -> Params.

feedvar(Params, Var, Val) ->
    lists:map(fun({Param, Var0}) when Var0 == Var ->
                      {Param, Val};
                 ({Param, Var0}) ->
                      {Param, Var0}
              end, Params).

