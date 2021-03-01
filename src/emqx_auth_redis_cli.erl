%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 glodon Enterprise, Inc. (http://glodon.com)
%%% @Author: robertzhouxh <zhouxuehao@gmail.com>
%%% @Date   Created: 2021-01-07 18:18:18
%%%-------------------------------------------------------------------

-module(emqx_auth_redis_cli).

-behaviour(ecpool_worker).

-include("emqx_auth_redis.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-import(proplists, [get_value/2, get_value/3]).

-export([ connect/1
        , q/4
        ]).

%%--------------------------------------------------------------------
%% Redis Connect/Query
%%--------------------------------------------------------------------

connect(Opts) ->
    Sentinel = get_value(sentinel, Opts),
    Host = case Sentinel =:= "" of
        true -> get_value(host, Opts);
        false ->
            eredis_sentinel:start_link(get_value(servers, Opts)),
            "sentinel:" ++ Sentinel
    end,
    case eredis:start_link(Host,
                           get_value(port, Opts, 6379),
                           get_value(database, Opts, 0),
                           get_value(password, Opts, ""),
                           3000,
                           5000,
                           get_value(options, Opts, [])) of
            {ok, Pid} -> {ok, Pid};
            {error, Reason = {connection_error, _}} ->
                ?LOG(error, "[Redis] Can't connect to Redis server: Connection refused."),
                {error, Reason};
            {error, Reason = {authentication_error, _}} ->
                ?LOG(error, "[Redis] Can't connect to Redis server: Authentication failed."),
                {error, Reason};
            {error, Reason} ->
                ?LOG(error, "[Redis] Can't connect to Redis server: ~p", [Reason]),
                {error, Reason}
    end.

%% Redis Query.
%% -spec(q(atom(), atom(), string(), emqx_types:credentials(), timeout())
%%       -> {ok, undefined | binary() | list()} | {error, atom() | binary()}).
q(Pool, Type, Cmd, Timeout) ->
    case Type of
        cluster -> eredis_cluster:q(Pool, Cmd);
        _ -> ecpool:with_client(Pool, fun(C) -> eredis:q(C, Cmd, Timeout) end)
    end.

%% -spec(q(atom(), atom(), string(), emqx_types:credentials(), timeout())
%%       -> {ok, undefined | binary() | list()} | {error, atom() | binary()}).
%% q(Pool, Type, CmdStr, Credentials, Timeout) ->
%%     Cmd = string:tokens(replvar(CmdStr, Credentials), " "),
%%     Cmd = string:tokens(CmdStr, " "),
%%     case Type of
%%         cluster -> eredis_cluster:q(Pool, Cmd);
%%         _ -> ecpool:with_client(Pool, fun(C) -> eredis:q(C, Cmd, Timeout) end)
%%     end.

%% replvar(Cmd, Credentials = #{cn := CN}) ->
%%     replvar(repl(Cmd, "%C", CN), maps:remove(cn, Credentials));
%% replvar(Cmd, Credentials = #{dn := DN}) ->
%%     replvar(repl(Cmd, "%d", DN), maps:remove(dn, Credentials));
%% replvar(Cmd, Credentials = #{clientid := ClientId}) ->
%%     replvar(repl(Cmd, "%c", ClientId), maps:remove(clientid, Credentials));
%% replvar(Cmd, Credentials = #{username := Username}) ->
%%     replvar(repl(Cmd, "%u", Username), maps:remove(username, Credentials));
%% replvar(Cmd, _) ->
%%     Cmd.

%% repl(S, _Var, undefined) ->
%%     S;
%% repl(S, Var, Val) ->
%%     NVal = re:replace(Val, "&", "\\\\&", [global, {return, list}]),
%%     re:replace(S, Var, NVal, [{return, list}]).

