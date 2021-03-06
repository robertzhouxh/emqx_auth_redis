%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 glodon Enterprise, Inc. (http://glodon.com)
%%% @Author: robertzhouxh <zhouxuehao@gmail.com>
%%% @Date   Created: 2021-01-07 18:18:18
%%%-------------------------------------------------------------------

-module(emqx_auth_redis_sup).

-behaviour(supervisor).

-include("emqx_auth_redis.hrl").

-export([start_link/0]).

-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, Server} = application:get_env(?APP, server),
    io:format("[Redis] Opts: ~p~n", [Server]),
    {ok, {{one_for_one, 10, 100}, pool_spec(Server)}}.

pool_spec(Server) ->
    Options = application:get_env(?APP, options, []),
    case proplists:get_value(type, Server) of
        cluster ->
            {ok, _} = eredis_cluster:start_pool(?APP, Server ++ Options),
            [];
        _ ->
            [ecpool:pool_spec(?APP, ?APP, emqx_auth_redis_cli, Server ++ Options)]
    end.

