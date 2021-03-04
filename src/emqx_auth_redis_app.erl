%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 glodon Enterprise, Inc. (http://glodon.com)
%%% @Author: robertzhouxh <zhouxuehao@gmail.com>
%%% @Date   Created: 2021-01-07 18:18:18
%%%-------------------------------------------------------------------

-module(emqx_auth_redis_app).

-behaviour(application).

-emqx_plugin(auth).

-include("emqx_auth_redis.hrl").

-export([ start/2
        , stop/1
        ]).

start(_StartType, _StartArgs) ->
    {ok, Sup} = emqx_auth_redis_sup:start_link(),
    if_cmd_enabled(auth_cmd, fun load_auth_hook/1),
    if_cmd_enabled(acl_cmd,  fun load_acl_hook/1),
    translate_env(),
    {ok, PoolOpts} = application:get_env(?WEB_HOOK_APP, web_pool_opts),
    io:format("WebHook-web_pool_opts: ~p~n", [PoolOpts]),
    ehttpc_sup:start_pool(?WEB_HOOK_APP, PoolOpts),
    {ok, Sup}.

stop(_State) ->
    emqx:unhook('client.authenticate', fun emqx_auth_redis:check/3),
    emqx:unhook('client.check_acl', fun emqx_acl_redis:check_acl/5),
    %% Ensure stop cluster pool if the server type is cluster
    ehttpc_sup:stop_pool(?WEB_HOOK_APP),
    eredis_cluster:stop_pool(?APP).

load_auth_hook(AuthCmd) ->
    SuperCmd = application:get_env(?APP, super_cmd, undefined),
    {ok, HashType} = application:get_env(?APP, password_hash),
    {ok, Timeout} = application:get_env(?APP, query_timeout),
    Type = proplists:get_value(type, application:get_env(?APP, server, [])),
    Config = #{auth_cmd => AuthCmd,
               super_cmd => SuperCmd,
               hash_type => HashType,
               timeout => Timeout,
               type => Type,
               pool => ?APP},
    ok = emqx_auth_redis:register_metrics(),
    emqx:hook('client.authenticate', fun emqx_auth_redis:check/3, [Config]).

load_acl_hook(AclCmd) ->
    {ok, Timeout} = application:get_env(?APP, query_timeout),
    Type = proplists:get_value(type, application:get_env(?APP, server, [])),
    Config = #{acl_cmd => AclCmd,
               timeout => Timeout,
               type => Type,
               pool => ?APP},
    ok = emqx_acl_redis:register_metrics(),
    emqx:hook('client.check_acl', fun emqx_acl_redis:check_acl/5, [Config]).

if_cmd_enabled(Par, Fun) ->
    case application:get_env(?APP, Par) of
        {ok, Cmd} -> Fun(Cmd);
        undefined -> ok
    end.

%% ------------------------- web-hook --------------------------------

add_default_scheme(URL) when is_list(URL) ->
    binary_to_list(add_default_scheme(list_to_binary(URL)));
add_default_scheme(<<"http://", _/binary>> = URL) ->
    URL;
add_default_scheme(<<"https://", _/binary>> = URL) ->
    URL;
add_default_scheme(URL) ->
    <<"http://", URL/binary>>.

translate_env() ->
    {ok, URL} = application:get_env(?WEB_HOOK_APP, url),
    #{host := Host0,
      path := Path0,
      scheme := Scheme} = URIMap = uri_string:parse(add_default_scheme(URL)),
    Port = maps:get(port, URIMap, case Scheme of
                                      "https" -> 443;
                                      _ -> 80
                                  end),
    Path = path(Path0),
    PoolSize = application:get_env(?WEB_HOOK_APP, web_pool_size, 8),
    {Inet, Host} = parse_host(Host0),
    MoreOpts = case Scheme of
                   "http" ->
                       [{transport_opts, [Inet]}];
                   "https" ->
                       CACertFile = application:get_env(?WEB_HOOK_APP, web_cafile, undefined),
                       CertFile = application:get_env(?WEB_HOOK_APP, web_certfile, undefined),
                       KeyFile = application:get_env(?WEB_HOOK_APP, web_keyfile, undefined),
                       {ok, Verify} = application:get_env(?WEB_HOOK_APP, web_verify),
                       VerifyType = case Verify of
                                       true -> verify_peer;
                                       false -> verify_none
                                   end,
                       TLSOpts = lists:filter(fun({_K, V}) when V =:= <<>> ->
                                                   false;
                                                   (_) ->
                                                   true
                                               end, [{keyfile, KeyFile}, {certfile, CertFile}, {cacertfile, CACertFile}]),
                       TlsVers = ['tlsv1.2','tlsv1.1',tlsv1],
                       NTLSOpts = [{verify, VerifyType},
                                   {versions, TlsVers},
                                   {ciphers, lists:foldl(fun(TlsVer, Ciphers) ->
                                                               Ciphers ++ ssl:cipher_suites(all, TlsVer)
                                                           end, [], TlsVers)} | TLSOpts],
                       [{transport, ssl}, {transport_opts, [Inet | NTLSOpts]}]
                end,
    PoolOpts = [{host, Host},
                {port, Port},
                {pool_size, PoolSize},
                {pool_type, hash},
                {connect_timeout, 5000},
                {retry, 5},
                {retry_timeout, 1000}] ++ MoreOpts,
    %% application:set_env(?WEB_HOOK_APP, path, Path),
    application:set_env(?WEB_HOOK_APP, web_pool_opts, PoolOpts),
    Headers = application:get_env(?WEB_HOOK_APP, headers, []),
    io:format("webhook-headers: ~p~n", [Headers]),
    NHeaders = set_content_type(Headers),
    application:set_env(?WEB_HOOK_APP, headers, NHeaders).

path("") ->
    "/";
path(Path) ->
    Path.

set_content_type(Headers) ->
    NHeaders = proplists:delete(<<"Content-Type">>, proplists:delete(<<"content-type">>, Headers)),
    [{<<"content-type">>, <<"application/json">>} | NHeaders].

parse_host(Host) ->
    case inet:parse_address(Host) of
        {ok, Addr} when size(Addr) =:= 4 -> {inet, Addr};
        {ok, Addr} when size(Addr) =:= 8 -> {inet6, Addr};
        {error, einval} ->
            case inet:getaddr(Host, inet6) of
                {ok, _} -> {inet6, Host};
                {error, _} -> {inet, Host}
            end
    end.
