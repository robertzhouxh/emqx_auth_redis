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
    %% {ok, Sup} = emqx_auth_redis_sup:start_link(),
    %% translate_env(),
    %% {ok, PoolOpts} = application:get_env(?WEB_HOOK_APP, web_pool_opts),
    %% io:format("[WebHook] pool_opts: ~p~n", [PoolOpts]),
    %% ehttpc_sup:start_pool(?WEB_HOOK_APP, PoolOpts),
    case translate_env() of
        ok ->
            {ok, PoolOpts} = application:get_env(?APP, pool_opts),
            {ok, Sup} = emqx_http_client_sup:start_link(?APP, ssl(inet(PoolOpts))),
	    with_env(auth_req, fun load_auth_hook/1),
	    with_env(acl_req,  fun load_acl_hook/1),
            {ok, Sup};
        {error, Reason} ->
            {error, Reason}
    end.

stop(_State) ->
    emqx:unhook('client.authenticate', fun emqx_auth_redis:check/3),
    emqx:unhook('client.check_acl', fun emqx_acl_redis:check_acl/5),
    %% ehttpc_sup:stop_pool(?WEB_HOOK_APP),
    emqx_http_client_sup:stop_pool(emqx_auth_redis),
    eredis_cluster:stop_pool(?APP).

load_auth_hook(AuthReq) ->
    {ok, Timeout} = application:get_env(?APP, query_timeout),
    Type = proplists:get_value(type, application:get_env(?APP, server, [])),
    Config = #{timeout => Timeout,
               type => Type,
	       pool => ?APP,
	       auth_req => AuthReq,
               pool_http => emqx_auth_http},
    ok = emqx_auth_redis:register_metrics(),
    emqx:hook('client.authenticate', fun emqx_auth_redis:check/3, [Config]).

load_acl_hook(AclReq) ->
    {ok, Timeout} = applicatin:get_env(?APP, query_timeout),
    Type = proplists:get_value(type, application:get_env(?APP, server, [])),
    Config = #{timeout => Timeout,
               type => Type,
               pool => ?APP,
	       acl_req   => AclReq,
	       pool_http => emqx_auth_http},
    ok = emqx_acl_redis:register_metrics(),
    emqx:hook('client.check_acl', fun emqx_acl_redis:check_acl/5, [Config]).


%% ------------------------ http client --------------------------------------------
with_env(Par, Fun) ->
    case application:get_env(?APP, Par) of
        undefined -> ok;
        {ok, Req} -> Fun(r(Req))
    end.

r(undefined) -> undefined;
r(Config) ->
    Method = proplists:get_value(method, Config, post),
    Path    = proplists:get_value(path, Config),
    %% make sure there is no authorization http header
    Headers = application:get_env(?APP, headers, []),
    NewHeaders = case Method of
                    Method when Method =:= post orelse Method =:= put ->
			MHeaders = proplists:delete(<<"authorization">>, proplists:delete(<<"content-type">>, Headers)),
			[{<<"content-type">>, <<"application/json">>} | MHeaders];
                    _ ->
			proplists:delete(<<"authorization">>, proplists:delete(<<"content-type">>, Headers))
                 end,
    Params = proplists:get_value(params, Config),
    {ok, RequestTimeout} = application:get_env(?APP, request_timeout),
    #http_request{method = Method, path = Path, headers = NewHeaders, params = Params, request_timeout = RequestTimeout}.

inet(PoolOpts) ->
    Host = proplists:get_value(host, PoolOpts),
    TransOpts = proplists:get_value(transport_opts, PoolOpts, []),
    NewPoolOpts = proplists:delete(transport_opts, PoolOpts),
    Inet = case Host of
               {_,_,_,_} -> inet;
               {_,_,_,_,_,_,_,_} -> inet6;
               _ ->
                   case inet:getaddr(Host, inet6) of
                       {error, _} -> inet;
                       {ok, _} -> inet6
                   end
           end,
    [{transport_opts, [Inet | TransOpts]} | NewPoolOpts].

ssl(PoolOpts) ->
    case proplists:get_value(ssl, PoolOpts, []) of
        [] ->
            PoolOpts;
        SSLOpts ->
            TransOpts = proplists:get_value(transport_opts, PoolOpts, []),
            NewPoolOpts = proplists:delete(transport_opts, PoolOpts),
            [{transport_opts, SSLOpts ++ TransOpts}, {transport, ssl} | NewPoolOpts]
    end.

translate_env() ->
    URLs = lists:foldl(fun(Name, Acc) ->
                    case application:get_env(?APP, Name, []) of
                        [] -> Acc;
                        Env ->
                            URL = proplists:get_value(url, Env),
                            #{host := Host,
                              path := Path,
                              scheme := Scheme} = URIMap = uri_string:parse(add_default_scheme(URL)),
                            Port = maps:get(port, URIMap, case Scheme of
                                                              "https" -> 443;
                                                              _ -> 80
                                                          end),
                            [{Name, {Host, Port, path(Path)}} | Acc]
                    end
                end, [], [acl_req, auth_req, super_req]),
    case same_host_and_port(URLs) of
        true ->
            [begin
                 {ok, Req} = application:get_env(?APP, Name),
                 application:set_env(?APP, Name, [{path, Path} | Req])
             end || {Name, {_, _, Path}} <- URLs],
            {_, {Host, Port, _}} = lists:last(URLs),
            PoolOpts = application:get_env(?APP, pool_opts, []),
            NHost = case inet:parse_address(Host) of
                        {ok, {_,_,_,_} = Addr} -> Addr;
                        {ok, {_,_,_,_,_,_,_,_} = Addr} -> Addr;
                        {error, einval} -> Host
                    end,
            application:set_env(?APP, pool_opts, [{host, NHost}, {port, Port} | PoolOpts]),
            ok;
        false ->
            {error, different_server}
    end.

add_default_scheme("http://" ++ _ = URL) ->
    URL;
add_default_scheme("https://" ++ _ = URL) ->
    URL;
add_default_scheme(URL) ->
    "http://" ++ URL.

path("") -> "/";
path(Path) -> Path.

same_host_and_port([_]) ->
    true;
same_host_and_port([{_, {Host, Port, _}}, {_, {Host, Port, _}}]) ->
    true;
same_host_and_port([{_, {Host, Port, _}}, URL = {_, {Host, Port, _}} | Rest]) ->
    same_host_and_port([URL | Rest]);
same_host_and_port(_) ->
    false.
    
%% ------------------------- web-hook --------------------------------

% add_default_scheme(URL) when is_list(URL) ->
%     binary_to_list(add_default_scheme(list_to_binary(URL)));
% add_default_scheme(<<"http://", _/binary>> = URL) ->
%     URL;
% add_default_scheme(<<"https://", _/binary>> = URL) ->
%     URL;
% add_default_scheme(URL) ->
%     <<"http://", URL/binary>>.
% 
% translate_env() ->
%     {ok, URL} = application:get_env(?WEB_HOOK_APP, url),
%     #{host := Host0,
%       path := Path0,
%       scheme := Scheme} = URIMap = uri_string:parse(add_default_scheme(URL)),
%     Port = maps:get(port, URIMap, case Scheme of
%                                       "https" -> 443;
%                                       _ -> 80
%                                   end),
%     Path = path(Path0),
%     PoolSize = application:get_env(?WEB_HOOK_APP, web_pool_size, 8),
%     {Inet, Host} = parse_host(Host0),
%     MoreOpts = case Scheme of
%                "http" ->
%                    [{transport_opts, [Inet]}];
%                "https" ->
%                    CACertFile = application:get_env(?WEB_HOOK_APP, cafile, undefined),
%                    CertFile = application:get_env(?WEB_HOOK_APP, certfile, undefined),
%                    KeyFile = application:get_env(?WEB_HOOK_APP, keyfile, undefined),
%                    {ok, Verify} = application:get_env(?WEB_HOOK_APP, verify),
%                    VerifyType = case Verify of
%                                    true -> verify_peer;
%                                    false -> verify_none
%                                end,
%                    TLSOpts = lists:filter(fun({_K, V}) ->
%                                             V /= <<>> andalso V /= undefined andalso V /= "" andalso true
%                                           end, [{keyfile, KeyFile}, {certfile, CertFile}, {cacertfile, CACertFile}]),
%                    TlsVers = ['tlsv1.2','tlsv1.1',tlsv1],
%                    NTLSOpts = [{verify, VerifyType},
%                                {versions, TlsVers},
%                                {ciphers, lists:foldl(fun(TlsVer, Ciphers) ->
%                                                            Ciphers ++ ssl:cipher_suites(all, TlsVer)
%                                                        end, [], TlsVers)} | TLSOpts],
%                    [{transport, ssl}, {transport_opts, [Inet | NTLSOpts]}]
%             end,
%     PoolOpts = [{host, Host},
%                 {port, Port},
%                 {pool_size, PoolSize},
%                 {pool_type, hash},
%                 {connect_timeout, 5000},
%                 {retry, 5},
%                 {retry_timeout, 1000}] ++ MoreOpts,
%     %% application:set_env(?WEB_HOOK_APP, path, Path),
%     application:set_env(?WEB_HOOK_APP, web_pool_opts, PoolOpts),
%     Headers = application:get_env(?WEB_HOOK_APP, headers, []),
%     io:format("webhook-headers: ~p~n", [Headers]),
%     NHeaders = set_content_type(Headers),
%     application:set_env(?WEB_HOOK_APP, headers, NHeaders).
% 
% path("") -> "/";
% path(Path) -> Path.
% 
% set_content_type(Headers) ->
%     NHeaders = proplists:delete(<<"Content-Type">>, proplists:delete(<<"content-type">>, Headers)),
%     [{<<"content-type">>, <<"application/json">>} | NHeaders].
% 
% parse_host(Host) ->
%     case inet:parse_address(Host) of
%         {ok, Addr} when size(Addr) =:= 4 -> {inet, Addr};
%         {ok, Addr} when size(Addr) =:= 8 -> {inet6, Addr};
%         {error, einval} ->
%             case inet:getaddr(Host, inet6) of
%                 {ok, _} -> {inet6, Host};
%                 {error, _} -> {inet, Host}
%             end
%     end.

