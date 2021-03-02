%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 GLD Enterprise, Inc. (https://glodon.com)
%%% @Author: robertzhouxh <robertzhouxh@gmail.com>
%%% @Date   Created: 2021-01-15 09:31:45
%%%-------------------------------------------------------------------
-module(emqx_auth_hook).

-include("emqx_auth_redis.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-export([send_http_request/5]).

send_http_request(ClientID, Params, Path, Headers, Method) when Method == post orelse update ->
    Body = emqx_json:encode(Params),
    ?LOG_GLD("Method: ~p, Send to: ~0p, params: ~0s", [Method, Path, Body]),
    case ehttpc:request(ehttpc_pool:pick_worker(?WEB_HOOK_APP, ClientID), Method, {Path, Headers, Body}) of
        {ok, StatusCode, _Hdrs} when StatusCode >= 200 andalso StatusCode < 300 ->
            ok;
        {ok, StatusCode, _Hdrs, Data} when StatusCode >= 200 andalso StatusCode < 300 ->
            {ok, Data};
        {ok, StatusCode, _} ->
            ?LOG(warning, "HTTP request failed with status code: ~p", [StatusCode]),
	    {error, not_authorized};
        {ok, StatusCode, _, _} ->
            ?LOG(warning, "HTTP request failed with status code: ~p", [StatusCode]),
	    {error, not_authorized};
        {error, Reason} ->
            ?LOG(error, "HTTP request error: ~p", [Reason]), {error, not_authorized}
    end;

send_http_request(ClientID, _Params, Path, Headers, Method) when Method == get orelse delete ->
    ?LOG_GLD("ClientId: ~s, Method: ~p, Send to: ~0p~nHeaders: ~p~n", [ClientID, Method, Path, Headers]),
    case ehttpc:request(ehttpc_pool:pick_worker(?WEB_HOOK_APP, ClientID), Method, {Path, Headers}) of
        {ok, StatusCode, _Hdrs} when StatusCode >= 200 andalso StatusCode < 300 ->
            ok;
        {ok, StatusCode, _Hdrs, Data} when StatusCode >= 200 andalso StatusCode < 300 ->
            {ok, Data};
        {ok, StatusCode, _} ->
            ?LOG(warning, "HTTP request failed with status code: ~p", [StatusCode]),
	    {error, not_authorized};
        {ok, StatusCode, _, _} ->
            ?LOG(warning, "HTTP request failed with status code: ~p", [StatusCode]),
	    {error, not_authorized};
        {error, Reason} ->
            ?LOG(error, "HTTP request error: ~p", [Reason]), {error, not_authorized}
    end;
send_http_request(ClientID, _Params, Path, Headers, Method) -> {error, invalid_method}.


