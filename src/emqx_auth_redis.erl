%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 glodon Enterprise, Inc. (http://glodon.com)
%%% @Author: robertzhouxh <zhouxuehao@gmail.com>
%%% @Date   Created: 2021-01-07 18:18:18
%%%-------------------------------------------------------------------

-module(emqx_auth_redis).

-include("emqx_auth_redis.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-export([ register_metrics/0
        , check/3
        , description/0
        ]).

-spec(register_metrics() -> ok).
register_metrics() ->
    lists:foreach(fun emqx_metrics:ensure/1, ?AUTH_METRICS).

%% check user
check(ClientInfo = #{password := Token, clientid := <<$^, ClientId/binary>>, username := Uid}, AuthResult, _State) ->
    {ok, SuperUser} = application:get_env(?WEB_HOOK_APP, super_account),
    ?LOG_GLD("AUTH Redis ZL-IoT-2.0 Tenant Uid: ~p, Token: ~p~n, SuperUser: ~p", [Uid, Token, SuperUser]),
    case is_superuser(Uid, SuperUser)  of 
	true -> 
	    ?LOG_GLD("Check Super: ~p~n", [SuperUser]),
	    {ok, SuperPsw} = application:get_env(?WEB_HOOK_APP, super_password),
	    case check_pass(Token, SuperPsw) of
		ok -> {stop, AuthResult#{is_superuser => true, anonymous => false, auth_result => success}};
		{error, ErrMsg} -> {stop, AuthResult#{anonymous => false, auth_result  => ErrMsg}}
	    end;
	_ -> 
	    ?LOG_GLD("Check Normal: ~p~n", [Uid]),
	    {ok, Path} = application:get_env(?WEB_HOOK_APP, auth_path),
	    %% {ok, Headers} = application:get_env(?WEB_HOOK_APP, headers),
	    NHeaders = [{<<"Authorization">>, <<"bearer ", Token/binary>>}],
	    case emqx_auth_hook:send_http_request(ClientId, #{}, Path, NHeaders, get) of
		{ok, RawData} -> 
		    ?LOG_GLD("WebHook Rsp: ~p", [RawData]),
		    {stop, AuthResult#{is_superuser => fasle, anonymous    => false, auth_result  => success}};
		{error, ErrMsg} -> 
		    ?LOG_GLD("WebHook Err: ~p", [ErrMsg]),
		    {stop, AuthResult#{anonymous    => false, auth_result  => ErrMsg}}
	    end
    end;

%% check device
check(ClientInfo = #{password := Password, clientid := ClientId, username := DevPrdTs}, AuthResult, #{timeout := Timeout, type := Type, pool := Pool} = State) ->
    case binary:split(DevPrdTs,<<$&>>,[global]) of
	[DevId,PrdId,_Ts] ->
	    AuthCmd = [<<"HMGET">>, <<"device:m_did:", DevId/binary>>, <<"device_token">>, <<"model_id">>],
	    CheckPass = 
		case emqx_auth_redis_cli:q(Pool, Type, AuthCmd, Timeout) of
		    {ok, [undefined|_]} -> {error, not_found};
		    {ok, DeviceToken} when is_binary(DeviceToken) -> check_pass({Password, DeviceToken}, ClientId, DevPrdTs);
		    {ok, [DeviceToken, PrdId]} when is_binary(DeviceToken) -> check_pass({Password, DeviceToken}, ClientId, DevPrdTs);
		    {ok, [DeviceToken, ProductId|_]} when is_binary(DeviceToken) -> 
			?LOG_GLD("[Redis] Auth from redis DeviceToken: ~p, ProductId:~p", [DeviceToken, ProductId]), {error, invalid_productid};
		    {error, Reason} -> ?LOG(error, "[Redis] Command: ~p failed: ~p", [AuthCmd, Reason]), {error, not_found}
		end,
	    case CheckPass of
		ok ->
		    ok = emqx_metrics:inc(?AUTH_METRICS(success)),
		    %% SuperCmd = [<<"HGET">>, <<"mqtt_device:", DevId/binary>>, <<"is_super">>],
		    %% IsSuperuser = is_superuser(Pool, Type, SuperCmd, ClientInfo, Timeout),
		    {stop, AuthResult#{is_superuser => false, anonymous    => false, auth_result  => success}};
		{error, not_found} ->
		    ok = emqx_metrics:inc(?AUTH_METRICS(ignore)),
		    ?LOG_GLD("[Redis] Auth from redis failed: ~p", [not_found]),
		    {stop, AuthResult#{auth_result => not_found, anonymous => false}};
		{error, ResultCode} ->
		    ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
		    ?LOG(error, "[Redis] Auth from redis failed: ~p", [ResultCode]),
		    {stop, AuthResult#{auth_result => ResultCode, anonymous => false}}
	    end;
	[DevPrdTs] ->
	    oldzl_check(DevPrdTs, Password, AuthResult, State);
	_ ->
	    ?LOG(error, "[Redis] Auth err:  ~p", [invalid_username_format]),
	    {error, invalid_username_format}
    end.

oldzl_check(DeviceId, Password, AuthResult, #{timeout := Timeout, type := Type, pool := Pool}) ->
    AuthCmd = [<<"HGET">>, <<"device:m_did:", DeviceId/binary>>, <<"device_token">>],
    CheckPass = 
	case emqx_auth_redis_cli:q(Pool, Type, AuthCmd, Timeout) of
	    {ok, [undefined|_]} -> {error, not_found};
	    {ok, DeviceToken} when is_binary(DeviceToken) -> check_pass(Password, hash(plain, DeviceToken));
	    {error, Reason} -> ?LOG(error, "[Redis] Command: ~p failed: ~p", [AuthCmd, Reason]), {error, not_found}
	end,
    case CheckPass of
	ok ->
	    ok = emqx_metrics:inc(?AUTH_METRICS(success)),
	    {stop, AuthResult#{is_superuser => false, anonymous    => false, auth_result  => success}};
	{error, not_found} ->
	    ok = emqx_metrics:inc(?AUTH_METRICS(ignore)),
	    ?LOG_GLD("[Redis] Auth from redis failed: ~p", [not_found]),
	    {stop, AuthResult#{auth_result => not_found, anonymous => false}};
	{error, ResultCode} ->
	    ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
	    ?LOG(error, "[Redis] Auth from redis failed: ~p", [ResultCode]),
	    {stop, AuthResult#{auth_result => ResultCode, anonymous => false}}
    end.
    

-spec(is_superuser(atom(), atom(), undefined|list(), emqx_types:client(), timeout()) -> boolean()).
is_superuser(_Pool, _Type, undefined, _ClientInfo, _Timeout) -> false;
is_superuser(Pool, Type, SuperCmd, _ClientInfo, Timeout) ->
    case emqx_auth_redis_cli:q(Pool, Type, SuperCmd, Timeout) of
        {ok, undefined} -> false;
        {ok, <<"1">>}   -> true;
        {ok, _Other}    -> false;
        {error, _Error} -> false
    end.

is_superuser(_Super, _Super) -> true;
is_superuser(_Uid, _Super) -> false.


%% is_superuser(RawData) when is_binary (RawData) ->
%%     case emqx_json:safe_decode(RawData)  of 
%% 	{ok, Data} -> maps:get(Data, <<"is_super">>);
%%         {error, ErrMsg} -> false
%%     end.

%% check_pass({PassHash, DeviceToken}, ClientId, DevPrdTs) ->
%%     ?LOG_GLD("AUTH Redis PassHash: ~p, DeviceToken: ~p, ClientId: ~p, DevPrdTs: ~p", [PassHash, DeviceToken, ClientId, DevPrdTs]),
%%     case binary:split(ClientId,<<$&>>,[global]) of
%% 	[<<$0,_DevId/binary>>,Meta] ->
%%             %% Content = <<DeviceId/binary,ProductId/binary,TS:64/interger>>,
%%             %% Content = <<DevPrdTs/binary,$&,TS/binary>>,
%% 	    Content = DevPrdTs,
%% 	    ?LOG_GLD("AUTH Redis ZL-IoT-2.0 DeviceToken: ~p, Content: ~p", [DeviceToken, Content]),
%% 	    case check_pass({PassHash,{DeviceToken, Content}}, Meta) of
%% 		ok -> ok;
%% 		{error, _Reason} -> {error, not_authorized}
%% 	    end;
%% 	[<<$1,DevId/binary>>,_Meta] ->
%% 	    %% [<<$1,DevId/binary>>,_Meta,_TS] ->
%% 	    Params = #{username => maybe(DevId)
%% 		      ,token => DeviceToken 
%% 		      },
%% 	    ?LOG_GLD("AUTH Redis ZL-IoT-2.0 Tenant Params: ~p", [Params]),
%% 	    emqx_auth_hook:send_http_request(ClientId, Params);
%% 	[ClientId] -> 
%% 	    ?LOG_GLD("Auth Redis ZL-IoT-1.0: ClientId: ~s", [ClientId]),
%% 	    check_pass({PassHash,DeviceToken},2#00011100)
%%     end;

check_pass({ PassHash, DeviceToken}, <<0:2,_Mode:2,0:2,_Fmt:1,_Shadow:1,_DevId/binary>>, DevPrdTs)       -> check_pass(PassHash, hash(hmacsha1, {DeviceToken, DevPrdTs}));
check_pass({ PassHash, DeviceToken}, <<0:2,_Mode:2,1:2,_Fmt:1,_Shadow:1,_DevId/binary>>, _DevPrdTs)      -> check_pass(PassHash, hash(sha256, DeviceToken));
check_pass({ PassHash, DeviceToken}, <<0:2,_Mode:2,2:2,_Fmt:1,_Shadow:1,_DevId/binary>>, _DevPrdTs)      -> check_pass(PassHash, hash(sha512, DeviceToken));
check_pass({ PassHash, DeviceToken}, <<0:2,_Mode:2,3:2,_Fmt:1,_Shadow:1,_DevId/binary>>, _DevPrdTs)      -> check_pass(PassHash, hash(plain, DeviceToken));
check_pass({_PassHash,_DeviceToken}, <<0:2,_Mode:2,_Algr:2,_Fmt:1,_Shadow:1, _DevId/binary>>, _DevPrdTs) -> {error, unsupportrd_algr};
check_pass({PassHash, DeviceToken},  <<1:2,_Mode:2, Algr:2,_Fmt:1,_Shadow:1,  DevId/binary>>,  DevPrdTs) ->
    Params = #{username => maybe(DevPrdTs)
	      ,passhash => PassHash
	      ,token => DeviceToken
	      ,algr => Algr
              },
    ?LOG_GLD("AUTH Redis ZL-IoT-2.0 Tenant Params: ~p", [Params]),
    emqx_auth_hook:send_http_request(DevId, Params);
check_pass(_, _, _) -> {error, invalid_client_type}.

check_pass(PassHash, PassHash) -> ok;
check_pass(_Hash1, _Hash2)     -> {error, password_error}.

hash(hmacsha1, {Key, Content}) -> hexstring(crypto:hmac(sha, Key, Content));
hash(sha, Password)            -> hexstring(crypto:hash(sha, Password));
hash(sha256, Password)         -> hexstring(crypto:hash(sha256, Password));
hash(sha512, Password)         -> hexstring(crypto:hash(sha512, Password));
hash(md5, Password)            -> hexstring(crypto:hash(md5, Password));
hash(plain, Password)          -> Password;
hash(_, _Password)             -> unknown_sign_method.

hexstring(<<X:128/big-unsigned-integer>>) -> iolist_to_binary(io_lib:format("~32.16.0b", [X]));
hexstring(<<X:160/big-unsigned-integer>>) -> iolist_to_binary(io_lib:format("~40.16.0b", [X]));
hexstring(<<X:256/big-unsigned-integer>>) -> iolist_to_binary(io_lib:format("~64.16.0b", [X]));
hexstring(<<X:512/big-unsigned-integer>>) -> iolist_to_binary(io_lib:format("~128.16.0b", [X])).

%% 1> crypto:start().
%% 2> <<Mac:160/integer>> = crypto:hmac(sha, <<"hello">>, <<"world">>).
%% <<138,58,132,188,208,208,6,94,151,241,117,211,112,68,124,
%%   125,2,224,9,115>>
%% 3> lists:flatten(io_lib:format("~40.16.0b", [Mac])). 
%% "8a3a84bcd0d0065e97f175d370447c7d02e00973"

maybe(undefined) -> null;
maybe(Str) -> Str.

description() -> "Authentication with Redis".
