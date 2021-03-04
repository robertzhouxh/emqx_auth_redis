%%%-------------------------------------------------------------------
%%% @Copyright (c) 2020-2021 glodon Enterprise, Inc. (http://glodon.com)
%%% @Author: robertzhouxh <zhouxuehao@gmail.com>
%%% @Date   Created: 2021-01-07 18:18:18
%%%-------------------------------------------------------------------

-module(emqx_acl_redis).

-include("emqx_auth_redis.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("emqx/include/logger.hrl").

-export([ register_metrics/0
        , check_acl/5
        , description/0
        ]).

-spec(register_metrics() -> ok).
register_metrics() ->
    lists:foreach(fun emqx_metrics:ensure/1, ?ACL_METRICS).

check_acl(ClientInfo, PubSub, Topic, AclResult, Config) ->
    case do_check_acl(ClientInfo, PubSub, Topic, AclResult, Config) of
        ok -> emqx_metrics:inc(?ACL_METRICS(ignore)), ok;
        {stop, allow} -> emqx_metrics:inc(?ACL_METRICS(allow)), {stop, allow};
        {stop, deny} -> emqx_metrics:inc(?ACL_METRICS(deny)), {stop, deny}
    end.

%% Binary bits match: default type is integer, default size is 8, default unit is 1
do_check_acl(#{username := <<$$, _/binary>>}, _PubSub, _Topic, _AclResult, _Config) -> ok;
do_check_acl(#{username := <<"dashboard">>}, _PubSub, _Topic, _AclResult, _Config) -> ok;
do_check_acl(#{username := Uid, clientid := <<$^, _/bytes>>}, _PubSub, <<"enno", _/binary>> = Topic, _AclResult, _Config) ->
    ?LOG_GLD("ACL Tenant ZL-IoT-2.0 UID: ~s, Topic: ~s", [Uid, Topic]), {stop, allow};
do_check_acl(#{username := Uid, clientid := <<$^, _/bytes>>, password := Token}, PubSub, Topic, _AclResult, _Config) ->
    ?LOG_GLD("ACL Tenant ZL-IoT-2.0 UID: ~s, Token: ~s, Topic: ~s", [Uid, Token, Topic]),
    [_Prefix| Rest] = emqx_topic:words(Topic),
    [PrdId| Rest1] = Rest,
    [DevId| _Rest2] = Rest1,
    {ok, Path} = application:get_env(?WEB_HOOK_APP, acl_path),
    {ok, Headers} = application:get_env(?WEB_HOOK_APP, headers, []),
    Params = #{deviceId => DevId},
    NHeaders = [{<<"Authorization">>, <<"bearer ", Token/binary>>} | Headers],
    case emqx_auth_hook:send_http_request(Uid, Params, Path, Headers, post) of
	{ok, RawData} -> 
	    ?LOG_GLD("ACL WebHook Rsp OK: ~p", [RawData]),
	    acl_match(PubSub, Topic, DevId, PrdId, 1);
	{error, ErrMsg} -> 
	    ?LOG_GLD("ACL WebHook Rsp Err: ~p", [ErrMsg]),
	    {stop, deny}
    end;
%% do_check_acl(#{username := DevPrdTs, clientid := <<0:2,_Rest/bits>>}, PubSub, Topic, _AclResult, _Config) ->
do_check_acl(#{username := DevPrdTs}, PubSub, Topic, _AclResult, _Config) ->
    case binary:split(DevPrdTs,<<$&>>,[global]) of
	%% ZL-2.0
	[DevId,PrdId,_Ts] ->
	    ?LOG_GLD("ACL Redis ZL-IoT-2.0: DevPrdTs: ~s, CType: ~p", [DevId,0]),
	    acl_match(PubSub, Topic, DevId, PrdId, 0);
	%% ZL-1.0
	[DevPrdTs] -> 
	    ?LOG_GLD("ACL Redis ZL-IoT-1.0: DevPrdTs: ~p", [DevPrdTs]),
	    acl_match(PubSub, Topic, DevPrdTs, null, 0);
	 _ ->
	    ?LOG_GLD("ACL Redis ZL-IoT-1.0: Invalid DevPrdTs: ~s", [DevPrdTs]),
	    {stop, deny}
    end.

acl_match(PubSub, Topic, DevId, null, 0) ->
    D_RULES = ?O_D_RULES(DevId),
    case match(PubSub, Topic, D_RULES) of
	allow   -> {stop, allow};
	nomatch -> {stop, deny}
    end;
acl_match(PubSub, Topic, DevId, PrdId, 0) ->
    D_RULES = ?D_RULES(PrdId, DevId),
    case match(PubSub, Topic, D_RULES) of
	allow   -> {stop, allow};
	nomatch -> {stop, deny}
    end;
acl_match(PubSub, Topic, DevId, PrdId, 1) ->
    U_RULES = ?U_RULES(PrdId,DevId),
    case match(PubSub, Topic, U_RULES) of
	allow   -> {stop, allow};
	nomatch -> {stop, deny}
    end.

match(_, _, []) -> nomatch;
match(PubSub, Topic, [{Filter, Access}| Rules]) ->
    %% case {match_topic(Topic, Filter), match_access(PubSub, b2i(Access))} of
    case {match_topic(Topic, Filter), match_access(PubSub, Access)} of
        {true, true} -> allow;
        {_, _} -> match(PubSub, Topic, Rules)
    end.

match_topic(Topic, Filter) -> emqx_topic:match(Topic, Filter).

match_access(subscribe, Access) -> (1 band Access) > 0;
match_access(publish, Access) -> (2 band Access) > 0.

%% b2i(Bin) -> list_to_integer(binary_to_list(Bin)).

description() -> "Redis ACL Module".
