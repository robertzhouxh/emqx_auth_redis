
-define(APP, emqx_auth_redis).
-define(WEB_HOOK_APP, emqx_web_hook).

-record(auth_metrics, {
        success = 'client.auth.success',
        failure = 'client.auth.failure',
        ignore = 'client.auth.ignore'
    }).

-record(acl_metrics, {
        allow = 'client.acl.allow',
        deny = 'client.acl.deny',
        ignore = 'client.acl.ignore'
    }).

-define(METRICS(Type), tl(tuple_to_list(#Type{}))).
-define(METRICS(Type, K), #Type{}#Type.K).

-define(AUTH_METRICS, ?METRICS(auth_metrics)).
-define(AUTH_METRICS(K), ?METRICS(auth_metrics, K)).

-define(ACL_METRICS, ?METRICS(acl_metrics)).
-define(ACL_METRICS(K), ?METRICS(acl_metrics, K)).

-define(U_RULES(ProductId,DeviceId), 
	[{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/cmd">>, 2}
	,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/cmd_reply">>, 1}
        ,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/propset">>, 2}
        ,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/propset_reply">>, 1}
        ,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/props">>, 1}
        ,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/events">>, 1}
        ,{<<"/ota/",ProductId/binary,$/,DeviceId/binary,"/upgrade">>, 2}
        ,{<<"/ota/",ProductId/binary,$/,DeviceId/binary,"/progress">>, 1}
        ,{<<"/shadow/",ProductId/binary,$/,DeviceId/binary,"/get">>, 3}
        ,{<<"/shadow/",ProductId/binary,$/,DeviceId/binary,"/update">>, 3}
        ,{<<"/sys/user/",DeviceId/binary,"/info">>, 1}
	,{<<"enno/out/json/logs/", DeviceId/binary>>, 1}
	]).

-define(D_RULES(ProductId,DeviceId), 
	[{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/props">>, 2}
        ,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/events">>, 2}
	,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/cmd">>, 1}
	,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/cmd_reply">>, 2}
	,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/propset">>, 1}
	,{<<"/sys/",ProductId/binary,$/,DeviceId/binary,"/propset_reply">>, 2}
	,{<<"/meta/",ProductId/binary,$/,DeviceId/binary,"/info">>, 2}
	,{<<"/meta/",ProductId/binary,$/,DeviceId/binary,"/info_reply">>, 1}
        ,{<<"/ota/",ProductId/binary,$/,DeviceId/binary,"/upgrade">>, 1}
        ,{<<"/ota/",ProductId/binary,$/,DeviceId/binary,"/progress">>, 2}
        ,{<<"/shadow/",ProductId/binary,$/,DeviceId/binary,"/get">>, 3}
        ,{<<"/shadow/",ProductId/binary,$/,DeviceId/binary,"/update">>, 3}
	]).

-define(O_D_RULES(DeviceId), 
	[{<<"enno/in/json">>, 2}
	,{<<"enno/out/json/", DeviceId/binary>>, 1}
	]).

-define(DEBUG, []).
-ifdef(DEBUG).
-define(LOG_GLD(Arg), io:format([?MODULE, ?FUNCTION_NAME, ?LINE, ??Arg, Arg]).
-define(LOG_GLD(Fmt, Args), io:format("[~p:~p#~p]" ++ Fmt ++ "~n~n", [?MODULE, ?FUNCTION_NAME, ?LINE] ++ Args)).
-define(ASSIGN(Var, Exp), Var = Exp, io:format("~s:~s -> ~p~n~n", [??Var, ??Exp, Var])).
-else.
-define(LOG_GLD(Fmt, Arg), ok).
-define(LOG_GLD(Arg), ok).
-define(ASSIGN(Var, Exp), Var = Exp).
-endif.
