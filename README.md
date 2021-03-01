emqx_auth_redis
===============

EMQ X Redis Authentication/ACL Plugin

Features
---------

- Full *Authentication*, *Superuser*, *ACL* support
- IPv4, IPv6 support
- Connection pool by [ecpool](https://github.com/emqx/ecpool)
- Support `single`, `sentinel`, `cluster` deployment structures of Redis
- Completely cover Redis 5, Redis 6 in our tests


Init Redis
---

```
docker exec -it redis sh

redis-cli

HMSET mqtt_device:i_am_device_id device_token "i_am_device_token"

```

AUTH/ACL
---

No need to config acl for device/user, plugin use macro to spawn the ACL Rules to avoid accessing the database

```
-define(U_RULES(ProductId,DeviceId), 
	[{<<ProductId/binary,$/,DeviceId/binary,"/cmd">>, 2}
	,{<<ProductId/binary,$/,DeviceId/binary,"/cmd_reply">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/propset">>, 2}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/propset_reply">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/ota_upgrade">>, 2}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/ota_progress">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/props">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/events">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/shadow_get">>, 3}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/shadow_update">>, 3}
    ,{<<"user/",DeviceId/binary,"/info">>, 1}
	]).

-define(D_RULES(ProductId,DeviceId), 
	[{<<ProductId/binary,$/,DeviceId/binary,"/props">>, 2}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/events">>, 2}
	,{<<ProductId/binary,$/,DeviceId/binary,"/cmd">>, 1}
	,{<<ProductId/binary,$/,DeviceId/binary,"/cmd_reply">>, 2}
	,{<<ProductId/binary,$/,DeviceId/binary,"/propset">>, 1}
	,{<<ProductId/binary,$/,DeviceId/binary,"/propset_reply">>, 2}
	,{<<ProductId/binary,$/,DeviceId/binary,"/info">>, 2}
	,{<<ProductId/binary,$/,DeviceId/binary,"/info_reply">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/ota_upgrade">>, 1}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/ota_progress">>, 2}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/shadow_get">>, 3}
    ,{<<ProductId/binary,$/,DeviceId/binary,"/shadow_update">>, 3}
	]).

-define(O_U_RULES(DeviceId), 
	[{<<"enno/out/json/logs/", DeviceId/binary>>, 1}
	,{<<"enno/out/json/", DeviceId/binary>>, 2}
	]).

-define(O_D_RULES(DeviceId), 
	[{<<"enno/in/json">>, 2}
	,{<<"enno/out/json/", DeviceId/binary>>, 1}
	]).

```
