#include <zorp/luapolicy.h>
#include <zorp/dispatch.h>
#include <zorp/stream.h>
#include <zorp/streamline.h>
#include <zorp/streamfd.h>
#include <zorp/proxygroup.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <zorp/luaobject.h>
#include <zorp/proxy.h>

lua_State* master_state;

int gettid()
{
   pid_t tid;
   tid = syscall(SYS_gettid);
   return tid;
}

static int z_lua_stream_new_instance(lua_State* state)
{
   ZStream* stream;
   int fd = lua_tointeger(state, 1);
   const char* name = lua_tolstring(state, 2, NULL);
   stream = z_stream_fd_new(fd, name);
   z_lua_create_policy_object(state, (void*)stream, "Zorp.Stream","Zorp.Stream.index");
   return 1;
}

static int z_lua_stream_new(lua_State* state, ZStream* stream)
{
   z_stream_ref(stream);   
   z_lua_create_policy_object(state, (void*)stream, "Zorp.Stream","Zorp.Stream.index");
   return 1;
};


static int z_lua_stream_read(lua_State* state)
{
   int bytes_read, res;
   ZStream* stream = (ZStream*)Z_LUA_GET_OBJECT(state, 1);
   int length = lua_tointeger(state, 2);
   gchar* buf = g_new0(char, length);
   res = z_stream_read(stream, buf, length, &bytes_read, NULL);
   lua_pushlstring(state, buf, length);
   g_free(buf);
   return 1;
}

static int z_lua_stream_get_fd(lua_State* state)
{
   ZStream* stream = (ZStream*)Z_LUA_GET_OBJECT(state, 1);
   int fd = z_stream_get_fd(stream);
   lua_pushinteger(state, fd);
   return 1;
}

static const struct luaL_reg z_lua_stream_methods [] = {
      {"read", z_lua_stream_read},
      {"get_fd", z_lua_stream_get_fd},
      {NULL, NULL}
  };

static int z_lua_stream_destroy(lua_State* state)
{
   ZStream* stream =(ZStream*)Z_LUA_GET_OBJECT(state, 1);
   z_stream_unref(stream);
   z_log("nosession", CORE_INFO, 3, "Unrefing stream from policy");
   return 0;
}

void z_lua_stream_register(lua_State* state)
{
  z_lua_class_register(state, "Zorp.Stream", "Zorp.Stream.index", z_lua_stream_methods, z_lua_stream_destroy);
}

static int z_lua_proxy_group_start(lua_State* state)
{
   //int table_value
   ZProxyGroup* proxy_group = (ZProxyGroup*)Z_LUA_GET_OBJECT(state, 1);
   ZStream* stream =(ZStream*)Z_LUA_GET_OBJECT(state, 2);
   ZProxyParams params;
   gchar* module_name = "plug";
   gchar* proxy_name = "plug";
   params.session_id = "svc:lofasz:1/rdp";
   params.client = stream;
   params.handler = NULL;
   params.parent = NULL;
   ZProxy* proxy = z_proxy_create_proxy(module_name, proxy_name, &params);
   z_proxy_group_start_session(proxy_group, proxy);
   return 0;   
}

int z_lua_proxy_group_new(lua_State* state)
{
   ZProxyGroup* proxy_group;
   int max_sessions = lua_tointeger(state, 1);
   proxy_group = z_proxy_group_new(max_sessions);
   z_lua_create_policy_object(state, (void*) proxy_group, "Zorp.ProxyGroup", "Zorp.ProxyGroup.index");
   return 1;
}

int z_lua_proxy_group_destroy(lua_State* state G_GNUC_UNUSED)
{
  return 0;
}

static const struct luaL_reg z_lua_proxy_group_methods [] = {

   {"start", z_lua_proxy_group_start},
   { NULL, NULL } 
};

void z_lua_proxy_group_register(lua_State* state)
{
   z_lua_class_register(state, "Zorp.ProxyGroup", "Zorp.ProxyGroup.index", z_lua_proxy_group_methods, z_lua_proxy_group_destroy); 
}

static gboolean z_lua_dispatch_accept(ZConnection *conn G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
   z_log(NULL, CORE_INFO, 2, "Connection accepted, tid='%d'", gettid());
   if (conn)
   {
      lua_getglobal(master_state, "accept");
      z_lua_stream_new(master_state, conn->stream);
      lua_call(master_state, 1, 0);
   }
   return TRUE;   
}

static void z_lua_dispatch_destroy_notify(gpointer data G_GNUC_UNUSED)
{
   z_log(NULL, CORE_INFO, 2, "Dispatcher destroyed, tid='%d'", gettid());
};

static int z_lua_dispatch(lua_State* state)
{
    gchar *session_id = "dispatch";
    ZDispatchBind* db;
    ZSockAddr* bound_addr;
    gint prio = 0;
    ZDispatchParams params;
    ZDispatchEntry* dispatch = NULL;
    params.common.threaded = TRUE;
    params.common.mark_tproxy = FALSE; 
    params.common.transparent = FALSE;
    params.tcp.backlog = 255;
    params.tcp.accept_one = FALSE;
    db = (ZDispatchBind*) lua_topointer(state, 1);
    z_log(NULL, CORE_INFO, 2, "Dispatcher created, tid='%d'", gettid());  
    dispatch = z_dispatch_register(session_id, db, &bound_addr, prio, &params, z_lua_dispatch_accept, NULL, z_lua_dispatch_destroy_notify);
    return 0;
}

static int z_lua_dispatch_bind_new_sa(lua_State* state)
{
   char* ip;
   int port;
   ZSockAddr* sa;
   ZDispatchBind* bind;
   ip = strdup(lua_tolstring(state, 1, NULL));
   port = lua_tointeger(state, 2);
   sa = z_sockaddr_inet_new(ip, port);
   bind = z_dispatch_bind_new_sa(ZD_PROTO_TCP, sa);
   lua_pushlightuserdata(state, (void *)bind);
   return 1;
}

static int z_lua_log(lua_State* state)
{
   const char* session_id = lua_tolstring(state, 1, NULL);
   const char* logtag = lua_tolstring(state, 2, NULL);
   int level = lua_tointeger(state, 3);
   const char* msg = lua_tolstring(state, 4, NULL);
   z_log(session_id, logtag, level, "%s",msg);
   return 0;
}

void register_lua_libs(lua_State* state)
{
   lua_register(state, "DBSockAddr", z_lua_dispatch_bind_new_sa);
   lua_register(state, "log", z_lua_log);
   lua_register(state, "Dispatcher", z_lua_dispatch);
   lua_register(state, "ProxyGroup", z_lua_proxy_group_new);
   z_lua_stream_register(state);
   z_lua_proxy_group_register(state);
}

ZPolicy* z_lua_policy_new(const char* policy_name)
{
   ZPolicy *self = (ZPolicy*) g_new0(ZLuaPolicy, 1);
 
   self->ref_cnt = 1; 
   self->policy_filename = g_strdup(policy_name);
  
  /* the main thread and the notification thread always references us,
   * and we should be deleted when that reference is dropped */
  
   return self;
}

gboolean z_lua_policy_boot(ZPolicy* self G_GNUC_UNUSED)
{
   return TRUE;
}

gboolean z_lua_policy_load(ZPolicy* self)
{
   ZLuaPolicy* policy = (ZLuaPolicy*) self;
   lua_State* state = lua_open();
   master_state = state;
   luaL_openlibs(state);
   register_lua_libs(state);
   if (luaL_loadfile(state, self->policy_filename) ||  
       lua_pcall(state, 0,0,0) )
   {
      fprintf(stderr,"%s\n", lua_tostring(state,-1));
   }
   policy->policy_state = state;
   return TRUE;
}


/* Calling the instance_name function directly for now
I should wrap it like in Zorp.Zorp.init */

gboolean z_lua_policy_init(ZPolicy* self, gchar const **instance_name, gchar const *virtual_instance_name G_GNUC_UNUSED, gboolean is_master G_GNUC_UNUSED) 
{
   ZLuaPolicy* policy = (ZLuaPolicy*) self;
   lua_State* state = policy->policy_state;
   lua_getglobal(state, instance_name[0]);
   lua_pushstring(state, instance_name[0]);
   lua_call(state, 1, 0);
   return TRUE;
}

gboolean z_lua_policy_deinit(ZPolicy* self, gchar const **instance_name G_GNUC_UNUSED, gchar const *virtual_instance_name G_GNUC_UNUSED)
{
   ZLuaPolicy* policy = (ZLuaPolicy*) self;
   lua_close(policy->policy_state);
   return TRUE;
}

gboolean z_lua_policy_cleanup(ZPolicy* self, gchar const **instance_name, gchar const *virtual_instance_name G_GNUC_UNUSED, gboolean is_master G_GNUC_UNUSED) 
{
   return z_lua_policy_deinit(self, instance_name, virtual_instance_name);
}


ZPolicyFuncs z_lua_policy_funcs = {
  .init = z_lua_policy_init,
  .new = z_lua_policy_new,
  .deinit = z_lua_policy_deinit,
  .load = z_lua_policy_load,
  .boot = z_lua_policy_boot,
  .cleanup = z_lua_policy_cleanup
};
