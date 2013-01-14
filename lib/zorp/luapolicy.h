#include <zorp/policy.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

typedef struct _ZLuaPolicy
{
   ZPolicy super;
   lua_State* policy_state;
} ZLuaPolicy;

ZPolicy* z_lua_policy_new(const char* policy_name);
gboolean z_lua_policy_boot(ZPolicy* self);
gboolean z_lua_policy_load(ZPolicy* self);
gboolean z_lua_policy_init(ZPolicy* self, gchar const **instance_name, gchar const *virtual_instance_name, gboolean is_master);
gboolean z_lua_policy_deinit(ZPolicy* self, gchar const **instance_name, gchar const *virtual_instance_name);
gboolean z_lua_policy_cleanup(ZPolicy* self, gchar const **instance_name, gchar const *virtual_instance_name, gboolean is_master);

extern ZPolicyFuncs z_lua_policy_funcs;
