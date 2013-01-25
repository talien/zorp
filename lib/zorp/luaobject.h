#ifndef _Z_LUAPOLICY_H
#define _Z_LUAPOLICY_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

typedef struct _ZLuaObject {
   int reg_key;
   void* value;
} ZLuaObject;

#define Z_LUA_GET_OBJECT(state, pos) (((ZLuaObject*)lua_touserdata(state, pos))->value)

int z_lua_create_policy_object(lua_State* state, void* object, char* class_name, char* class_index_name);
int z_lua_get_object_attr(lua_State* state);
int z_lua_set_object_attr(lua_State* state);
void z_lua_reg_object_lib(lua_State* state);
void z_lua_class_register(lua_State* state, char* class_name, char* class_index_name, struct luaL_reg* methods, lua_CFunction destroy_method);

#endif
