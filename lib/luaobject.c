#include <zorp/luaobject.h>

int z_lua_create_policy_object(lua_State* state, void* object, char* class_name, char* class_index_name)
{
    ZLuaObject* lua_object = (ZLuaObject*)lua_newuserdata(state, sizeof(ZLuaObject));
    luaL_getmetatable(state, class_name);
    lua_setmetatable(state, -2);
    lua_newtable(state);
    luaL_getmetatable(state, class_index_name);
    lua_setmetatable(state, -2);
    lua_object->value = object;
    lua_object->reg_key = luaL_ref(state, LUA_REGISTRYINDEX);
    return 1;
}
 
int z_lua_get_object_index_table(lua_State* state)
{
    ZLuaObject* udata = (ZLuaObject*)lua_touserdata(state,1);
    lua_rawgeti(state, LUA_REGISTRYINDEX, udata->reg_key);
    return 1;
}

int z_lua_get_object_attr(lua_State* state)
{
    ZLuaObject* udata = (ZLuaObject*)lua_touserdata(state,1);
    lua_rawgeti(state, LUA_REGISTRYINDEX, udata->reg_key);
    lua_insert(state,2);
    lua_gettable(state, 2);
    printf("__get called\n");
    return 1;
}

int z_lua_set_object_attr(lua_State* state)
{
    ZLuaObject* udata = (ZLuaObject*)lua_touserdata(state,1);
    lua_rawgeti(state, LUA_REGISTRYINDEX, udata->reg_key);
    lua_insert(state,2);
    lua_settable(state, 2);
    printf("__set called\n");
    return 0;
}

static const struct luaL_reg z_object_lib [] = {
 { "__set", z_lua_get_object_attr},
 { "__get", z_lua_set_object_attr},
 { "__get_index", z_lua_get_object_index_table},
 { NULL, NULL}
};

void lua_reg_object_lib(lua_State* state)
{
   luaL_openlib(state, "Zorp.Object", z_object_lib, 0);
}

void z_lua_class_register(lua_State* state, char* class_name, char* class_index_name, struct luaL_reg* methods, lua_CFunction destroy_method)
{
   luaL_newmetatable(state, class_name);
   lua_pushstring(state, "__index");
   lua_pushcfunction(state, z_lua_get_object_attr);
   lua_settable(state, -3);
   lua_pushstring(state, "__newindex");
   lua_pushcfunction(state, z_lua_set_object_attr);
   lua_settable(state, -3);
   lua_pushstring(state, "__gc");
   lua_pushcfunction(state, destroy_method);
   lua_settable(state, -3);
   luaL_newmetatable(state, class_index_name);
   lua_pushstring(state, "__index");
   lua_pushvalue(state, -2);  /* pushes the metatable */
   lua_settable(state, -3);  /* metatable.__index = metatable */
   luaL_openlib(state, NULL, methods, 0);
}

