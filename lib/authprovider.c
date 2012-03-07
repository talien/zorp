/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/authprovider.h>
#include <zorp/log.h>


/**
 * z_auth_provider_check_passwd:
 *
 * NOTE: this function requires the Python lock to be held.
 **/
gboolean
z_auth_provider_check_passwd(
                             ZAuthProvider *self,
                             gchar *session_id,
                             gchar *username,
                             gchar *passwd,
                             gchar ***groups G_GNUC_UNUSED,
                             ZProxy *proxy
                            )
{
  gboolean called;
  ZPolicyObj *res;
  gboolean ret = FALSE;
  ZPolicyObj *session;

  z_session_enter(session_id);

  session = z_policy_getattr(proxy->handler, "session");
  res = z_policy_call(self, "performAuthentication",
                      z_policy_var_build("(sOss)", session_id, session, username, passwd),
                      &called, session_id);
  z_policy_var_unref(session);

  if (res != NULL)
    {
      gboolean retval;

      if (z_policy_var_parse_boolean(res, &retval))
        {
          z_log(session_id, CORE_INFO, 6, "Authentication backend called; username='%s', result='%d'",
                username, retval);
          ret = retval;
        }
      else
        {
          z_log(session_id, CORE_POLICY, 1, "Authentication backend returned a non-int type;");
        }

      z_policy_var_unref(res);
    }

  z_session_leave(session_id);

  return ret;
}
