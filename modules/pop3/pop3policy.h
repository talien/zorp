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
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#ifndef ZORP_MODULES_POP3POLICY_H_INCLUDED
#define ZORP_MODULES_POP3POLICY_H_INCLUDED

#include "pop3.h"

guint pop3_policy_command_hash_search(Pop3Proxy *self,gchar *command);

gboolean ftp_hash_get_type(ZPolicyObj *tuple, guint *filter_type);

guint pop3_policy_command_hash_do(Pop3Proxy *self);

guint pop3_policy_response_hash_do(Pop3Proxy *self);

gboolean pop3_policy_stack_hash_do(Pop3Proxy *self, ZStackedProxy **stacked);

#endif

