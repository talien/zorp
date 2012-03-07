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
 ***************************************************************************/
#ifndef ZORP_CREDENTIALS_H_INCLUDED
#define ZORP_CREDENTIALS_H_INCLUDED

#include <zorp/proxy.h>

/**
 * Stores a credential item, which is an array of strings.
 *
 * I.e. in the case of passwords the credential item contains a single string.
 * On the other hand a key credential may contain a key type, public and private key.
 */
typedef struct _ZCredentialItem
{
  gint count;                 /**< Number of strings in the item */
  gchar **credentials;        /**< Array of credential strings */
} ZCredentialItem;

/**
 * List of credential items
 */
typedef struct _ZCredentialList
{
  gint count;                 /**< Number of credential items */
  ZCredentialItem *items;     /**< Array of credential items */
} ZCredentialList;

ZCredentialList *z_proxy_get_credential_list(ZProxy *self, const gchar *username, const gchar *domain, const gchar *target_host, gushort port, const gchar *method);

gchar *z_proxy_get_credential_password(ZProxy *self, const gchar *username, const gchar *domain, const gchar *target_host, gushort port);

void z_credential_list_free(ZCredentialList *self);

#endif
