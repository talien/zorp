############################################################################
##
## Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
## 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
##
############################################################################
"""
<module maturity="stable">
  <summary>Module defining Zorp exception types.</summary>
  <description>
    <para>
    </para>
  </description>
</module>
"""

class ZorpException(Exception):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ZorpException, self).__init__()
        self.what = ''
        self.detail = detail

    def __str__(self):
        return '%s: %s' % (self.what, self.detail)

class ZoneException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ZoneException, self).__init__(detail)
        self.what = 'Zone not found'

class ServiceException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ServiceException, self).__init__(detail)
        self.what = 'Service'

class DACException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(DACException, self).__init__(detail)
        self.what = 'DAC policy violation'

class MACException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(MACException, self).__init__(detail)
        self.what = 'MAC policy violation'

class AAException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(AAException, self).__init__(detail)
        self.what = 'Authentication or authorization failed'

# for compatibility
AuthException = AAException

class LimitException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(LimitException, self).__init__(detail)
        self.what = 'Limit error'

class InternalException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(InternalException, self).__init__(detail)
        self.what = 'Internal error occured'

class UserException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(UserException, self).__init__(detail)
        self.what = 'Incorrect, or unspecified parameter'

class LicenseException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(LicenseException, self).__init__(detail)
        self.what = 'Attempt to use unlicensed components'

class MatcherException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(MatcherException, self).__init__(detail)
        self.what = 'Matcher error'

class ConfigException(ZorpException):
    def __init__(self, detail):
        """<method internal="yes">
        </method>"""
        super(ConfigException, self).__init__(detail)
        self.what = 'Configuration error'
