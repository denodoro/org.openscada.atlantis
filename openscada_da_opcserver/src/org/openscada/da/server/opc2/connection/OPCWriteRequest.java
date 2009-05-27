/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006-2009 inavare GmbH (http://inavare.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package org.openscada.da.server.opc2.connection;

import org.jinterop.dcom.core.JIVariant;

public class OPCWriteRequest
{
    private final JIVariant value;

    private final String itemId;

    public OPCWriteRequest ( final String itemId, final JIVariant value )
    {
        this.value = value;
        this.itemId = itemId;
    }

    public JIVariant getValue ()
    {
        return this.value;
    }

    public String getItemId ()
    {
        return this.itemId;
    }
}
