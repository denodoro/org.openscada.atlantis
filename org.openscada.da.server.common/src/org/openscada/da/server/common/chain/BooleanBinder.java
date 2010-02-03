/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006-2010 inavare GmbH (http://inavare.com)
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

package org.openscada.da.server.common.chain;

import org.openscada.core.Variant;

public class BooleanBinder implements AttributeBinder
{
    private Boolean value = null;

    public void bind ( final Variant value ) throws Exception
    {
        if ( value == null )
        {
            this.value = null;
        }
        else
        {
            this.value = value.asBoolean ();
        }
    }

    public Boolean getValue ()
    {
        return this.value;
    }

    public boolean getSafeValue ( final boolean defaultValue )
    {
        final Boolean result = this.value;
        if ( result == null )
        {
            return defaultValue;
        }
        else
        {
            return result;
        }
    }

    public Variant getAttributeValue ()
    {
        return new Variant ( getValue () );
    }

}