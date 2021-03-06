/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006-2012 TH4 SYSTEMS GmbH (http://th4-systems.com)
 *
 * OpenSCADA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * only, as published by the Free Software Foundation.
 *
 * OpenSCADA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License version 3 for more details
 * (a copy is included in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with OpenSCADA. If not, see
 * <http://opensource.org/licenses/lgpl-3.0.html> for a copy of the LGPLv3 License.
 */

package org.openscada.da.server.common;

import java.util.EnumSet;

import org.openscada.core.InvalidOperationException;
import org.openscada.core.Variant;
import org.openscada.da.core.IODirection;
import org.openscada.utils.concurrent.NotifyFuture;

public abstract class DataItemOutput extends DataItemBase
{

    public DataItemOutput ( final String id )
    {
        super ( new DataItemInformationBase ( id, EnumSet.of ( IODirection.OUTPUT ) ) );
    }

    @Override
    public NotifyFuture<Variant> readValue () throws InvalidOperationException
    {
        throw new InvalidOperationException ();
    }

}
