/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006-2011 TH4 SYSTEMS GmbH (http://th4-systems.com)
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

package org.openscada.ae.server.http.monitor;

import java.util.Map;

import org.openscada.ae.Event;
import org.openscada.ae.Event.EventBuilder;
import org.openscada.ae.monitor.common.MonitorDecoratorAdapter;
import org.openscada.core.Variant;
import org.openscada.utils.lang.Immutable;

@Immutable
public class EventMonitorDecorator extends MonitorDecoratorAdapter
{
    private final int sequence;

    private final Variant message;

    public EventMonitorDecorator ( final int sequence, final Variant message )
    {
        this.sequence = sequence;
        this.message = message;
    }

    @Override
    public EventBuilder decorate ( final EventBuilder eventBuilder )
    {
        eventBuilder.attribute ( "sequence", Variant.valueOf ( this.sequence ) );
        if ( this.message != null )
        {
            eventBuilder.attribute ( Event.Fields.MESSAGE, this.message );
        }
        return eventBuilder;
    }

    @Override
    public void decorateMonitorStatus ( final Map<String, Variant> attributes )
    {
        if ( this.message != null )
        {
            attributes.put ( Event.Fields.MESSAGE.getName (), this.message );
        }
    }
}
