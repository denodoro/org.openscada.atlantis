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

package org.openscada.da.datasource.script;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.openscada.core.Variant;
import org.openscada.core.VariantEditor;
import org.openscada.da.datasource.DataSource;
import org.openscada.utils.osgi.pool.ObjectPoolTracker;
import org.openscada.utils.osgi.pool.SingleObjectPoolServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WriterController
{

    private final static Logger logger = LoggerFactory.getLogger ( WriterController.class );

    private final ObjectPoolTracker tracker;

    private volatile Map<String, SingleObjectPoolServiceTracker> trackers = Collections.emptyMap ();

    public WriterController ( final ObjectPoolTracker tracker )
    {
        this.tracker = tracker;
    }

    public void setWriteItems ( final Map<String, String> datasources )
    {
        // create new tracker map
        final Map<String, SingleObjectPoolServiceTracker> newTrackers = new HashMap<String, SingleObjectPoolServiceTracker> ( 1 );
        for ( final Map.Entry<String, String> entry : datasources.entrySet () )
        {
            final String name = entry.getKey ();
            final String dataSourceId = entry.getValue ();

            final SingleObjectPoolServiceTracker objectTracker = new SingleObjectPoolServiceTracker ( this.tracker, dataSourceId, null );
            objectTracker.open ();
            newTrackers.put ( name, objectTracker );

            logger.debug ( "Added {} as {}", dataSourceId, name );
        }

        // swap
        final Map<String, SingleObjectPoolServiceTracker> oldTrackers = this.trackers;
        this.trackers = newTrackers;

        // close old stuff
        for ( final SingleObjectPoolServiceTracker tracker : oldTrackers.values () )
        {
            tracker.close ();
        }
    }

    public void write ( final String dataSourceName, final Object value ) throws Exception
    {
        logger.debug ( "Write request - name: {}, value: {}", dataSourceName, value );

        final SingleObjectPoolServiceTracker objectTracker = this.trackers.get ( dataSourceName );
        if ( objectTracker == null )
        {
            throw new IllegalArgumentException ( String.format ( "Data source '%s' is not configured", dataSourceName ) );
        }

        final Object o = objectTracker.getCurrentService ();
        if ( o == null )
        {
            throw new IllegalStateException ( String.format ( "Data source '%s' was not found", dataSourceName ) );
        }
        if ( ! ( o instanceof DataSource ) )
        {
            throw new IllegalStateException ( String.format ( "Data source '%s' is not a data source", dataSourceName ) );
        }

        ( (DataSource)o ).startWriteValue ( Variant.valueOf ( value ), null );
    }

    public void writeAsText ( final String itemId, final String value ) throws Exception
    {
        write ( itemId, VariantEditor.toVariant ( value ) );
    }
}
