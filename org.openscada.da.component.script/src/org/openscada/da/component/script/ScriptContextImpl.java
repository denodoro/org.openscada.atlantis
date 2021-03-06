/*
 * This file is part of the openSCADA project
 * Copyright (C) 2011-2012 TH4 SYSTEMS GmbH (http://th4-systems.com)
 *
 * openSCADA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * only, as published by the Free Software Foundation.
 *
 * openSCADA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License version 3 for more details
 * (a copy is included in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with openSCADA. If not, see
 * <http://opensource.org/licenses/lgpl-3.0.html> for a copy of the LGPLv3 License.
 */

package org.openscada.da.component.script;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.openscada.core.Variant;
import org.openscada.core.connection.provider.ConnectionIdTracker;
import org.openscada.da.connection.provider.ConnectionService;
import org.openscada.da.core.OperationParameters;
import org.openscada.da.server.common.chain.DataItemInputChained;
import org.openscada.da.server.common.chain.WriteHandler;
import org.openscada.da.server.common.chain.WriteHandlerItem;
import org.openscada.utils.osgi.pool.ObjectPoolImpl;
import org.osgi.framework.BundleContext;

public class ScriptContextImpl implements ScriptContext
{

    private final BundleContext context;

    private final Map<String, String> parameters;

    private final Executor executor;

    private final Map<String, Item> items = new HashMap<String, ScriptContext.Item> ();

    private final Lock itemsLock = new ReentrantLock ();

    private final ObjectPoolImpl objectPool;

    public ScriptContextImpl ( final Executor executor, final ObjectPoolImpl objectPool, final String id, final BundleContext context, final Map<String, String> parameters )
    {
        this.executor = executor;
        this.context = context;
        this.objectPool = objectPool;
        this.parameters = Collections.unmodifiableMap ( parameters );
    }

    @Override
    public Item registerItem ( final String itemId, final Map<String, Variant> attributes, final WriteHandler writeHandler )
    {
        if ( writeHandler != null )
        {
            return registerItem ( new ItemWrapper ( this.objectPool, new WriteHandlerItem ( itemId, writeHandler, this.executor ), attributes ) );
        }
        else
        {
            return registerItem ( new ItemWrapper ( this.objectPool, new DataItemInputChained ( itemId, this.executor ), attributes ) );
        }
    }

    private Item registerItem ( final Item item )
    {
        this.itemsLock.lock ();
        try
        {
            final Item oldItem = this.items.remove ( item.getItemId () );
            if ( oldItem != null )
            {
                oldItem.dispose ();
            }

            this.items.put ( item.getItemId (), item );

            return item;
        }
        finally
        {
            this.itemsLock.unlock ();
        }
    }

    @Override
    public void unregisterItem ( final String itemId )
    {
        final Item item;

        this.itemsLock.lock ();
        try
        {
            item = this.items.remove ( itemId );
        }
        finally
        {
            this.itemsLock.unlock ();
        }

        if ( item != null )
        {
            item.dispose ();
        }
    }

    @Override
    public void unregisterItem ( final Item item )
    {
        unregisterItem ( item.getItemId () );
    }

    @Override
    public void writeDataItem ( final String connectionId, final String itemId, final Variant value, final OperationParameters operationParameters ) throws Exception
    {
        final ConnectionIdTracker tracker = new ConnectionIdTracker ( this.context, connectionId, null, ConnectionService.class );
        tracker.open ();
        try
        {
            final ConnectionService service = (ConnectionService)tracker.waitForService ( 0 );
            if ( service != null )
            {
                service.getConnection ().write ( itemId, value, operationParameters, null );
            }
        }
        finally
        {
            tracker.close ();
        }
    }

    @Override
    public void dispose ()
    {
        this.itemsLock.lock ();
        try
        {
            for ( final Item item : this.items.values () )
            {
                item.dispose ();
            }
            this.items.clear ();
        }
        finally
        {
            this.itemsLock.unlock ();
        }
    }

    @Override
    public Map<String, String> getParameters ()
    {
        return this.parameters;
    }

}
