/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006-2010 TH4 SYSTEMS GmbH (http://th4-systems.com)
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

package org.openscada.ae.server.info.internal;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import org.openscada.ae.MonitorStatus;
import org.openscada.ae.MonitorStatusInformation;
import org.openscada.ae.monitor.MonitorListener;
import org.openscada.ae.monitor.MonitorService;
import org.openscada.core.Variant;
import org.openscada.da.client.DataItemValue;
import org.openscada.da.client.DataItemValue.Builder;
import org.openscada.da.datasource.base.DataInputOutputSource;
import org.openscada.da.datasource.base.DataInputSource;
import org.openscada.da.datasource.base.WriteHandler;
import org.openscada.sec.UserInformation;
import org.openscada.utils.osgi.pool.ObjectPool;
import org.openscada.utils.osgi.pool.ObjectPoolImpl;
import org.openscada.utils.osgi.pool.ObjectPoolListener;
import org.openscada.utils.osgi.pool.ObjectPoolTracker;
import org.openscada.utils.osgi.pool.ObjectPoolTracker.ObjectPoolServiceListener;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InfoService
{
    private final static String ALERT_ACTIVE_ITEM = "ALERT_ACTIVE";

    private final static String ALERT_DISABLED_ITEM = "ALERT_DISABLED";

    private final static Logger logger = LoggerFactory.getLogger ( InfoService.class );

    private final Executor executor;

    private final ObjectPoolImpl dataSourcePool;

    private final Map<String, DataInputSource> items = new HashMap<String, DataInputSource> ();

    private final DataInputOutputSource alertActiveItem;

    private final DataInputOutputSource alertDisabledItem;

    private String prefix;

    private final Map<String, MonitorStatusInformation> cachedMonitors = new HashMap<String, MonitorStatusInformation> ();

    private final Map<MonitorStatus, AtomicInteger> aggregatedMonitors = new HashMap<MonitorStatus, AtomicInteger> ();

    private volatile boolean alertDisabled = false;

    ///////////////////////////////////////////////////////////////////////
    // constructor
    ///////////////////////////////////////////////////////////////////////

    /**
     * @param context
     * @param executor
     * @param monitorPoolTracker
     * @param dataSourcePool
     */
    public InfoService ( final BundleContext context, final Executor executor, final ObjectPoolTracker monitorPoolTracker, final ObjectPoolImpl dataSourcePool )
    {
        // set final fields
        this.executor = executor;
        this.dataSourcePool = dataSourcePool;
        clearAggregatedMonitors ();

        // create items
        for ( final MonitorStatus monitorStatus : MonitorStatus.values () )
        {
            this.items.put ( monitorStatus.name (), new DataInputSource ( executor ) );
        }
        this.alertActiveItem = new DataInputOutputSource ( executor );
        this.alertActiveItem.setWriteHandler ( new WriteHandler () {
            @Override
            public void handleWrite ( final UserInformation userInformation, final Variant value ) throws Exception
            {
                setValue ( InfoService.this.alertActiveItem, value.asBoolean ( false ) );
            }
        } );
        this.alertDisabledItem = new DataInputOutputSource ( executor );
        this.alertDisabledItem.setWriteHandler ( new WriteHandler () {
            @Override
            public void handleWrite ( final UserInformation userInformation, final Variant value ) throws Exception
            {
                setAlertDisabled ( Variant.valueOf ( value ).asBoolean ( false ) );
            }
        } );

        // listener for single monitor
        final MonitorListener ml = new MonitorListener () {
            @Override
            public void statusChanged ( final MonitorStatusInformation status )
            {
                executor.execute ( new Runnable () {
                    @Override
                    public void run ()
                    {
                        handleStatusChanged ( status );
                    }
                } );
            }
        };

        // listener for all monitors of a pool
        final ObjectPoolListener objectPoolListener = new ObjectPoolListener () {
            @Override
            public void serviceAdded ( final Object service, final Dictionary<?, ?> properties )
            {
                ( (MonitorService)service ).addStatusListener ( ml );
            }

            @Override
            public void serviceRemoved ( final Object service, final Dictionary<?, ?> properties )
            {
                ( (MonitorService)service ).removeStatusListener ( ml );
            }

            @Override
            public void serviceModified ( final Object service, final Dictionary<?, ?> properties )
            {
                ( (MonitorService)service ).removeStatusListener ( ml );
                ( (MonitorService)service ).addStatusListener ( ml );
            }
        };

        // listener for all monitor pools
        monitorPoolTracker.addListener ( new ObjectPoolServiceListener () {
            @Override
            public void poolAdded ( final ObjectPool objectPool, final int priority )
            {
                objectPool.addListener ( objectPoolListener );
            }

            @Override
            public void poolRemoved ( final ObjectPool objectPool )
            {
                objectPool.removeListener ( objectPoolListener );
            }

            @Override
            public void poolModified ( final ObjectPool objectPool, final int newPriority )
            {
                objectPool.removeListener ( objectPoolListener );
                objectPool.addListener ( objectPoolListener );
            }
        } );
        logger.debug ( "InfoService created" );

        // set default values
        notifyChanges ();
        setValue ( this.alertActiveItem, false );
        setValue ( this.alertDisabledItem, this.alertDisabled );
    }

    ///////////////////////////////////////////////////////////////////////
    // public api
    ///////////////////////////////////////////////////////////////////////

    /**
     * @param parameters
     */
    public void update ( final Map<String, String> parameters )
    {
        this.executor.execute ( new Runnable () {
            @Override
            public void run ()
            {
                handleUpdate ( parameters );
            }

        } );
    }

    /**
     * 
     */
    public void dispose ()
    {
        this.executor.execute ( new Runnable () {
            @Override
            public void run ()
            {
                unregisterItems ( InfoService.this.prefix );
            }
        } );
    }

    ///////////////////////////////////////////////////////////////////////
    // private api
    ///////////////////////////////////////////////////////////////////////

    /**
     * @param parameters
     */
    private void handleUpdate ( final Map<String, String> parameters )
    {
        logger.debug ( "parameter change requested" );
        unregisterItems ( this.prefix );
        this.prefix = defaultParameter ( parameters, "prefix", InfoServiceFactory.FACTORY_ID );
        registerItems ( this.prefix );
        logger.info ( "parameters changed" );
    }

    /**
     * @param prefix
     */
    private void registerItems ( final String prefix )
    {
        for ( final Entry<String, DataInputSource> entry : this.items.entrySet () )
        {
            final String id = prefix + "." + entry.getKey ();
            logger.info ( "register item with id {}", id );
            this.dataSourcePool.addService ( id, entry.getValue (), new Properties () );
        }
        this.dataSourcePool.addService ( prefix + "." + ALERT_ACTIVE_ITEM, this.alertActiveItem, new Properties () );
        this.dataSourcePool.addService ( prefix + "." + ALERT_DISABLED_ITEM, this.alertDisabledItem, new Properties () );
    }

    /**
     * @param prefix
     */
    private void unregisterItems ( final String prefix )
    {
        for ( final Entry<String, DataInputSource> entry : this.items.entrySet () )
        {
            final String id = prefix + "." + entry.getKey ();
            this.dataSourcePool.removeService ( id, entry.getValue () );
            logger.info ( "unregister item with id {}", id );
        }
        this.dataSourcePool.removeService ( prefix + "." + ALERT_ACTIVE_ITEM, this.alertActiveItem );
        this.dataSourcePool.removeService ( prefix + "." + ALERT_DISABLED_ITEM, this.alertDisabledItem );
    }

    /**
     * @param msi
     */
    private void handleStatusChanged ( final MonitorStatusInformation msi )
    {
        if ( msi == null )
        {
            throw new IllegalArgumentException ( "'monitorInformation' must not be null" );
        }

        Boolean active = null;

        final MonitorStatusInformation oldMsi = this.cachedMonitors.put ( msi.getId (), msi );
        if ( oldMsi != null )
        {
            this.aggregatedMonitors.get ( oldMsi.getStatus () ).decrementAndGet ();
            if ( oldMsi.getStatus () == MonitorStatus.NOT_OK_NOT_AKN || oldMsi.getStatus () == MonitorStatus.NOT_AKN )
            {
                active = false;
            }
        }
        this.aggregatedMonitors.get ( msi.getStatus () ).incrementAndGet ();
        if ( msi.getStatus () == MonitorStatus.NOT_OK_NOT_AKN || msi.getStatus () == MonitorStatus.NOT_AKN )
        {
            active = true;
        }

        if ( active != null )
        {
            if ( active )
            {
                alert ();
            }
            else
            {
                silenceAlert ();
            }
        }
        notifyChanges ();
    }

    /**
     * 
     */
    private void alert ()
    {
        logger.info ( "alert enabled" );
        if ( !this.alertDisabled )
        {
            setValue ( this.alertActiveItem, true );
        }
    }

    /**
     * 
     */
    private void silenceAlert ()
    {
        logger.info ( "alert disabled" );
        setValue ( this.alertActiveItem, false );
    }

    /**
     * @param disabled
     */
    private void setAlertDisabled ( final boolean disabled )
    {
        this.alertDisabled = disabled;
        setValue ( this.alertDisabledItem, this.alertDisabled );
        if ( disabled )
        {
            silenceAlert ();
        }
    }

    /**
     * reset summation of monitors
     */
    private void clearAggregatedMonitors ()
    {
        this.aggregatedMonitors.clear ();
        for ( final MonitorStatus status : MonitorStatus.values () )
        {
            this.aggregatedMonitors.put ( status, new AtomicInteger ( 0 ) );
        }
    }

    /**
     * send all changes to client
     */
    private void notifyChanges ()
    {
        for ( final MonitorStatus monitorStatus : MonitorStatus.values () )
        {
            setValue ( this.items.get ( monitorStatus.name () ), this.aggregatedMonitors.get ( monitorStatus ) );
        }
    }

    ///////////////////////////////////////////////////////////////////////
    // helper methods
    ///////////////////////////////////////////////////////////////////////

    /**
     * @param item
     * @param value
     */
    private void setValue ( final DataInputSource item, final Object value )
    {
        final Builder div = new DataItemValue.Builder ();
        div.setValue ( Variant.valueOf ( value ) );
        item.setValue ( div.build () );
    }

    /**
     * @param parameters
     * @param key
     * @param defaultValue
     * @return
     */
    private String defaultParameter ( final Map<String, String> parameters, final String key, final String defaultValue )
    {
        final String value = parameters.get ( key );
        if ( value == null || "".equals ( value.trim () ) )
        {
            return defaultValue;
        }
        return value;
    }
}
