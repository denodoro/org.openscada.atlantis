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

package org.openscada.hd.server.common.internal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.openscada.core.InvalidSessionException;
import org.openscada.core.UnableToCreateSessionException;
import org.openscada.core.server.common.ServiceCommon;
import org.openscada.hd.HistoricalItemInformation;
import org.openscada.hd.InvalidItemException;
import org.openscada.hd.Query;
import org.openscada.hd.QueryListener;
import org.openscada.hd.QueryParameters;
import org.openscada.hd.server.Service;
import org.openscada.hd.server.Session;
import org.openscada.hd.server.common.HistoricalItem;
import org.openscada.sec.UserInformation;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.Profiler;

public class ServiceImpl extends ServiceCommon implements Service, ServiceTrackerCustomizer<HistoricalItem, HistoricalItem>
{

    private final static Logger logger = LoggerFactory.getLogger ( ServiceImpl.class );

    private final ReadWriteLock sessionLock = new ReentrantReadWriteLock ();

    private final Set<SessionImpl> sessions = new HashSet<SessionImpl> ();

    private final BundleContext context;

    private final ServiceTracker<HistoricalItem, HistoricalItem> tracker;

    private final Map<String, HistoricalItem> items = new HashMap<String, HistoricalItem> ();

    private final Set<HistoricalItemInformation> itemInformations = new HashSet<HistoricalItemInformation> ();

    public ServiceImpl ( final BundleContext context ) throws InvalidSyntaxException
    {
        this.context = context;
        this.tracker = new ServiceTracker<HistoricalItem, HistoricalItem> ( this.context, HistoricalItem.class, this );
    }

    @Override
    public void closeSession ( final org.openscada.core.server.Session session ) throws InvalidSessionException
    {
        SessionImpl sessionImpl = null;

        try
        {
            this.sessionLock.writeLock ().lock ();
            if ( this.sessions.remove ( session ) )
            {
                sessionImpl = (SessionImpl)session;

                sessionImpl.dispose ();
            }
        }
        finally
        {
            this.sessionLock.writeLock ().unlock ();
        }

        if ( sessionImpl != null )
        {
        }
    }

    @Override
    public org.openscada.core.server.Session createSession ( final Properties properties ) throws UnableToCreateSessionException
    {
        final Map<String, String> sessionResultProperties = new HashMap<String, String> ();
        final UserInformation user = createUserInformation ( properties, sessionResultProperties );
        final SessionImpl session = new SessionImpl ( user, sessionResultProperties );
        try
        {
            this.sessionLock.writeLock ().lock ();
            synchronized ( this )
            {
                // bad locking strategy ...
                this.sessions.add ( session );
                logger.info ( "Sending known items: {}", this.itemInformations.size () );
                session.listChanged ( this.itemInformations, null, true );
            }
        }
        finally
        {
            this.sessionLock.writeLock ().unlock ();
        }
        return session;
    }

    @Override
    public void start () throws Exception
    {
        logger.info ( "Staring new service" );
        this.tracker.open ();
    }

    @Override
    public void stop () throws Exception
    {
        logger.info ( "Stopping service" );
        this.tracker.close ();
    }

    protected SessionImpl validateSession ( final Session session ) throws InvalidSessionException
    {
        if ( ! ( session instanceof Session ) )
        {
            throw new InvalidSessionException ();
        }

        try
        {
            this.sessionLock.readLock ().lock ();
            if ( !this.sessions.contains ( session ) )
            {
                throw new InvalidSessionException ();
            }
        }
        finally
        {
            this.sessionLock.readLock ().unlock ();
        }

        return (SessionImpl)session;
    }

    public static final String CREATE_QUERY_PROFILER = "CREATE_QUERY";

    @Override
    public Query createQuery ( final Session session, final String itemId, final QueryParameters parameters, final QueryListener listener, final boolean updateData ) throws InvalidSessionException, InvalidItemException
    {
        final Profiler p = new Profiler ( "createQuery" );
        p.setLogger ( logger );

        p.start ( "Validate session" );
        final SessionImpl sessionImpl = validateSession ( session );

        try
        {
            synchronized ( this )
            {
                p.start ( "Get item" );

                final HistoricalItem item = this.items.get ( itemId );
                if ( item == null )
                {
                    throw new InvalidItemException ( itemId );
                }
                p.start ( "new Query" );
                final QueryImpl queryImpl = new QueryImpl ( sessionImpl, listener );
                p.start ( "createQuery" );
                final Query query = item.createQuery ( parameters, queryImpl, updateData );
                p.start ( "Completing" );

                if ( query != null )
                {
                    queryImpl.setQuery ( query );
                    return queryImpl;
                }
                else
                {
                    logger.warn ( "Unable to create query: {}", itemId );
                    return null;
                }
            }
        }
        finally
        {
            p.stop ().log ();
        }
    }

    protected void fireListChanged ( final Set<HistoricalItemInformation> addedOrModified, final Set<String> removed, final boolean full )
    {
        try
        {
            this.sessionLock.readLock ().lock ();
            for ( final SessionImpl session : this.sessions )
            {
                session.listChanged ( addedOrModified, removed, full );
            }
        }
        finally
        {
            this.sessionLock.readLock ().unlock ();
        }
    }

    @Override
    public HistoricalItem addingService ( final ServiceReference<HistoricalItem> reference )
    {
        logger.info ( "Adding service: {}", reference );

        final String itemId = (String)reference.getProperty ( Constants.SERVICE_PID );
        if ( itemId == null )
        {
            logger.warn ( "Failed to register item {}. '{}' is not set", reference, Constants.SERVICE_PID );
            return null;
        }

        final HistoricalItem item = this.context.getService ( reference );
        final HistoricalItemInformation info = item.getInformation ();

        if ( !itemId.equals ( info.getId () ) )
        {
            logger.warn ( "Unable to register item since {} ({}) and item id ({}) don't match", new Object[] { Constants.SERVICE_PID, itemId, info.getId () } );
            this.context.ungetService ( reference );
            return null;
        }

        synchronized ( this )
        {
            if ( this.items.containsKey ( info.getId () ) )
            {
                this.context.ungetService ( reference );
                return null;
            }
            else
            {
                this.items.put ( info.getId (), item );
                this.itemInformations.add ( info );
                fireListChanged ( new HashSet<HistoricalItemInformation> ( Arrays.asList ( info ) ), null, false );
                return item;
            }
        }
    }

    @Override
    public void modifiedService ( final ServiceReference<HistoricalItem> reference, final HistoricalItem service )
    {
    }

    @Override
    public void removedService ( final ServiceReference<HistoricalItem> reference, final HistoricalItem service )
    {
        final String itemId = (String)reference.getProperty ( Constants.SERVICE_PID );

        synchronized ( this )
        {
            final HistoricalItem item = this.items.remove ( itemId );
            if ( item != null )
            {
                this.context.ungetService ( reference );
                this.itemInformations.remove ( item.getInformation () );
                fireListChanged ( null, new HashSet<String> ( Arrays.asList ( itemId ) ), false );
            }
        }
    }
}
