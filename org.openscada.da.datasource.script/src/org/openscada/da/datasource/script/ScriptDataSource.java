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

package org.openscada.da.datasource.script;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.script.SimpleScriptContext;

import org.openscada.ae.event.EventProcessor;
import org.openscada.ca.ConfigurationDataHelper;
import org.openscada.core.OperationException;
import org.openscada.core.Variant;
import org.openscada.core.subscription.SubscriptionState;
import org.openscada.da.client.DataItemValue;
import org.openscada.da.client.DataItemValue.Builder;
import org.openscada.da.core.OperationParameters;
import org.openscada.da.core.WriteAttributeResult;
import org.openscada.da.core.WriteAttributeResults;
import org.openscada.da.core.WriteResult;
import org.openscada.da.datasource.base.AbstractMultiSourceDataSource;
import org.openscada.da.datasource.base.DataSourceHandler;
import org.openscada.utils.concurrent.FutureTask;
import org.openscada.utils.concurrent.InstantErrorFuture;
import org.openscada.utils.concurrent.NotifyFuture;
import org.openscada.utils.osgi.pool.ObjectPoolTracker;
import org.openscada.utils.script.ScriptExecutor;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScriptDataSource extends AbstractMultiSourceDataSource
{
    private static final String DEFAULT_ENGINE_NAME = System.getProperty ( "org.openscada.da.datasource.script.defaultScriptEngine", "JavaScript" );

    final static Logger logger = LoggerFactory.getLogger ( ScriptDataSource.class );

    private final ScheduledExecutorService executor;

    private final ScriptEngineManager manager;

    private SimpleScriptContext scriptContext;

    private ScriptExecutor updateCommand;

    private ScriptExecutor timerCommand;

    private ScriptEngine scriptEngine;

    private final ClassLoader classLoader;

    private final WriterController writer;

    private ScheduledFuture<?> timer;

    private ScriptExecutor writeCommand;

    private final EventProcessor eventProcessor;

    public ScriptDataSource ( final BundleContext context, final ObjectPoolTracker poolTracker, final ScheduledExecutorService executor, final EventProcessor eventProcessor )
    {
        super ( poolTracker );
        this.executor = executor;
        this.classLoader = getClass ().getClassLoader ();
        this.eventProcessor = eventProcessor;

        final ClassLoader currentClassLoader = Thread.currentThread ().getContextClassLoader ();

        try
        {
            Thread.currentThread ().setContextClassLoader ( this.classLoader );
            this.manager = new ScriptEngineManager ( this.classLoader );
        }
        finally
        {
            Thread.currentThread ().setContextClassLoader ( currentClassLoader );
        }

        this.writer = new WriterController ( poolTracker );
    }

    @Override
    protected Executor getExecutor ()
    {
        return this.executor;
    }

    protected Object performWrite ( final ScriptExecutor command, final Variant value, final Map<String, Variant> attributes, final OperationParameters operationParameters ) throws Exception
    {
        this.scriptContext.setAttribute ( "value", value, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "attributes", attributes, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "parameters", operationParameters, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "eventProcessor", this.eventProcessor, ScriptContext.ENGINE_SCOPE );

        return performScript ( command, this.scriptContext );
    }

    @Override
    public NotifyFuture<WriteAttributeResults> startWriteAttributes ( final Map<String, Variant> attributes, final OperationParameters operationParameters )
    {
        final ScriptExecutor writeCommand = this.writeCommand;
        if ( writeCommand == null )
        {
            return new InstantErrorFuture<WriteAttributeResults> ( new OperationException ( "Not supported" ) );
        }

        final FutureTask<WriteAttributeResults> task = new FutureTask<WriteAttributeResults> ( new Callable<WriteAttributeResults> () {
            @Override
            public WriteAttributeResults call () throws Exception
            {
                return convertAttributeResult ( attributes, performWrite ( writeCommand, null, attributes, operationParameters ) );
            }
        } );
        this.executor.execute ( task );
        return task;
    }

    protected WriteAttributeResults convertAttributeResult ( final Map<String, Variant> attributes, final Object result )
    {
        if ( result == null )
        {
            final WriteAttributeResults r = new WriteAttributeResults ();

            // mark all as ok
            for ( final Map.Entry<String, Variant> entry : attributes.entrySet () )
            {
                r.put ( entry.getKey (), WriteAttributeResult.OK );
            }
            return r;
        }
        if ( result instanceof WriteAttributeResults )
        {
            return (WriteAttributeResults)result;
        }
        if ( result instanceof Map<?, ?> )
        {
            final WriteAttributeResults r = new WriteAttributeResults ();

            final Map<?, ?> map = (Map<?, ?>)result;
            for ( final Map.Entry<?, ?> entry : map.entrySet () )
            {
                if ( entry.getKey () instanceof String && entry.getValue () instanceof WriteAttributeResult )
                {
                    r.put ( (String)entry.getKey (), (WriteAttributeResult)entry.getValue () );
                }
            }
            return r;
        }

        // else ...

        final WriteAttributeResults r = new WriteAttributeResults ();

        // mark all as ok
        for ( final Map.Entry<String, Variant> entry : attributes.entrySet () )
        {
            r.put ( entry.getKey (), new WriteAttributeResult ( new OperationException ( String.format ( "Write attribute result error: %s", result ) ) ) );
        }
        return r;
    }

    protected WriteResult convertValueResult ( final Object result )
    {
        if ( result == null )
        {
            return WriteResult.OK;
        }
        if ( result instanceof WriteResult )
        {
            return (WriteResult)result;
        }
        return new WriteResult ( new OperationException ( String.format ( "Write error: %s", result ) ) );
    }

    @Override
    public NotifyFuture<WriteResult> startWriteValue ( final Variant value, final OperationParameters operationParameters )
    {
        final ScriptExecutor writeCommand = this.writeCommand;
        if ( writeCommand == null )
        {
            return new InstantErrorFuture<WriteResult> ( new OperationException ( "Not supported" ) );
        }

        final FutureTask<WriteResult> task = new FutureTask<WriteResult> ( new Callable<WriteResult> () {
            @Override
            public WriteResult call () throws Exception
            {
                return convertValueResult ( performWrite ( writeCommand, value, null, operationParameters ) );
            }
        } );
        this.executor.execute ( task );
        return task;
    }

    public synchronized void update ( final Map<String, String> parameters ) throws Exception
    {
        stopTimer ();

        final ClassLoader currentClassLoader = Thread.currentThread ().getContextClassLoader ();
        try
        {
            final ClassLoader classLoader = getClass ().getClassLoader ();
            Thread.currentThread ().setContextClassLoader ( classLoader );

            final ConfigurationDataHelper cfg = new ConfigurationDataHelper ( parameters );

            setWriteItems ( cfg );
            setScript ( cfg );
            setDataSources ( parameters );
            startTimer ( cfg.getInteger ( "timer", -1 ) );

            handleChange ();
        }
        finally
        {
            Thread.currentThread ().setContextClassLoader ( currentClassLoader );
        }
    }

    private void setWriteItems ( final ConfigurationDataHelper cfg )
    {
        this.writer.setWriteItems ( cfg.getPrefixed ( "writeSource." ) );
    }

    private void startTimer ( final int period )
    {
        if ( period <= 0 )
        {
            return;
        }

        this.timer = this.executor.scheduleAtFixedRate ( new Runnable () {

            @Override
            public void run ()
            {
                handleTimer ();
            }
        }, period, period, TimeUnit.MILLISECONDS );
    }

    private void stopTimer ()
    {
        if ( this.timer != null )
        {
            this.timer.cancel ( false );
            this.timer = null;
        }
    }

    private void setScript ( final ConfigurationDataHelper cfg ) throws ScriptException
    {

        String engine = cfg.getString ( "engine", DEFAULT_ENGINE_NAME );
        if ( "".equals ( engine ) )
        {
            engine = DEFAULT_ENGINE_NAME;
        }

        this.scriptContext = new SimpleScriptContext ();

        this.scriptEngine = this.manager.getEngineByName ( engine );
        if ( this.scriptEngine == null )
        {
            throw new IllegalArgumentException ( String.format ( "'%s' is not a valid script engine", engine ) );
        }

        // trigger init script
        final String initScript = cfg.getString ( "init" );
        if ( initScript != null )
        {
            this.scriptEngine.eval ( initScript, this.scriptContext );
        }

        this.updateCommand = makeScript ( cfg.getString ( "updateCommand" ) );
        this.timerCommand = makeScript ( cfg.getString ( "timerCommand" ) );
        this.writeCommand = makeScript ( cfg.getString ( "writeCommand" ) );
    }

    private ScriptExecutor makeScript ( final String string ) throws ScriptException
    {
        if ( string == null || string.isEmpty () )
        {
            return null;
        }

        return new ScriptExecutor ( this.scriptEngine, string, this.classLoader );
    }

    protected synchronized void handleTimer ()
    {
        this.scriptContext.setAttribute ( "writer", this.writer, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "eventProcessor", this.eventProcessor, ScriptContext.ENGINE_SCOPE );

        executeScript ( this.timerCommand );
    }

    /**
     * Handle data change
     */
    @Override
    protected synchronized void handleChange ()
    {
        // calcuate
        // gather all data
        final Map<String, DataItemValue> values = new HashMap<String, DataItemValue> ();
        for ( final Map.Entry<String, DataSourceHandler> entry : this.sources.entrySet () )
        {
            values.put ( entry.getKey (), entry.getValue ().getValue () );
        }

        this.scriptContext.setAttribute ( "data", values, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "writer", this.writer, ScriptContext.ENGINE_SCOPE );
        this.scriptContext.setAttribute ( "eventProcessor", this.eventProcessor, ScriptContext.ENGINE_SCOPE );

        executeScript ( this.updateCommand );
    }

    protected Object performScript ( final ScriptExecutor command, final ScriptContext scriptContext ) throws Exception
    {
        return command.execute ( scriptContext );
    }

    protected void executeScript ( final ScriptExecutor command )
    {
        if ( command == null )
        {
            return;
        }

        try
        {
            setResult ( performScript ( command, this.scriptContext ) );
        }
        catch ( final Throwable e )
        {
            logger.warn ( "Failed to evaluate", e );
            logger.debug ( "Failed script: {}", command );
            setError ( e );
        }
    }

    private synchronized void setError ( final Throwable e )
    {
        final Builder builder = new DataItemValue.Builder ();
        builder.setValue ( Variant.NULL );
        builder.setTimestamp ( Calendar.getInstance () );
        builder.setAttribute ( "script.error", Variant.TRUE );
        builder.setAttribute ( "script.error.message", Variant.valueOf ( e.getMessage () ) );
        updateData ( builder.build () );
    }

    private synchronized void setResult ( final Object result )
    {
        logger.debug ( "Setting result: {}", result );

        if ( result instanceof Builder )
        {
            logger.debug ( "Using builder" );
            updateData ( ( (Builder)result ).build () );
        }
        else if ( result instanceof DataItemValue )
        {
            logger.debug ( "Using data item value" );
            updateData ( (DataItemValue)result );
        }
        else
        {
            logger.debug ( "Falling back to plain value" );
            final Builder builder = new DataItemValue.Builder ();
            builder.setSubscriptionState ( SubscriptionState.CONNECTED );
            builder.setValue ( Variant.valueOf ( result ) );
            updateData ( builder.build () );
        }
    }

}
