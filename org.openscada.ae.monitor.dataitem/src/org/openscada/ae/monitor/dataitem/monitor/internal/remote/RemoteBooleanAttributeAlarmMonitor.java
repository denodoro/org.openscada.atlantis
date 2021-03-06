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

package org.openscada.ae.monitor.dataitem.monitor.internal.remote;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

import org.openscada.ae.MonitorStatus;
import org.openscada.ae.event.EventProcessor;
import org.openscada.ae.monitor.dataitem.DataItemMonitor;
import org.openscada.ca.ConfigurationDataHelper;
import org.openscada.core.Variant;
import org.openscada.core.VariantEditor;
import org.openscada.da.client.DataItemValue;
import org.openscada.da.client.DataItemValue.Builder;
import org.openscada.da.core.OperationParameters;
import org.openscada.da.master.MasterItem;
import org.openscada.sec.UserInformation;
import org.openscada.utils.osgi.pool.ObjectPoolTracker;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RemoteBooleanAttributeAlarmMonitor extends GenericRemoteMonitor implements DataItemMonitor
{

    private final static Logger logger = LoggerFactory.getLogger ( RemoteBooleanAttributeAlarmMonitor.class );

    public static final String FACTORY_ID = "ae.monitor.da.remote.booleanAttributeAlarm";

    private String attributeValue;

    private String attributeAck;

    private String attributeActive;

    private String attributeTimestamp;

    private String attributeAckTimestamp;

    private Variant aknValue = Variant.TRUE;

    public RemoteBooleanAttributeAlarmMonitor ( final BundleContext context, final Executor executor, final ObjectPoolTracker poolTracker, final EventProcessor eventProcessor, final String id, final int priority )
    {
        super ( context, executor, poolTracker, priority, id, eventProcessor );
    }

    @Override
    protected DataItemValue handleUpdate ( final DataItemValue itemValue )
    {
        final Builder builder = new Builder ( itemValue );

        final Variant value = builder.getAttributes ().get ( this.attributeValue );
        final Variant ack = builder.getAttributes ().get ( this.attributeAck );
        final Variant active = builder.getAttributes ().get ( this.attributeActive );

        final Calendar timestamp = getTimestamp ( itemValue, this.attributeTimestamp );
        final Calendar aknTimestamp = getTimestamp ( itemValue, this.attributeAckTimestamp );

        if ( value == null )
        {
            setState ( MonitorStatus.UNSAFE );
            return injectState ( builder ).build ();
        }

        final boolean alarmFlag = value.asBoolean ();

        final boolean activeFlag;
        if ( active == null )
        {
            activeFlag = true;
        }
        else
        {
            activeFlag = active.asBoolean ();
        }

        final MonitorStatus state;

        if ( !activeFlag )
        {
            state = MonitorStatus.INACTIVE;
        }
        else if ( ack == null )
        {
            state = alarmFlag ? MonitorStatus.NOT_OK : MonitorStatus.OK;
        }
        else
        {
            final boolean ackRequiredFlag = ack.asBoolean ();
            if ( alarmFlag )
            {
                if ( ackRequiredFlag )
                {
                    state = MonitorStatus.NOT_OK_NOT_AKN;
                }
                else
                {
                    state = MonitorStatus.NOT_OK_AKN;
                }
            }
            else
            {
                if ( ackRequiredFlag )
                {
                    state = MonitorStatus.NOT_AKN;
                }
                else
                {
                    state = MonitorStatus.OK;
                }
            }
        }

        setState ( state, timestamp.getTime (), aknTimestamp.getTime () );

        return injectState ( builder ).build ();
    }

    @Override
    public void akn ( final UserInformation aknUser, final Date aknTimestamp )
    {
        publishAckRequestEvent ( aknUser, aknTimestamp );

        final Map<String, Variant> attributes = new HashMap<String, Variant> ();
        attributes.put ( this.attributeAck, this.aknValue );

        for ( final MasterItem item : getMasterItems () )
        {
            item.startWriteAttributes ( attributes, new OperationParameters ( aknUser ) );
        }
    }

    @Override
    public void setActive ( final UserInformation userInformation, final boolean state )
    {
        final Map<String, Variant> attributes = new HashMap<String, Variant> ();
        attributes.put ( this.attributeActive, state ? Variant.TRUE : Variant.FALSE );

        for ( final MasterItem item : getMasterItems () )
        {
            item.startWriteAttributes ( attributes, new OperationParameters ( UserInformation.ANONYMOUS ) );
        }
    }

    @Override
    public synchronized void update ( final UserInformation userInformation, final Map<String, String> parameters ) throws Exception
    {
        super.update ( userInformation, parameters );

        logger.debug ( "Apply update: {}", parameters );

        final ConfigurationDataHelper cfg = new ConfigurationDataHelper ( parameters );

        this.attributeValue = cfg.getString ( "attribute.value.name" );
        this.attributeAck = cfg.getString ( "attribute.ack.name" );
        this.attributeActive = cfg.getString ( "attribute.active.name" );
        this.attributeTimestamp = cfg.getStringNonEmpty ( "attribute.active.timestamp.name" );
        this.attributeAckTimestamp = cfg.getStringNonEmpty ( "attribute.ack.timestamp.name" );

        final VariantEditor ve = new VariantEditor ();
        ve.setAsText ( cfg.getString ( "attribute.ack.value", "BOOL#true" ) );
        this.aknValue = (Variant)ve.getValue ();

        reprocess ();

        logger.debug ( "Done applying" );
    }

}
