package org.openscada.ae.monitor.dataitem.monitor.internal.remote;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

import org.openscada.ae.ConditionStatus;
import org.openscada.ae.event.EventProcessor;
import org.openscada.ae.monitor.dataitem.DataItemMonitor;
import org.openscada.ca.ConfigurationDataHelper;
import org.openscada.core.Variant;
import org.openscada.da.client.DataItemValue;
import org.openscada.da.client.DataItemValue.Builder;
import org.openscada.da.datasource.WriteInformation;
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

    public RemoteBooleanAttributeAlarmMonitor ( final BundleContext context, final Executor executor, final ObjectPoolTracker poolTracker, final EventProcessor eventProcessor, final String id, final int priority )
    {
        super ( context, executor, poolTracker, priority, id, eventProcessor );
    }

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
            setState ( ConditionStatus.UNSAFE );
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

        final ConditionStatus state;

        if ( !activeFlag )
        {
            state = ConditionStatus.INACTIVE;
        }
        else if ( ack == null )
        {
            state = alarmFlag ? ConditionStatus.NOT_OK : ConditionStatus.OK;
        }
        else
        {
            final boolean ackRequiredFlag = ack.asBoolean ();
            if ( alarmFlag )
            {
                if ( ackRequiredFlag )
                {
                    state = ConditionStatus.NOT_OK_NOT_AKN;
                }
                else
                {
                    state = ConditionStatus.NOT_OK_AKN;
                }
            }
            else
            {
                if ( ackRequiredFlag )
                {
                    state = ConditionStatus.NOT_AKN;
                }
                else
                {
                    state = ConditionStatus.OK;
                }
            }
        }

        setState ( state, timestamp, aknTimestamp );

        return injectState ( builder ).build ();
    }

    public void akn ( final UserInformation aknUser, final Date aknTimestamp )
    {
        publishAckRequestEvent ( aknUser, aknTimestamp );

        final Map<String, Variant> attributes = new HashMap<String, Variant> ();
        attributes.put ( this.attributeAck, Variant.TRUE );

        for ( final MasterItem item : getMasterItems () )
        {
            item.startWriteAttributes ( new WriteInformation ( aknUser ), attributes );
        }
    }

    public void setActive ( final boolean state )
    {
        final Map<String, Variant> attributes = new HashMap<String, Variant> ();
        attributes.put ( this.attributeActive, state ? Variant.TRUE : Variant.FALSE );

        for ( final MasterItem item : getMasterItems () )
        {
            item.startWriteAttributes ( new WriteInformation ( null ), attributes );
        }
    }

    @Override
    public synchronized void update ( final Map<String, String> parameters ) throws Exception
    {
        super.update ( parameters );

        logger.debug ( "Apply update: {}", parameters );

        final ConfigurationDataHelper cfg = new ConfigurationDataHelper ( parameters );

        this.attributeValue = cfg.getString ( "attribute.value.name" );
        this.attributeAck = cfg.getString ( "attribute.ack.name" );
        this.attributeActive = cfg.getString ( "attribute.active.name" );
        this.attributeTimestamp = cfg.getStringNonEmpty ( "attribute.active.timestamp.name" );
        this.attributeAckTimestamp = cfg.getStringNonEmpty ( "attribute.ack.timestamp.name" );

        reprocess ();

        logger.debug ( "Done applying" );
    }

}
