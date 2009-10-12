package org.openscada.hd.server.storage.osgi;

import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.Map.Entry;

import org.openscada.core.Variant;
import org.openscada.da.client.DataItemValue;
import org.openscada.hd.HistoricalItemInformation;
import org.openscada.hd.Query;
import org.openscada.hd.QueryListener;
import org.openscada.hd.QueryParameters;
import org.openscada.hd.Value;
import org.openscada.hd.ValueInformation;
import org.openscada.hd.server.common.StorageHistoricalItem;
import org.openscada.hd.server.storage.ConfigurationImpl;
import org.openscada.hd.server.storage.ExtendedStorageChannel;
import org.openscada.hd.server.storage.calculation.CalculationMethod;
import org.openscada.hd.server.storage.datatypes.DoubleValue;
import org.openscada.hd.server.storage.datatypes.LongValue;
import org.openscada.hd.server.storage.relict.RelictCleaner;
import org.openscada.hd.server.storage.relict.RelictCleanerCallerTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of StorageHistoricalItem as OSGi service.
 * @author Ludwig Straub
 */
public class ShiService implements StorageHistoricalItem, RelictCleaner
{
    /** The default logger. */
    private final static Logger logger = LoggerFactory.getLogger ( ShiService.class );

    /** Delay in milliseconds after that old data is deleted for the first time after initialization of the class. */
    private final static long CLEANER_TASK_DELAY = 1000 * 60;

    /** Period in milliseconds between two consecutive attemps to delete old data. */
    private final static long CLEANER_TASK_PERIOD = 1000 * 60 * 10;

    private final ConfigurationImpl configuration;

    private final Map<CalculationMethod, ExtendedStorageChannel> storageChannels;

    private ExtendedStorageChannel rootStorageChannel;

    /** Flag indicating whether the service is currently running or not. */
    private boolean started;

    /** Timer that is used for deleting old data. */
    private Timer deleteRelictsTimer;

    public ShiService ( final ConfigurationImpl configuration )
    {
        this.configuration = configuration;
        this.storageChannels = new HashMap<CalculationMethod, ExtendedStorageChannel> ();
        this.rootStorageChannel = null;
        this.started = false;
    }

    public ConfigurationImpl getConfiguration ()
    {
        return this.configuration;
    }

    /**
     * @see org.openscada.hd.server.common.StorageHistoricalItem#createQuery
     */
    public Query createQuery ( final QueryParameters parameters, final QueryListener listener, final boolean updateData )
    {
        try
        {
            final Map<String, Value[]> map = new HashMap<String, Value[]> ();
            ValueInformation[] valueInformations = null;
            final Set<String> calculationMethods = new HashSet<String> ();
            for ( final Entry<CalculationMethod, ExtendedStorageChannel> entry : this.storageChannels.entrySet () )
            {
                final CalculationMethod calculationMethod = entry.getKey ();
                final DoubleValue[] dvs = entry.getValue ().getDoubleValues ( parameters.getStartTimestamp ().getTimeInMillis (), parameters.getEndTimestamp ().getTimeInMillis () );
                final Value[] values = new Value[dvs.length];
                if ( calculationMethod == CalculationMethod.AVERAGE )
                {
                    valueInformations = new ValueInformation[dvs.length];
                }
                for ( int i = 0; i < dvs.length; i++ )
                {
                    final DoubleValue doubleValue = dvs[i];
                    values[i] = new Value ( doubleValue.getValue () );
                    if ( calculationMethod == CalculationMethod.AVERAGE )
                    {
                        valueInformations[i] = new ValueInformation ( parameters.getStartTimestamp (), parameters.getEndTimestamp (), doubleValue.getQualityIndicator (), doubleValue.getBaseValueCount () );
                    }
                }
                if ( calculationMethod == CalculationMethod.AVERAGE )
                {
                    map.put ( CalculationMethod.convertCalculationMethodToShortString ( calculationMethod ), values );
                    calculationMethods.add ( CalculationMethod.convertCalculationMethodToShortString ( calculationMethod ) );
                }
            }
            listener.updateParameters ( parameters, calculationMethods );
            listener.updateData ( 0, map, valueInformations );
        }
        catch ( final Exception e )
        {
            logger.warn ( "Failed to create query", e );
        }
        return new Query () {
            public void changeParameters ( final QueryParameters parameters )
            {
            }

            public void close ()
            {
            }
        };
    }

    /**
     * @see org.openscada.hd.server.common.StorageHistoricalItem#getInformation
     */
    public HistoricalItemInformation getInformation ()
    {
        // FIXME: remove the whole method
        return null;
    }

    /**
     * @see org.openscada.hd.server.common.StorageHistoricalItem#updateData
     */
    public synchronized void updateData ( final DataItemValue value )
    {
        if ( !this.started || this.rootStorageChannel == null || value == null )
        {
            return;
        }
        final Variant variant = value.getValue ();
        if ( variant == null )
        {
            return;
        }
        final Calendar calendar = value.getTimestamp ();
        final long time = calendar == null ? System.currentTimeMillis () : calendar.getTimeInMillis ();
        final double qualityIndicator = !value.isConnected () || value.isError () ? 0 : 1;
        try
        {
            if ( variant.isLong () || variant.isInteger () || variant.isBoolean () )
            {
                this.rootStorageChannel.updateLong ( new LongValue ( time, qualityIndicator, 1, variant.asLong ( 0L ) ) );
            }
            else
            {
                this.rootStorageChannel.updateDouble ( new DoubleValue ( time, qualityIndicator, 1, variant.asDouble ( 0.0 ) ) );
            }
        }
        catch ( final Exception e )
        {
            logger.error ( String.format ( "could not process value (%s)", variant ), e );
        }
    }

    public synchronized void addStorageChannel ( final ExtendedStorageChannel storageChannel, final CalculationMethod calculationMethod )
    {
        this.storageChannels.put ( calculationMethod, storageChannel );
        if ( calculationMethod == CalculationMethod.NATIVE )
        {
            this.rootStorageChannel = storageChannel;
        }
    }

    /**
     * This method activates the service processing.
     * The methods updateData and createQuery only have effect after calling this method.
     */
    public synchronized void start ()
    {
        this.deleteRelictsTimer = new Timer ();
        this.deleteRelictsTimer.schedule ( new RelictCleanerCallerTask ( this ), CLEANER_TASK_DELAY, CLEANER_TASK_PERIOD );
        this.started = true;
    }

    /**
     * This method stops the service from processing and destroys its internal structure.
     * The service cannot be started again, after stop has been called.
     * After calling this method, no further call to this service can be made.
     */
    public synchronized void stop ()
    {
        this.started = false;
        if ( this.deleteRelictsTimer != null )
        {
            this.deleteRelictsTimer.cancel ();
            this.deleteRelictsTimer.purge ();
            this.deleteRelictsTimer = null;
        }
    }

    /**
     * @see org.openscada.hd.server.storage.relict.RelictCleaner#cleanupRelicts
     */
    public synchronized void cleanupRelicts () throws Exception
    {
        if ( this.rootStorageChannel != null )
        {
            this.rootStorageChannel.cleanupRelicts ();
        }
    }
}
