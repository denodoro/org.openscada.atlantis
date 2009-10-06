package org.openscada.hd.server.storage.backend;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.openscada.hd.server.storage.StorageChannelMetaData;
import org.openscada.hd.server.storage.calculation.CalculationMethod;
import org.openscada.hd.server.storage.datatypes.LongValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This backend implementation is able to handle multiple storage channel backend objects.
 * It is arranged that each such backend object is responsible for its own exclusive time span.
 * @author Ludwig Straub
 */
public class BackEndMultiplexor implements BackEnd
{
    /**
     * Comparator that is used to sort storage channel meta data by time span.
     * @author Ludwig Straub
     */
    private static class InverseTimeOrderComparator implements Comparator<BackEnd>
    {
        /**
         * @see java.util.Comparator#compare
         */
        public int compare ( final BackEnd o1, final BackEnd o2 )
        {
            if ( o1 == null )
            {
                return 1;
            }
            if ( o2 == null )
            {
                return -1;
            }
            StorageChannelMetaData m1 = null;
            try
            {
                m1 = o1.getMetaData ();
            }
            catch ( Exception e )
            {
                return 1;
            }
            StorageChannelMetaData m2 = null;
            try
            {
                m2 = o2.getMetaData ();
            }
            catch ( Exception e )
            {
                return -1;
            }
            if ( m1 == null )
            {
                return 1;
            }
            if ( m2 == null )
            {
                return -1;
            }
            final long endTime1 = m1.getEndTime ();
            final long endTime2 = m2.getEndTime ();
            if ( endTime1 < endTime2 )
            {
                return 1;
            }
            if ( endTime1 > endTime2 )
            {
                return -1;
            }
            final long startTime1 = m1.getStartTime ();
            final long startTime2 = m2.getStartTime ();
            if ( startTime1 < startTime2 )
            {
                return 1;
            }
            if ( startTime1 > startTime2 )
            {
                return -1;
            }
            return 0;
        }
    }

    /** The default logger. */
    private final static Logger logger = LoggerFactory.getLogger ( BackEndMultiplexor.class );

    /** Metadata of the storage channel. */
    private StorageChannelMetaData metaData;

    /** Factory that is used to create new fractal backend objects. */
    private final BackEndFactory backEndFactory;

    /** List of currently available backend objects. The elements are sorted by time span. The latest element is placed first. */
    private final List<BackEnd> backEnds;

    /** Amount of milliseconds that can be contained by any newly created storage channel backend. */
    private final long newBackendTimespan;

    /**
     * Constructor.
     * @param backEndFactory factory that is used to create new fractal backend objects
     * @param newBackendTimespan timespan that is used when a new backend fragment has to be created
     */
    public BackEndMultiplexor ( final BackEndFactory backEndFactory, final long newBackendTimespan )
    {
        this.backEndFactory = backEndFactory;
        this.newBackendTimespan = newBackendTimespan;
        backEnds = new LinkedList<BackEnd> ();
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#create
     */
    public synchronized void create ( final StorageChannelMetaData storageChannelMetaData ) throws Exception
    {
        // assure that no old data exists
        if ( backEndFactory.getExistingBackEnds ( storageChannelMetaData.getDataItemId (), storageChannelMetaData.getDetailLevelId (), storageChannelMetaData.getCalculationMethod () ).length > 0 )
        {
            String message = String.format ( "data already exists for combination! (data source: '%s'; detail level: '%d'; calculation method: '%s')", storageChannelMetaData.getDataItemId (), storageChannelMetaData.getDetailLevelId (), CalculationMethod.convertCalculationMethodToString ( storageChannelMetaData.getCalculationMethod () ) );
            logger.error ( message );
            throw new Exception ( message );
        }
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#initialize
     */
    public synchronized void initialize ( final StorageChannelMetaData storageChannelMetaData ) throws Exception
    {
        backEnds.clear ();
        BackEnd[] backEndArray = backEndFactory.getExistingBackEnds ( storageChannelMetaData.getDataItemId (), storageChannelMetaData.getDetailLevelId (), storageChannelMetaData.getCalculationMethod () );
        Arrays.sort ( backEndArray, new InverseTimeOrderComparator () );
        backEnds.addAll ( Arrays.asList ( backEndArray ) );
        metaData = new StorageChannelMetaData ( storageChannelMetaData );
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#getMetaData
     */
    public synchronized StorageChannelMetaData getMetaData () throws Exception
    {
        if ( metaData == null )
        {
            String message = "method getMetaData must not be called when instance is not initialized";
            logger.error ( message );
            throw new Exception ( message );
        }
        return metaData;
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#isTimeSpanConstant
     */
    public boolean isTimeSpanConstant ()
    {
        return false;
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#deinitialize
     */
    public synchronized void deinitialize () throws Exception
    {
        for ( BackEnd backEnd : backEnds )
        {
            backEnd.deinitialize ();
        }
        metaData = null;
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEnd#delete
     */
    public synchronized void delete () throws Exception
    {
        for ( BackEnd backEnd : backEnds )
        {
            backEnd.delete ();
        }
        backEnds.clear ();
    }

    /**
     * This method returns the backend that is able to process data with the passed timestamp.
     * If no suitable backend currently exists, a new one will be created using the backend factory.
     * @param timestamp timestam for which a storage channel backend has to be retrieved
     * @return backend that is able to process data with the passed timestamp
     * @throws Exception in case of any problem
     */
    private BackEnd getBackEnd ( final long timestamp ) throws Exception
    {
        // search within the array of existing storage channel backends for a suitable channel
        long maxEndTime = Long.MAX_VALUE;
        final long size = backEnds.size ();
        BackEnd backEnd = null;
        for ( int i = 0; i < size; i++ )
        {
            backEnd = backEnds.get ( i );
            final StorageChannelMetaData metaData = backEnd.getMetaData ();
            final long startTime = metaData.getStartTime ();
            if ( startTime <= timestamp )
            {
                // check if an existing backend can be used
                long endTime = metaData.getEndTime ();
                if ( endTime > timestamp )
                {
                    return backEnd;
                }

                // calculate start time for the new storage channel backend fragment
                while ( ( endTime + this.newBackendTimespan ) <= timestamp )
                {
                    endTime += this.newBackendTimespan;
                    if ( endTime > maxEndTime )
                    {
                        String message = "logic error! end time cannot be before start time when creating a new storage channel backend fragment";
                        logger.error ( message );
                        throw new Exception ( message );
                    }
                }

                // a new backend has to be created
                StorageChannelMetaData storageChannelMetaData = new StorageChannelMetaData ( metaData );
                storageChannelMetaData.setStartTime ( endTime );
                storageChannelMetaData.setEndTime ( Math.min ( endTime + this.newBackendTimespan, maxEndTime ) );
                backEnd = backEndFactory.createNewBackEnd ( storageChannelMetaData );
                backEnd.create ( storageChannelMetaData );
                backEnd.initialize ( storageChannelMetaData );
                backEnds.add ( i, backEnd );
                return backEnd;
            }
            maxEndTime = startTime;
        }

        // create a new backend channel with a completely independent timespan, since no channel exists
        // as start time, a time not too far in the past is chosen, since older data might be processed in the future
        StorageChannelMetaData storageChannelMetaData = new StorageChannelMetaData ( metaData );
        storageChannelMetaData.setStartTime ( timestamp - this.newBackendTimespan / 10 );
        storageChannelMetaData.setEndTime ( storageChannelMetaData.getStartTime () + this.newBackendTimespan );
        backEnd = backEndFactory.createNewBackEnd ( storageChannelMetaData );
        backEnd.create ( storageChannelMetaData );
        backEnd.initialize ( storageChannelMetaData );
        backEnds.add ( backEnd );
        return backEnd;
    }

    /**
     * This method removes backend objects from the internal list.
     * @param backEndsToRemove backend objects that have to be removed
     */
    private void removeBackEnds ( List<BackEnd> backEndsToRemove )
    {
        for ( BackEnd backEnd : backEndsToRemove )
        {
            try
            {
                backEnds.remove ( backEnd );
                backEnd.deinitialize ();
            }
            catch ( Exception e )
            {
            }
        }
    }

    /**
     * @see org.openscada.hd.server.storage.StorageChannel#updateLong
     */
    public synchronized void updateLong ( final LongValue longValue ) throws Exception
    {
        if ( longValue != null )
        {
            try
            {
                getBackEnd ( longValue.getTime () ).updateLong ( longValue );
            }
            catch ( Exception e )
            {
                logger.error ( String.format ( "backend (%s): could not write to sub backend (startTime: %s)", metaData, longValue.getTime () ), e );
            }
        }
    }

    /**
     * @see org.openscada.hd.server.storage.StorageChannel#updateLongs
     */
    public synchronized void updateLongs ( final LongValue[] longValues ) throws Exception
    {
        if ( longValues != null )
        {
            // assign all long values to the backend that is responsible for their processing
            final Map<Long, List<LongValue>> backends = new HashMap<Long, List<LongValue>> ();
            for ( LongValue longValue : longValues )
            {
                long startTime = 0L;
                try
                {
                    startTime = getBackEnd ( longValue.getTime () ).getMetaData ().getStartTime ();
                }
                catch ( Exception e )
                {
                    logger.error ( String.format ( "backend (%s): could not access sub backend (startTime: %s)", metaData, longValue.getTime () ), e );
                }
                List<LongValue> longValuesToProcess = backends.get ( startTime );
                if ( longValuesToProcess == null )
                {
                    longValuesToProcess = new ArrayList<LongValue> ();
                    backends.put ( startTime, longValuesToProcess );
                }
                longValuesToProcess.add ( longValue );
            }

            // process the ordered long values as bulk
            for ( Map.Entry<Long, List<LongValue>> entry : backends.entrySet () )
            {
                try
                {
                    getBackEnd ( entry.getKey () ).updateLongs ( entry.getValue ().toArray ( EMPTY_LONGVALUE_ARRAY ) );
                }
                catch ( Exception e )
                {
                    logger.error ( String.format ( "backend (%s): could not write to sub backend (startTime: %s)", metaData, entry.getKey () ), e );
                }
            }
        }
    }

    /**
     * @see org.openscada.hd.server.storage.StorageChannel#getLongValues
     */
    public synchronized LongValue[] getLongValues ( final long startTime, final long endTime ) throws Exception
    {
        // collect result data
        final List<LongValue> longValues = new LinkedList<LongValue> ();
        List<BackEnd> backEndsToRemove = new ArrayList<BackEnd> ();
        for ( BackEnd backEnd : backEnds )
        {
            try
            {
                final StorageChannelMetaData metaData = backEnd.getMetaData ();
                if ( ( metaData.getStartTime () < endTime ) && ( metaData.getEndTime () > startTime ) )
                {
                    // process values that match the time span
                    longValues.addAll ( 0, Arrays.asList ( backEnd.getLongValues ( startTime, endTime ) ) );
                }
                else
                {
                    LongValue firstLongValue = longValues.isEmpty () ? null : longValues.get ( 0 );
                    if ( ( firstLongValue != null ) && ( firstLongValue.getTime () > startTime ) )
                    {
                        // add value
                        List<LongValue> array = Arrays.asList ( backEnd.getLongValues ( startTime, endTime ) );
                        if ( !array.isEmpty () )
                        {
                            longValues.addAll ( 0, array );
                            break;
                        }
                    }
                }
            }
            catch ( Exception e )
            {
                backEndsToRemove.add ( backEnd );
                String message = String.format ( "backend (%s): could not read from sub backend (startTime: %s; endTime: %s)", metaData, startTime, endTime );
                if ( startTime < ( System.currentTimeMillis () - metaData.getProposedDataAge () ) )
                {
                    logger.info ( message + " - backend is probably outdated", e );
                }
                else
                {
                    logger.error ( message, e );
                }
            }
        }

        // remove problematic backends
        removeBackEnds ( backEndsToRemove );

        // return final result
        return longValues.toArray ( EMPTY_LONGVALUE_ARRAY );
    }
}