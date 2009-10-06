package org.openscada.hd.server.storage.backend;

import java.io.File;
import java.io.FileFilter;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.openscada.hd.server.storage.StorageChannelMetaData;
import org.openscada.hd.server.storage.calculation.CalculationMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides an implementation of the BackEndFactory for storage channel backend objects of type FileBackEnd.
 * @author Ludwig Straub
 */
public class FileBackEndFactory implements BackEndFactory
{
    /**
     * This file filter searches for sub directories with the specified name.
     * @author Ludwig Straub
     */
    private static class DirectoryFileFilter implements FileFilter
    {
        /** Case insensitive name of the sub directories that have to be searched. If null is set then all directories are accepted. */
        private final String name;

        /**
         * Constructor
         * @param name case insensitive name of the sub directories that have to be searched. If null is passed then all directories are accepted
         */
        public DirectoryFileFilter ( final String name )
        {
            this.name = name;
        }

        /**
         * @see java.io.FileFilter#accept
         */
        public boolean accept ( final File file )
        {
            return file.isDirectory () && ( ( name == null ) || file.getName ().equalsIgnoreCase ( name ) );
        }
    }

    /**
     * This file filter searches for files matching files with the specified name.
     * @author Ludwig Straub
     */
    private static class FileFileFilter implements FileFilter
    {
        /** Case insensitive name of the files that have to be searched. If null is set then all files are accepted. */
        private final String fileNamePattern;

        /**
         * Constructor
         * @param fileNamePattern case pattern of file names that have to be searched. If null is passed then all files are accepted
         */
        public FileFileFilter ( final String fileNamePattern )
        {
            this.fileNamePattern = fileNamePattern;
        }

        /**
         * @see java.io.FileFilter#accept
         */
        public boolean accept ( final File file )
        {
            return file.isFile () && file.getName ().matches ( fileNamePattern );
        }
    }

    /** The default logger. */
    private final static Logger logger = LoggerFactory.getLogger ( FileBackEndFactory.class );

    /** Text that is used to split the different parts of the generated file names. */
    private final static String FILENAME_PART_SEPERATOR = "_";

    /** File mask that is used when no other file mask is passed. Sample file: MyDataSource-AVG-1-1000000-1100000.wa (dataItemId-calculationMethod-level-startTime-endTime) */
    public final static String FILE_MASK = "%1$s" + FILENAME_PART_SEPERATOR + "%3$s" + FILENAME_PART_SEPERATOR + "%2$s" + FILENAME_PART_SEPERATOR + "%4$s" + FILENAME_PART_SEPERATOR + "%5$s.va";

    /** Regular expression for data item id fragments. */
    private final static String DATA_ITEM_ID_REGEX_PATTERN = ".*";

    /** Regular expression for detail level id fragments. */
    private final static String DETAIL_LEVEL_ID_REGEX_PATTERN = "[0-9]+";

    /** Regular expression for calculation method information fragments. */
    private final static String CALCULATION_METHOD_REGEX_PATTERN = ".*";

    /** Regular expression for start time fragments. */
    private final static String START_TIME_REGEX_PATTERN = "[0-9]+";

    /** Regular expression for end time fragments. */
    private final static String END_TIME_REGEX_PATTERN = "[0-9]+";

    /** Prepared empty backend array. */
    private final static BackEnd[] EMTPY_BACKEND_ARRAY = new BackEnd[0];

    /** Prepared empty metadata array. */
    private final static StorageChannelMetaData[] emptyMetaDataArray = new StorageChannelMetaData[0];

    /** Root folder within the storage files are located and new ones have to be created. */
    private final String fileRoot;

    /** Precompiled regular expression pattern for extracting the data item id from a filename. */
    private final Pattern dataItemIdPattern;

    /** Precompiled regular expression pattern for extracting the calculation method information from a filename. */
    private final Pattern calculationMethodPattern;

    /** Precompiled regular expression pattern for extracting the detail level id from a filename. */
    private final Pattern detailLevelIdPattern;

    /**
     * Constructor
     * @param fileRoot root folder within the storage files are located and new ones have to be created
     */
    public FileBackEndFactory ( final String fileRoot )
    {
        this.fileRoot = fileRoot;
        this.dataItemIdPattern = Pattern.compile ( String.format ( FILE_MASK, "(" + DATA_ITEM_ID_REGEX_PATTERN + ")", CALCULATION_METHOD_REGEX_PATTERN, DETAIL_LEVEL_ID_REGEX_PATTERN, START_TIME_REGEX_PATTERN, END_TIME_REGEX_PATTERN ), Pattern.CASE_INSENSITIVE );
        this.calculationMethodPattern = Pattern.compile ( String.format ( FILE_MASK, DATA_ITEM_ID_REGEX_PATTERN, "(" + CALCULATION_METHOD_REGEX_PATTERN + ")", DETAIL_LEVEL_ID_REGEX_PATTERN, START_TIME_REGEX_PATTERN, END_TIME_REGEX_PATTERN ), Pattern.CASE_INSENSITIVE );
        this.detailLevelIdPattern = Pattern.compile ( String.format ( FILE_MASK, DATA_ITEM_ID_REGEX_PATTERN, CALCULATION_METHOD_REGEX_PATTERN, "(" + DETAIL_LEVEL_ID_REGEX_PATTERN + ")", START_TIME_REGEX_PATTERN, END_TIME_REGEX_PATTERN ), Pattern.CASE_INSENSITIVE );
    }

    /**
     * This method converts the passed text to a valid part of a file name.
     * @param rawFileNamePart text to be converted
     * @return converted text
     */
    private static String encodeFileNamePart ( final String rawFileNamePart )
    {
        if ( rawFileNamePart == null )
        {
            return "";
        }
        try
        {
            return URLEncoder.encode ( rawFileNamePart, "utf-8" ).replaceAll ( FILENAME_PART_SEPERATOR, " " );
        }
        catch ( final Exception e )
        {
            return rawFileNamePart;
        }
    }

    /**
     * This method extracts data from the file name and returns the result.
     * If the desired information could not be extracted, then the default value will be returned instead.
     * @param pattern pattern that will be used to extract data from the filename
     * @param fileName filename from which data should be extracted
     * @param defaultValue default value that will be returned, if the desired information cannot be extracted from the filename
     * @return information extracted from the filename or default value if no information could be extracted
     */
    private static String extractDataFromFileName ( final Pattern pattern, final String fileName, final String defaultValue )
    {
        // check input
        if ( ( pattern == null ) || ( fileName == null ) )
        {
            return defaultValue;
        }

        // parse filename
        final Matcher matcher = pattern.matcher ( fileName );
        if ( matcher.groupCount () != 1 )
        {
            return defaultValue;
        }
        String result = matcher.group ( 1 );
        return result != null ? result : defaultValue;
    }

    /**
     * This method extracts data from the file name and returns the result.
     * If the desired information could not be extracted, then the default value will be returned instead.
     * @param pattern pattern that will be used to extract data from the filename
     * @param fileName filename from which data should be extracted
     * @param defaultValue default value that will be returned, if the desired information cannot be extracted from the filename
     * @return information extracted from the filename or default value if no information could be extracted
     */
    private static long extractDataFromFileName ( final Pattern pattern, final String fileName, final long defaultValue )
    {
        return Long.parseLong ( extractDataFromFileName ( pattern, fileName, "" + defaultValue ) );
    }

    /**
     * This method creates and initializes a back end object for the passed file object.
     * If the object is not used internally within this class, then the object should be deinitialized before passing the argument outside this class.
     * @param file file that is used to create a back end object
     * @return initialized back end object
     */
    private BackEnd getBackEnd ( final File file )
    {
        FileBackEnd fileBackEnd = null;
        try
        {
            fileBackEnd = new FileBackEnd ( file.getPath () );
            fileBackEnd.initialize ( null );
            final StorageChannelMetaData metaData = fileBackEnd.getMetaData ();
            final String fileName = file.getName ();
            final String dataItemId = encodeFileNamePart ( metaData.getDataItemId () );
            final String calculationMethod = CalculationMethod.convertCalculationMethodToShortString ( metaData.getCalculationMethod () );
            final long detailLevelId = metaData.getDetailLevelId ();
            if ( ( dataItemId == null ) || !extractDataFromFileName ( dataItemIdPattern, fileName, dataItemId ).equals ( dataItemId ) || ( extractDataFromFileName ( calculationMethodPattern, fileName, calculationMethod ) != calculationMethod ) || ( extractDataFromFileName ( detailLevelIdPattern, fileName, detailLevelId ) != detailLevelId ) )
            {
                fileBackEnd = null;
                logger.warn ( String.format ( "file content does not match expected content due to file name (%s). file will be ignored", file.getPath () ) );
            }
        }
        catch ( Exception e )
        {
            fileBackEnd = null;
            logger.warn ( String.format ( "file '%s' could not be evaluated and will be ignored", file.getPath () ), e );
        }
        return fileBackEnd;
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEndFactory#getExistingBackEndsMetaData
     */
    public StorageChannelMetaData[] getExistingBackEndsMetaData () throws Exception
    {
        // check if root folder exists
        File root = new File ( fileRoot );
        if ( !root.exists () || !root.isDirectory () )
        {
            return emptyMetaDataArray;
        }

        // get all directories
        File[] directories = root.listFiles ( new DirectoryFileFilter ( null ) );
        List<StorageChannelMetaData> metaDatas = new LinkedList<StorageChannelMetaData> ();
        for ( File dataItemDirectory : directories )
        {
            for ( File file : dataItemDirectory.listFiles ( new FileFileFilter ( String.format ( FILE_MASK, dataItemDirectory.getName (), ".*", ".*", ".*", ".*" ) ) ) )
            {
                final BackEnd backEnd = getBackEnd ( file );
                if ( backEnd != null )
                {
                    try
                    {
                        StorageChannelMetaData metaData = backEnd.getMetaData ();
                        if ( metaData != null )
                        {
                            boolean addNew = true;
                            for ( StorageChannelMetaData entry : metaDatas )
                            {
                                String storedDataItemId = entry.getDataItemId ();
                                if ( ( storedDataItemId != null ) && !storedDataItemId.equals ( metaData.getDataItemId () ) )
                                {
                                    // since the list is ordered by directory and therefore by data item id, it can be assumed that no more suitable entry exists in the list
                                    break;
                                }
                                if ( ( entry.getDetailLevelId () == metaData.getDetailLevelId () ) && ( entry.getCalculationMethod () == metaData.getCalculationMethod () ) )
                                {
                                    // adapt the current entry in the list and expand the time span
                                    entry.setStartTime ( Math.min ( entry.getStartTime (), metaData.getStartTime () ) );
                                    entry.setEndTime ( Math.max ( entry.getEndTime (), metaData.getEndTime () ) );
                                    addNew = false;
                                    break;
                                }
                            }
                            if ( addNew )
                            {
                                metaDatas.add ( 0, new StorageChannelMetaData ( metaData ) );
                            }
                        }
                        backEnd.deinitialize ();
                    }
                    catch ( Exception e )
                    {
                        logger.warn ( String.format ( "metadata of file '%s' could not be retrieved. file will be ignored", file.getPath () ), e );
                    }
                }
            }
        }
        return metaDatas.toArray ( emptyMetaDataArray );
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEndFactory#getExistingBackEnds
     */
    public BackEnd[] getExistingBackEnds ( final String dataItemId, final long detailLevelId, final CalculationMethod calculationMethod ) throws Exception
    {
        // check input
        if ( dataItemId == null )
        {
            return EMTPY_BACKEND_ARRAY;
        }

        // check if root folder exists
        File root = new File ( fileRoot );
        if ( !root.exists () || !root.isDirectory () )
        {
            return EMTPY_BACKEND_ARRAY;
        }

        // get all directories within the root folder
        final String dataItemIdFileName = encodeFileNamePart ( dataItemId );
        File[] directories = root.listFiles ( new DirectoryFileFilter ( dataItemIdFileName ) );

        // check if sub directory exists
        if ( directories.length == 0 )
        {
            return EMTPY_BACKEND_ARRAY;
        }

        // evaluate the data item directory
        final List<BackEnd> backEnds = new ArrayList<BackEnd> ();
        for ( File file : directories[0].listFiles ( new FileFileFilter ( String.format ( FILE_MASK, dataItemIdFileName, CalculationMethod.convertCalculationMethodToShortString ( calculationMethod ), detailLevelId, ".*", ".*" ) ) ) )
        {
            final BackEnd backEnd = getBackEnd ( file );
            if ( backEnd != null )
            {
                backEnd.deinitialize ();
                backEnds.add ( backEnd );
            }
        }
        return backEnds.toArray ( EMTPY_BACKEND_ARRAY );
    }

    /**
     * @see org.openscada.hd.server.storage.backend.BackEndFactory#createNewBackEnd
     */
    public BackEnd createNewBackEnd ( final StorageChannelMetaData storageChannelMetaData ) throws Exception
    {
        // check input
        if ( storageChannelMetaData == null )
        {
            String message = "invalid StorageChannelMetaData object passed to FileBackEndFactory!";
            logger.error ( message );
            throw new Exception ( message );
        }
        final String dataItemId = encodeFileNamePart ( storageChannelMetaData.getDataItemId () );
        if ( dataItemId == null )
        {
            String message = "invalid dataItemId specified as metadata for FileBackEndFactory!";
            logger.error ( message );
            throw new Exception ( message );
        }

        // assure that root folder exists
        return new FileBackEnd ( new File ( new File ( fileRoot, dataItemId ), String.format ( FILE_MASK, dataItemId, CalculationMethod.convertCalculationMethodToShortString ( storageChannelMetaData.getCalculationMethod () ), storageChannelMetaData.getDetailLevelId (), storageChannelMetaData.getStartTime (), storageChannelMetaData.getEndTime () ) ).getPath () );
    }
}