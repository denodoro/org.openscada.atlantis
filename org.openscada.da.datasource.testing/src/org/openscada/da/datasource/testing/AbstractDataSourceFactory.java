package org.openscada.da.datasource.testing;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

import org.openscada.ca.ConfigurationFactory;
import org.openscada.da.datasource.DataSource;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

public abstract class AbstractDataSourceFactory implements ConfigurationFactory
{

    private final ScheduledExecutorService scheduler;

    private final BundleContext context;

    public AbstractDataSourceFactory ( final BundleContext context, final ScheduledExecutorService scheduler )
    {
        this.context = context;
        this.scheduler = scheduler;
    }

    public ScheduledExecutorService getScheduler ()
    {
        return this.scheduler;
    }

    private final Map<String, DefaultDataSource> dataSources = new HashMap<String, DefaultDataSource> ();

    private final Map<String, ServiceRegistration> regs = new HashMap<String, ServiceRegistration> ();

    public synchronized void delete ( final String configurationId ) throws Exception
    {
        final ServiceRegistration reg = this.regs.remove ( configurationId );
        reg.unregister ();

        final DefaultDataSource source = this.dataSources.remove ( configurationId );
        source.dispose ();
    }

    public synchronized void update ( final String configurationId, final Map<String, String> properties ) throws Exception
    {
        DefaultDataSource source = this.dataSources.get ( configurationId );
        if ( source == null )
        {
            source = createDataSource ();
            this.dataSources.put ( configurationId, source );
            final Dictionary<String, String> props = new Hashtable<String, String> ();
            props.put ( DataSource.DATA_SOURCE_ID, configurationId );

            this.regs.put ( configurationId, this.context.registerService ( DataSource.class.getName (), source, props ) );
        }
        source.update ( properties );
    }

    protected abstract DefaultDataSource createDataSource ();

    public synchronized void dispose ()
    {
        for ( final ServiceRegistration reg : this.regs.values () )
        {
            reg.unregister ();
        }
        this.regs.clear ();

        for ( final DefaultDataSource source : this.dataSources.values () )
        {
            source.dispose ();
        }
        this.dataSources.clear ();
    }
}
