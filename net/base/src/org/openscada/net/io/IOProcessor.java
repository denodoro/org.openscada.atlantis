package org.openscada.net.io;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.openscada.utils.timing.AlreadyBoundException;
import org.openscada.utils.timing.NotBoundException;
import org.openscada.utils.timing.Scheduler;
import org.openscada.utils.timing.WrongThreadException;

public class IOProcessor implements Runnable {
    
    private static Logger _log = Logger.getLogger(IOProcessor.class);
	
	public Map<SelectionKey,IOChannel> _connections = new HashMap<SelectionKey,IOChannel>(); 
	
	public Selector _selector = null;
	public Thread _thread = null;
    public boolean _running = false;
    public Scheduler _scheduler = null;
	
	public IOProcessor () throws IOException
	{
        super();
        
        _scheduler = new Scheduler ( false );
        
		_selector = Selector.open();
	}
	
    /**
     * Starts the IO processor in a new thread if not already running.
     * 
     * @warning If the processor was started manually (using run) it will be started a second time
     *
     */
	public synchronized void start ()
	{
        if ( _running )
            return;
        
        _running = true;
        
		if ( _thread != null )
			return;
		
		_thread = new Thread(this);
		_thread.setDaemon(true);
		_thread.start ();
	}
	
	public void registerConnection ( IOChannel connection, int ops ) throws ClosedChannelException
	{
		SelectionKey key = connection.getSelectableChannel().keyFor( _selector );
		if ( key == null )
		{
            key = connection.getSelectableChannel().register ( _selector, ops );
            _connections.put ( key, connection );
		}
		else
		{
			key.interestOps(ops);
		}
		
		_selector.wakeup();
	}
	
	public void unregisterConnection ( IOChannel connection )
	{
		SelectionKey key = connection.getSelectableChannel().keyFor ( _selector );
		
		if ( key != null )
		{
			_connections.remove(key);
			key.cancel();
		}
	}

	public void run()
	{
        // Try to bind to the scheduler. If this fails there is somebody else
        // bound to it so we return
        try
        {
            _scheduler.bindToCurrentThread();
        }
        catch ( AlreadyBoundException e1 )
        {
            e1.printStackTrace();
            return;
        }
        
        _running = true;
		while ( _running )
		{
			try
            {
                int rc = 0;
                rc = _selector.select (100);
                
				if ( rc > 0 )
				{
					for ( SelectionKey key : _selector.selectedKeys() )
					{
                        IOChannelListener listener = _connections.get(key).getIOChannelListener();
						
						// check state and check if connection was closed during processing
						if ( key.isConnectable() )
							listener.handleConnect();
						if ( !key.isValid() )
							continue;
						
						// check state and check if connection was closed during processing
						if ( key.isAcceptable() )
							listener.handleAccept();
						if ( !key.isValid() )
							continue;
						
						// check state and check if connection was closed during processing
						if ( key.isReadable() )
							listener.handleRead();
						if ( !key.isValid() )
							continue;
						
						// check state and check if connection was closed during processing
						if ( key.isWritable() )
							listener.handleWrite();
						if ( !key.isValid() )
							continue;
					}
					
					// clear the selected list
					_selector.selectedKeys().clear();
				}
                
                _scheduler.runOnce ();
                
			} catch (IOException e) {
				e.printStackTrace();
			}
            catch ( NotBoundException e )
            {
                e.printStackTrace();
                _running = false;
            }
            catch ( WrongThreadException e )
            {
                e.printStackTrace();
                _running = false;
            }
		}
	}

	public Selector getSelector() {
		return _selector;
	}

    public Scheduler getScheduler ()
    {
        return _scheduler;
    }
	
	
}
