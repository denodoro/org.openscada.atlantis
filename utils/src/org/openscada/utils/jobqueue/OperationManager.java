/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006 inavare GmbH (http://inavare.com)
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

package org.openscada.utils.jobqueue;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class OperationManager
{
    public class Handle
    {
        private Operation _operation = null;
        private OperationManager _manager = null;
        private Long _id = null;
        
        private boolean _started = false;
        private boolean _canceled = false;
        
        public Handle ( Operation operation, OperationManager manager, Long id )
        {
            _operation = operation;
            _manager = manager;
            _id = id;
        }
        
        synchronized public void cancel () throws CancelNotSupportedException
        {
            if ( _started )
            {
                _operation.cancel ();
                _canceled = true;
                remove ();
            }
        }
        
        synchronized public void start ()
        {
            if ( (!_started) && (!_canceled) )
            {
                _operation.start ( this );
                _started = true;
            }
        }
        
        synchronized public void completed ()
        {
            remove ();
        }
       
        private void remove ()
        {
            _manager.remove ( this );
            notifyAll ();
        }

        public Long getId ()
        {
            return _id;
        }
    }
    
    private Map<Long, Handle> _operationMap = new HashMap<Long, Handle> ();
    
    public Handle schedule ( Operation operation )
    {
        synchronized ( this )
        {
            Random r = new Random ();
            Long id;
            do
            {
                id = r.nextLong ();
            } while ( _operationMap.containsKey ( id ) );
            
            Handle handle = new Handle ( operation, this, id );
            _operationMap.put ( id, handle );
            return handle;
        }
    }
    
    public void remove ( Handle handle )
    {
        synchronized ( this )
        {
            _operationMap.remove ( handle.getId () );
        }
    }
    
    public Handle get ( long id )
    {
        synchronized ( this )
        {
            return _operationMap.get ( id );
        }
    }

}
