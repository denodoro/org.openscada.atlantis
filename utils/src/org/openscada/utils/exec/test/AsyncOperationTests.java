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

package org.openscada.utils.exec.test;

import junit.framework.TestCase;

import org.openscada.utils.exec.AsyncBasedOperation;
import org.openscada.utils.exec.Operation;
import org.openscada.utils.exec.OperationResult;

public class AsyncOperationTests extends TestCase
{
    
    Operation<String,String> _opAsyncSuccess = null;
    
    @Override
    protected void setUp () throws Exception
    {
        _opAsyncSuccess = new AsyncBasedOperation<String,String>(){

            @Override
            protected void startExecute ( final OperationResult<String> or, final String arg0 )
            {
               new Thread( new Runnable () {

                public void run ()
                {
                    try
                    {
                        Thread.sleep(1000);
                        System.out.println ( "Say hello: " + arg0 );
                        Thread.sleep(1000);
                        
                        or.notifySuccess ( "Hello to: " + arg0 );
                    }
                    catch ( Exception e )
                    {
                        or.notifyFailure(e);
                    }
                }} ).start();
            }

           
        };
        
        super.setUp ();
    }
    
    public void testSync () throws Exception
    {
        assertEquals ( _opAsyncSuccess.execute("Alice"), "Hello to: Alice" );
    }
    
    public void testAsync () throws Exception
    {
        OperationResult<String> or = _opAsyncSuccess.startExecute("Bob");
        System.out.println("Started execution");
        
        or.complete();
        
        assertTrue ( or.isComplete() );
        assertTrue ( or.isSuccess() );
    }
    
    public void testAsyncHandler () throws Exception
    {
        TestOperationHandler<String> handler = new TestOperationHandler<String>();
        
        OperationResult<String> or = _opAsyncSuccess.startExecute(handler, "Bob");
        System.out.println("Started execution");
        
        or.complete();
        
        assertTrue ( or.isComplete() );
        assertTrue ( or.isSuccess() );
        
        assertTrue ( handler.isSuccess() );
        assertFalse ( handler.isFailure() );
        
        assertNull ( handler.getException() );
        assertEquals ( handler.getResult(), "Hello to: Bob" );
    }
}
