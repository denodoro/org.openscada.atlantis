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

package org.openscada.da.server.simulation.scriptomatic;

import javax.script.ScriptException;

import org.openscada.core.Variant;
import org.openscada.da.core.OperationParameters;

public class ObjectHandler implements ScriptomaticHandler
{
    private final ScriptomaticContext context;

    private final Object object;

    public ObjectHandler ( final ScriptomaticContext context, final Object result )
    {
        this.context = context;
        this.object = result;
    }

    protected void eval ( final String methodName, final Object... args ) throws ScriptException, NoSuchMethodException
    {
        this.context.getInvocable ().invokeMethod ( this.object, methodName, args );
    }

    @Override
    public void cyclic () throws ScriptException, NoSuchMethodException
    {
        eval ( "cyclic" );
    }

    @Override
    public void start () throws ScriptException, NoSuchMethodException
    {
        eval ( "start" );
    }

    @Override
    public void stop () throws ScriptException, NoSuchMethodException
    {
        eval ( "stop" );
    }

    @Override
    public void trigger ( final Variant value, final OperationParameters operationParameters ) throws ScriptException, NoSuchMethodException
    {
        eval ( "trigger", value );
    }

}
