/*
 * This file is part of the OpenSCADA project
 * Copyright (C) 2006 inavare GmbH (http://inavare.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package org.openscada.rcp.client;

import org.eclipse.jface.action.ActionContributionItem;
import org.eclipse.jface.action.GroupMarker;
import org.eclipse.jface.action.IContributionItem;
import org.eclipse.jface.action.ICoolBarManager;
import org.eclipse.jface.action.IMenuManager;
import org.eclipse.jface.action.IToolBarManager;
import org.eclipse.jface.action.MenuManager;
import org.eclipse.jface.action.Separator;
import org.eclipse.jface.action.ToolBarContributionItem;
import org.eclipse.jface.action.ToolBarManager;
import org.eclipse.swt.SWT;
import org.eclipse.ui.IWorkbenchActionConstants;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.actions.ActionFactory;
import org.eclipse.ui.actions.ActionGroup;
import org.eclipse.ui.actions.ContributionItemFactory;
import org.eclipse.ui.actions.ActionFactory.IWorkbenchAction;
import org.eclipse.ui.application.ActionBarAdvisor;
import org.eclipse.ui.application.IActionBarConfigurer;

public class ApplicationActionBarAdvisor extends ActionBarAdvisor {

//  Actions - important to allocate these only in makeActions, and then use them
    // in the fill methods.  This ensures that the actions aren't recreated
    // when fillActionBars is called with FILL_PROXY.
    private IWorkbenchAction exitAction;
    private IWorkbenchAction aboutAction;
    private IWorkbenchAction newWindowAction;
    
    private IContributionItem _showViews = null;
    private IContributionItem _newWizards = null;

    public ApplicationActionBarAdvisor(IActionBarConfigurer configurer)
    {
        super ( configurer );
    }
    
    @Override
    protected void makeActions ( final IWorkbenchWindow window )
    {
        // Creates the actions and registers them.
        // Registering is needed to ensure that key bindings work.
        // The corresponding commands keybindings are defined in the plugin.xml file.
        // Registering also provides automatic disposal of the actions when
        // the window is closed.

        exitAction = ActionFactory.QUIT.create(window);
        register(exitAction);
        
        aboutAction = ActionFactory.ABOUT.create(window);
        register(aboutAction);
        
        newWindowAction = ActionFactory.OPEN_NEW_WINDOW.create ( window );
        register(newWindowAction);
        
        register ( ActionFactory.NEW_WIZARD_DROP_DOWN.create ( window ) );        
        register ( ActionFactory.NEW.create ( window ) );
        register ( ActionFactory.INTRO.create ( window ) );
        
        _showViews = ContributionItemFactory.VIEWS_SHORTLIST.create ( window );
        _newWizards = ContributionItemFactory.NEW_WIZARD_SHORTLIST.create ( window );
    }
    
    @Override
    protected void fillMenuBar ( IMenuManager menuBar )
    {
        MenuManager fileMenu = new MenuManager("&File", IWorkbenchActionConstants.M_FILE);
        MenuManager windowMenu = new MenuManager("&Window", IWorkbenchActionConstants.M_WINDOW);
        MenuManager helpMenu = new MenuManager("&Help", IWorkbenchActionConstants.M_HELP);
        MenuManager fileNewMenu = new MenuManager ( "&New", IWorkbenchActionConstants.NEW_EXT );
        
        menuBar.add(fileMenu);
        menuBar.add(windowMenu);
        // Add a group marker indicating where action set menus will appear.
        menuBar.add(new GroupMarker(IWorkbenchActionConstants.MB_ADDITIONS));
        menuBar.add(helpMenu);
        
        // File
        fileMenu.add ( newWindowAction );
        fileMenu.add ( new Separator () );
        fileMenu.add ( fileNewMenu );
        
        fileMenu.add ( new Separator () );
        fileMenu.add ( exitAction );
        
        fileNewMenu.add ( _newWizards );
        
        // Window
        windowMenu.add ( _showViews );
        
        // Help
        helpMenu.add ( aboutAction );
        helpMenu.add ( getAction ( ActionFactory.INTRO.getId () ) );
    }
    
    @Override
    protected void fillCoolBar(ICoolBarManager coolBar) {
        IToolBarManager toolbar = new ToolBarManager(SWT.FLAT | SWT.RIGHT);
        coolBar.add(new ToolBarContributionItem(toolbar, "main"));
        toolbar.add(getAction(ActionFactory.NEW_WIZARD_DROP_DOWN.getId()));
    }
    
}
