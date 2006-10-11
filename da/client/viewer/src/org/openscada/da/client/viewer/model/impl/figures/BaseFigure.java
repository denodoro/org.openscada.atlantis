package org.openscada.da.client.viewer.model.impl.figures;

import org.eclipse.draw2d.IFigure;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.widgets.Display;
import org.openscada.da.client.viewer.model.DynamicUIObject;
import org.openscada.da.client.viewer.model.impl.AliasedPropertyInput;
import org.openscada.da.client.viewer.model.impl.BaseDynamicObject;
import org.openscada.da.client.viewer.model.impl.Helper;
import org.openscada.da.client.viewer.model.impl.PropertyInput;

public abstract class BaseFigure extends BaseDynamicObject implements DynamicUIObject
{
    private Color _color = null;
    private org.eclipse.draw2d.geometry.Rectangle _bounds = new org.eclipse.draw2d.geometry.Rectangle ( 0, 0, 0, 0 );

    public BaseFigure ( String id )
    {
        super ( id );
        addInput ( new PropertyInput ( this, "color" ) );
        addInput ( new AliasedPropertyInput ( this, "width", "width" ) );
        addInput ( new AliasedPropertyInput ( this, "height", "height" ) );
        addInput ( new AliasedPropertyInput ( this, "x", "x" ) );
        addInput ( new AliasedPropertyInput ( this, "y", "y" ) );
    }
    
    public void setHeight ( Long height )
    {
        if ( height != null )
            _bounds.height = height.intValue ();
        update ();
    }
    
    public void setWidth ( Long width )
    {
        if ( width != null )
            _bounds.width = width.intValue ();
        update ();
    }
    
    public void setX ( Long x )
    {
        if ( x != null )
            _bounds.x = x.intValue ();
        update ();
    }

    public void setY ( Long y )
    {
        if ( y != null )
            _bounds.y = y.intValue ();
        update ();
    }

    public org.openscada.da.client.viewer.model.types.Color getColor ()
    {
        return Helper.colorFromRGB ( _color.getRGB () );
    }

    public void setColor ( org.openscada.da.client.viewer.model.types.Color color )
    {
        _color = new Color ( Display.getCurrent (), Helper.colorToRGB ( color ) );
        update ();
    }

    public org.eclipse.draw2d.geometry.Rectangle getBounds ()
    {
        return _bounds;
    }

    public void setBounds ( org.eclipse.draw2d.geometry.Rectangle bounds )
    {
        _bounds = bounds;
    }
    
    protected void updateFigure ( IFigure figure )
    {
        if ( figure == null )
            return;
        
        figure.setBounds ( _bounds );
        
        if ( _color != null )
        {
            figure.setBackgroundColor ( _color );
        }
    }
    
    protected abstract void update ();
}
