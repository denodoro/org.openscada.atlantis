package org.openscada.ae;

import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Map.Entry;

import org.openscada.core.Variant;
import org.openscada.utils.lang.Immutable;

@Immutable
public class Event implements Cloneable, Comparable<Event>
{
    public static class EventComparator implements Comparator<Event>
    {
        public int compare ( final Event o1, final Event o2 )
        {
            final int s = o1.getSourceTimestamp ().compareTo ( o2.getSourceTimestamp () );
            if ( s == 0 )
            {
                final int e = o1.getEntryTimestamp ().compareTo ( o2.getEntryTimestamp () );
                if ( e == 0 )
                {
                    return o1.getId ().compareTo ( o2.getId () );
                }
                return e;
            }
            return s;
        }
    }

    public static class EventBuilder
    {
        private final Event event = new Event ();

        private EventBuilder ()
        {
        }

        public EventBuilder event ( final Event event )
        {
            this.event.id = event.getId ();
            this.event.sourceTimestamp = event.getSourceTimestamp ();
            this.event.entryTimestamp = event.getEntryTimestamp ();
            this.event.attributes.putAll ( event.getAttributes () );
            return this;
        }

        public EventBuilder id ( final UUID id )
        {
            this.event.id = id;
            return this;
        }

        public EventBuilder sourceTimestamp ( final Date sourceTimestamp )
        {
            this.event.sourceTimestamp = sourceTimestamp;
            return this;
        }

        public EventBuilder entryTimestamp ( final Date entryTimestamp )
        {
            this.event.entryTimestamp = entryTimestamp;
            return this;
        }

        public EventBuilder attributes ( final Map<String, Variant> attributes )
        {
            this.event.attributes.putAll ( attributes );
            return this;
        }

        public EventBuilder attribute ( final String key, final Variant value )
        {
            this.event.attributes.put ( key, value );
            return this;
        }

        public EventBuilder attribute ( final String key, final Object value )
        {
            this.event.attributes.put ( key, new Variant ( value ) );
            return this;
        }

        public Event build ()
        {
            return new Event ( this.event );
        }
    }

    public enum Fields
    {
        TYPE ( "type", String.class ),
        SOURCE ( "source", String.class ),
        PRIORITY ( "priority", Integer.class );

        private final Class<? extends Object> clazz;

        private final String name;

        Fields ( final String name, final Class<? extends Object> clazz )
        {
            this.name = name;
            this.clazz = clazz;
        }

        public Class<? extends Object> getType ()
        {
            return this.clazz;
        }

        public String getName ()
        {
            return this.name;
        }

        public boolean contains ( final String name )
        {
            return byField ( name ) == null ? false : true;
        }

        public Fields byField ( final String name )
        {
            for ( final Fields field : values () )
            {
                if ( field.getName ().equals ( name ) )
                {
                    return field;
                }
            }
            return null;
        }
    }

    public static final EventComparator comparator = new EventComparator ();

    private UUID id;

    private Date sourceTimestamp;

    private Date entryTimestamp;

    private final Map<String, Variant> attributes = new HashMap<String, Variant> ();

    private Event ( final Event event )
    {
        this.id = event.getId ();
        this.sourceTimestamp = event.getSourceTimestamp ();
        this.entryTimestamp = event.getEntryTimestamp ();
        this.attributes.putAll ( event.getAttributes () );
    }

    private Event ()
    {
    }

    public UUID getId ()
    {
        return this.id;
    }

    public Date getSourceTimestamp ()
    {
        return this.sourceTimestamp;
    }

    public Date getEntryTimestamp ()
    {
        return this.entryTimestamp;
    }

    public Map<String, Variant> getAttributes ()
    {
        return Collections.unmodifiableMap ( this.attributes );
    }

    @Override
    public int hashCode ()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( this.id == null ? 0 : this.id.hashCode () );
        return result;
    }

    @Override
    public boolean equals ( final Object obj )
    {
        if ( this == obj )
        {
            return true;
        }
        if ( obj == null )
        {
            return false;
        }
        if ( getClass () != obj.getClass () )
        {
            return false;
        }
        final Event other = (Event)obj;
        if ( this.id == null )
        {
            if ( other.id != null )
            {
                return false;
            }
        }
        else if ( !this.id.equals ( other.id ) )
        {
            return false;
        }
        return true;
    }

    public static EventBuilder create ()
    {
        return new EventBuilder ();
    }

    public Event clone ()
    {
        return new Event ( this );
    }

    @Override
    public String toString ()
    {
        final StringBuilder sb = new StringBuilder ();
        sb.append ( "Event {" );
        sb.append ( "id: " );
        sb.append ( this.id == null ? null : this.id.toString () );
        sb.append ( ", sourceTimestamp: " );
        sb.append ( this.sourceTimestamp == null ? null : this.sourceTimestamp.toString () );
        sb.append ( ", entryTimestamp: " );
        sb.append ( this.entryTimestamp == null ? null : this.entryTimestamp.toString () );
        for ( final Entry<String, Variant> entry : this.attributes.entrySet () )
        {
            sb.append ( ", " + entry.getKey () );
            sb.append ( ": " );
            sb.append ( entry.getValue () == null ? null : entry.getValue () );
        }
        sb.append ( "}" );
        return sb.toString ();
    }

    public int compareTo ( final Event o )
    {
        return comparator.compare ( this, o );
    }
}
