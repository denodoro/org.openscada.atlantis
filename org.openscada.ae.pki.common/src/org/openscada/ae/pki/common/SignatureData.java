package org.openscada.ae.pki.common;

import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.net.base.data.Message;

/**
 * Data structure for signing
 * */
public class SignatureData {

	
	private final String messageDataString;
	private final Long timestamp;
	
	public SignatureData(AcknowledgeRequest aknRequest){
		/**
		 * Es wird nicht direkt die toString()-Methode benutzt, da der Server, bzw Verifizierer die gleichen
		 * Daten hashen muss und nicht die Signatur mit dabei sein darf.
		 * */
		this.messageDataString = "[AcknowledgeRequest - " + 
		"request: " + aknRequest.getRequest() +	"monitorId: " + aknRequest.getMonitorId() +	"aknTimestamp: " + aknRequest.getAknTimestamp();	
		this.timestamp = aknRequest.getAknTimestamp();
	}
	
	public SignatureData(Message message){
		this.messageDataString = String.format ( "[Message - cc: %s, seq: %s]", message.getCommandCode(), message.getSequence() );
		this.timestamp = message.getTimestamp();
	}

	@Override
	public String toString() {
		return "messageDataString: " + messageDataString + " - timestamp: " + String.valueOf(this.timestamp);
	}
	
	
	
	
	
}
