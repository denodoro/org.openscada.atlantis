package org.openscada.ae.pki.common;

import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.net.base.data.Message;

public class TransactionRequest {

	private final Object request;
	private final long timestamp;
	
	public TransactionRequest(AcknowledgeRequest aknRequest){
		this.request = aknRequest;
		this.timestamp = aknRequest.getAknTimestamp();
	}
	
	public TransactionRequest(Message transactionRequest){
		this.request = transactionRequest;
		this.timestamp = transactionRequest.getTimestamp();
	}

	public Object getRequest() {
		return request;
	}

	public long getTimestamp() {
		return timestamp;
	}
	
}
