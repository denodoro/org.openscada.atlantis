package org.openscada.ae.pki.common.test.sign;


import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.net.base.data.Message;

public class SignTester {


	org.openscada.ae.pki.common.sign.Signer signerNgp = new org.openscada.ae.client.ngp.pki.pkcs12.signprovider.SignerImpl();
	org.openscada.ae.pki.common.sign.Signer signerNet = new org.openscada.ae.client.net.pki.pkcs12.signprovider.SignerImpl();
	
public AcknowledgeRequest acknowledge(AcknowledgeRequest aknRequest){
	AcknowledgeRequest signedRequest = (AcknowledgeRequest)signerNgp.signRequest(aknRequest);
	
	
	return signedRequest;
}


public Message acknowledgeMessage(Message aknRequest){
	Message signedRequest = (Message)signerNet.signRequest(aknRequest);
	
	return null;
}

}
