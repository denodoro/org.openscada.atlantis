package org.openscada.ae.pki.common.test.verifiy;

import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.net.base.data.Message;

public class VerifyTester {

	org.openscada.ae.pki.common.verifiy.Verifier verifierNgp = new org.openscada.ae.server.ngp.pki.pkcs12.verifiyprovider.VerifierImpl();
//	org.openscada.ae.pki.common.verifiy.Verifier verifierNet = new org.openscada.ae.server.net.pki.pkcs12.verifiyprovider.VerifierImpl();
	
	public void acknowledge(AcknowledgeRequest aknRequest){
		boolean verifiedRequest = verifierNgp.verifyRequest(aknRequest);
		
if(verifiedRequest){
	System.out.println("Der Request wurde verifiziert!");
}
else{
	System.out.println("Der Request wurde NICHT verifiziert!");
}

	}


//	public Message acknowledgeMessage(Message aknRequest){
//		Message signedRequest = signerNet.signAknRequest(aknRequest);
//		
//		return null;
//	}

}
