package org.openscada.ae.pki.common.testing;

import java.util.HashMap;

import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.ae.pki.common.test.sign.SignTester;
import org.openscada.ae.pki.common.test.verifiy.VerifyTester;
import org.openscada.core.data.Request;
import org.openscada.net.base.data.Message;
import org.openscada.net.base.data.StringValue;

public class TestPKI {

	
	public static void main(String[] args) {
		SignTester signTester = new SignTester();
		VerifyTester verifyTester = new VerifyTester();
		
		System.out.println("hallo");
		AcknowledgeRequest aknRequestNgp = getTestAknRequest();
		Message aknRequestNet = getTestAknMessage();
		System.out.println("Requests erstellt. Nun signieren.");
		System.out.println("-----------------sign NGP");
		AcknowledgeRequest signedAknRequestNgp = signTester.acknowledge(aknRequestNgp);
		System.out.println("-----------------sign NET");
		System.out.println(aknRequestNet.getClass());
		Message signedAknRequestNet = signTester.acknowledgeMessage(aknRequestNet);
		System.out.println("Requests signiert. Nun verifizieren.");
		System.out.println("-----------------verify NGP");
		verifyTester.acknowledge(signedAknRequestNgp);
		System.out.println("-----------------verify NET");
		verifyTester.acknowledge(signedAknRequestNet);
		System.out.println("Requests verifiziert.");
	}
	
	

	public static AcknowledgeRequest getTestAknRequest(){
		AcknowledgeRequest aknRequest = new AcknowledgeRequest(new Request(123), "monitorId1", new Long("201301132019"), new org.openscada.core.data.OperationParameters(null, new HashMap<String, String>()));
		return aknRequest;
	}
	
	public static Message getTestAknMessage(){
		Message aknMessage = new Message(Message.CC_ACK);
		aknMessage.setTimestamp(new Long("201301132019"));
		aknMessage.getValues().put("id", new StringValue("monitorId1"));
		return aknMessage;
	}
}
