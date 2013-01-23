package org.openscada.ae.client.net.pki.pkcs12.signprovider;


import java.security.PrivateKey;
import org.openscada.net.base.data.Message;

public interface Signer extends org.openscada.ae.pki.common.sign.Signer{
	/**
	 * Interface-Methode zum Signieren einer Message
	 * Da auch die Methode signRequest vom org.openscada.ae.pki.common.sign.Signer geerbt wird
	 * und in der Implementierung des Interfaces vorhanden ist,
	 * sollte die signRequest-Methode aus dem Signer innerhalb dieser Methode aufgerufen werden mit
	 * signRequest(new SignatureData(requestToBeSigned))
	 * */
//	public Message signAknRequest(Message requestToBeSigned);
}
