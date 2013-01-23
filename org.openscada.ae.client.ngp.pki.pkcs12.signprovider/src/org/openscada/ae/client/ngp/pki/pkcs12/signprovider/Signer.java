package org.openscada.ae.client.ngp.pki.pkcs12.signprovider;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.core.data.Request;

public interface Signer extends org.openscada.ae.pki.common.sign.Signer{
	/**
	 * Interface-Methode zum Signieren eines AcknowledgeRequests
	 * Da auch die Methode signRequest vom org.openscada.ae.pki.common.sign.Signer geerbt wird
	 * und in der Implementierung des Interfaces vorhanden ist,
	 * sollte diese Methode innerhalb dieser Methode aufgerufen werden mit
	 * signRequest(new SignatureData(requestToBeSigned, privateKey, idToFindPubKeyOnOtherSide))
	 * */
//	public AcknowledgeRequest signAknRequest(AcknowledgeRequest requestToBeSigned);
}
