package org.openscada.ae.pki.common.sign;

import java.security.PrivateKey;

import org.openscada.ae.pki.common.SignatureData;
import org.openscada.net.base.data.Message;

public interface Signer {
	/**
	 * Interface-Methode zum Signieren eines Requests
	 * SignatureData muss auf Client- wie Serverseite gleich sein, bzw erstellt werden koennen
	 * PrivateKey wird zum verschluesseln des Hashwertes der SignatureData gebraucht
	 * idToFindPubKeyOnOtherSide wird gebraucht, um den PublicKey auf der anderen Seite zum Entschluesseln des Hashwertes zu finden
	 * @return byte-Array, welches die Signatur darstellt
	 * */
//	public byte[] signRequest(SignatureData signData, PrivateKey privateKey, String idToFindPubKeyOnOtherSide);
	public Object signRequest(Object message);
}
