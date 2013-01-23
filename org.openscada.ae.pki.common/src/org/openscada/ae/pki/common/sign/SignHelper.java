package org.openscada.ae.pki.common.sign;

import java.security.KeyStore;
import java.security.PrivateKey;

public interface SignHelper {

	/**
	 * Der PrivateKey, dh die Referenz auf den Privaten Key kann zB entweder aus einer PKCS12-Datei oder ueber
	 * die PKCS11-API geholt werden.
	 * */
	public PrivateKey getPrivateKeyForSigning();
	
	/**
	 * Im Client und auf dem Server muss Einigkeit herrschen, mit welchem String der Empfaenger den
	 * Public Key zB aus der DB holen kann und wo der Sender diesen String zB aus der PKCS12-Datei oder ueber 
	 * die PKCS11-API finden kann
	 * */
	public String getIdentifierStringForCertificate();
	
}
