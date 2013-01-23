package org.openscada.ae.pki.common.verifiy;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.openscada.ae.pki.common.SignatureData;

public abstract class Verify {

	/**
	 * Um weitere Requests verifizieren lassen zu koennen, muss in SignatureData ein weiterer entsprechender Konstruktor
	 * eingebaut werden. Diese Methode soll in den Implementierungen des Verifiers aufgerufen werden, nach die 
	 * erforderlichen Daten extrahiert worden sind.
	 * */
	public boolean verifySignatureData(SignatureData signData, PublicKey publicKeyOfSender, byte[] signatureBytes) {

		Signature signature = null;
		try {
			/**
			 * Initialisierung mit Algorithmus SHA256withRSA, der vom Anbieter BouncyCastle implementiert worden ist.
			 * */
			signature = Signature.getInstance("SHA256withRSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return false;
		}
		try {
			signature.initVerify(publicKeyOfSender);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		}
		try {
			
			signature.update(signData.toString().getBytes());
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		}
		
		try {
			if(signature.verify(signatureBytes)){
				System.out.println("Die Signatur des Requests ist wirklich vom Besitzer des übergebenen PublicKey");				
				return true;
			}
			else{
				System.out.println("Die Signatur des Requests ist NICHT!!! vom Besitzer des übergebenen PublicKey");
				return false;
			}
		} catch (SignatureException e) {			
			e.printStackTrace();
			return false;
		}
	}
	
	

}
