package org.openscada.ae.client.ngp.pki.pkcs12.signprovider;

import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;

import org.openscada.ae.pki.common.sign.Signer;
import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.ae.pki.common.EnDeCoderByteString;
import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.sign.SignHelper;

public class SignerImpl implements Signer {
	
	private SignHelper signHelper = new SignHelperImpl();

	/**
	 * @param requestToBeSigned Der AcknowledgeRequest, der wenn es klappt, hinterher eine als String encodierte Signatur
	 * in den OperationParameters hat, die unter "signature" zu finden ist. Diese muss zum Verifizieren
	 * erst zurueck in ein byte-Array verwandelt werden (decodiert).
	 * @param privateKey Eine Referenz auf den PrivatKey, der zum Signieren benutzt werden soll.
	 * @param certAlias Der String, mit dem der Server das entsprechende PublicKey-Zertifikat zum Verifizieren finden kann.
	 * Dieser String sollte vom Token gelesen werden k�nnen und sich um die Seriennummer oder den Aliasnamen des Zertifikats handeln.
	 * */
	
	@Override
	public Object signRequest(Object requestToBeSigned) {
		if(requestToBeSigned instanceof AcknowledgeRequest){
			AcknowledgeRequest aknRequest = (AcknowledgeRequest)requestToBeSigned;
		byte[] signatureOfRequest;
		PrivateKey privateKeyForSigning = this.signHelper.getPrivateKeyForSigning();
		String idToFindPubKeyOnOtherSide = this.signHelper.getIdentifierStringForCertificate();

		signatureOfRequest = createSignatureForRequest(new SignatureData(aknRequest), privateKeyForSigning, idToFindPubKeyOnOtherSide);

		aknRequest.getOperationParameters().getProperties().put("stringIdentityOfUserCertificate", idToFindPubKeyOnOtherSide);
		
		aknRequest.getOperationParameters().getProperties().put("signature", EnDeCoderByteString.getInstance().encodeBytearrayToString(signatureOfRequest));

		return aknRequest;
		}
		else{
			System.out.println("Something went wrong in SignerImpl ngp signRequest");
			return null;
		}
	}
	

	

	/**
	 * @param signData Die aus dem (Acknowledge-)Request extrahierten Daten zum Signieren
	 * @param privateKey Der Private Schluessel des Bedieners
	 * @param certAlias Der aliasString, mit dem der Server sp�ter das zugehoerige 
	 * 			Zertifikat aus der Datenbank finden soll. Dies kann auch ein anderer String
	 * 			sein, es muss nur auf beiden Seiten klar sein, was es ist.
	 * @return Ein byte-Array, das die Signatur darstellt und an den Request angehaengt werden soll.
	 * */
	
	public byte[] createSignatureForRequest(SignatureData signData, PrivateKey privateKey,
			String idToFindPubKeyOnOtherSide) {
		Signature signature = null;
		byte[] signatureOfRequest = null;
		try {
			/**
			 * Algorithmus SHA256 der SHA2-Gruppe als Hash-Algorithmus mit RSA als Signaturalgorithmus. 
			 * SHA1 ist zwar als knackbar eingestuft worden, praktische Tests, mit denen sinnvolle Nachrichten 
			 * mit gleichen Hashwerten erzielt wurden, gibt es allerdings auch dort noch nicht. Da
			 * SHA1 jedoch als potentiell unsicher eingestuft wurde,
			 * empfiehlt das BSI die Hashalgorithmen der SHA2-Gruppe.
			 * (siehe https://www.bsi.bund.de/ContentBSI/Publikationen/TechnischeRichtlinien/tr02102/index_htm.html)
			 * provider: BC = Bouncy Castle
			 * */
			signature = Signature.getInstance("SHA256withRSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		}
		try {
			signature.initSign((PrivateKey) privateKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
		try {
			signature.update(signData.toString().getBytes());
		} catch (SignatureException e) {
			e.printStackTrace();
			return null;
		}
		try {
			signatureOfRequest = signature.sign();
		} catch (SignatureException e) {
			e.printStackTrace();
			return null;
		}
		return signatureOfRequest;
	}

}
