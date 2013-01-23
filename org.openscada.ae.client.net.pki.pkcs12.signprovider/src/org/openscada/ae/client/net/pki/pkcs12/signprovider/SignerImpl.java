package org.openscada.ae.client.net.pki.pkcs12.signprovider;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import org.openscada.ae.pki.common.sign.Signer;
import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.ae.pki.common.EnDeCoderByteString;
import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.sign.SignHelper;
import org.openscada.net.base.data.Message;
import org.openscada.net.base.data.StringValue;

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
	public Object signRequest(
			Object requestToBeSigned) {
		if(requestToBeSigned instanceof Message){
			Message message = (Message)requestToBeSigned;
		byte[] signatureOfRequest;
		PrivateKey privateKeyForSigning = this.signHelper.getPrivateKeyForSigning();
		String idToFindPublicKeyOnOtherSide = this.signHelper.getIdentifierStringForCertificate();
		signatureOfRequest = createSignatureForRequest(new SignatureData(message), privateKeyForSigning, idToFindPublicKeyOnOtherSide);

		message.getValues().put("stringIdentityOfUserCertificate", new StringValue(idToFindPublicKeyOnOtherSide));	
		message.getValues().put("signature", new StringValue(EnDeCoderByteString.getInstance().encodeBytearrayToString(signatureOfRequest)));

		System.out.println("signing finished with signature: " + signatureOfRequest.toString());
		return message;
		}
		else{
			System.out.println("Something went wrong in SignerImpl signRequest()");
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
			System.out.println("It seems you did not have copied the provider jar to your jre/lib/ext-directory. " +
					"In case of the BC provider, go to http://www.bouncycastle.org/latest_releases.html ," +
					" download the bcprov-JdkVersion-Version.jar of your jre-Version, so for example, " +
					"if you have JDK 1.5 or later, download the http://www.bouncycastle.org/download/bcprov-jdk15on-147.jar . " +
					"And then copy it to your jre/lib/ext directory of your Java install. " +
					"If you are using Windows, you might probably have two installations, one for the full JDK and one just contains the JRE." +
					"Then you have to add a line to the file /jre/lib/security/java.security . security.provider.N=org.bouncycastle.jce.provider.BouncyCastleProvider ," +
					" where N is the next number in the sequence.");
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
