package org.openscada.ae.server.ngp.pki.pkcs12.verifiyprovider;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.openscada.ae.data.message.AcknowledgeRequest;
import org.openscada.ae.pki.common.EnDeCoderByteString;
import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.TransactionRequest;
import org.openscada.ae.pki.common.verifiy.Verifier;
import org.openscada.ae.pki.common.verifiy.Verify;
import org.openscada.ae.pki.common.verifiy.VerifyHelper;


public class VerifierImpl extends Verify implements Verifier{

private VerifyHelper verifyHelper = new VerifyHelperImpl();

	@Override
	public boolean verifyRequest(Object message){
		if(message instanceof AcknowledgeRequest ){
			return verifyAknRequest((AcknowledgeRequest) message);
		}
		/**
		 * TODO
		 * Funktionalitaet auch fuer andere Requests einbauen
		 * */
		else {
			return false;
		}
	}

	/**
	 * Extrahiert die erforderlichen Daten zum Verifizieren aus dem Request und ruft damit
	 * verifySignatureData auf.
	 * */
	private boolean verifyAknRequest(AcknowledgeRequest requestToBeVerified) {
		String identifier = requestToBeVerified.getOperationParameters().getProperties().get("stringIdentityOfUserCertificate");
		if(identifier.isEmpty()){
			System.out.println("1");
			return false;
		}
		X509Certificate certificateOfUser = this.verifyHelper.getPublicKeyCertificateByStringIdentifier(identifier);
		if(certificateOfUser==null){
			System.out.println("2");
			return false;
		}
		
		
		System.out.println("verifying certificate with CA");
		boolean verifiedByCA = verifyCertificateWithCACertificate(certificateOfUser);
		System.out.println("verified by CA? " + verifiedByCA);
		if(verifiedByCA==false){
			System.out.println("3");
			return false;
		}
		/**
		 * TODO: nochmal pruefen, ob das decodieren so auch funktioniert, oder ob man da
		 * noch aufgrund der codierung (utf8 etc) etwas aendern muss.
		 * */
		System.out.println("Signatur ist angekommen. als string: " + requestToBeVerified.getOperationParameters().getProperties().get("signature"));
		System.out.println("als byteArray: " + EnDeCoderByteString.getInstance().decodeStringToBytearray(requestToBeVerified.getOperationParameters().getProperties().get("signature")));
		byte[] signatureBytes = EnDeCoderByteString.getInstance().decodeStringToBytearray(requestToBeVerified.getOperationParameters().getProperties().get("signature"));
		
		if(signatureBytes==null){
			return false;
		}
		PublicKey publicKey = certificateOfUser.getPublicKey();
		if(publicKey==null){
			return false;
		}
			if(verifySignatureData(new SignatureData(requestToBeVerified), publicKey, signatureBytes)){
				if(this.verifyHelper.testTimeStampSingularity(new TransactionRequest(requestToBeVerified))){
					return true;
				}
			}
			return false;
	}


	
	/**
	 * Validiert, ob das uebergebene Zertifikat auch vom CA-Zertifikat signiert wurde.
	 * TODO: noch weiter fassen und gegen eine ganze Certificateskette verifizieren,
	 * doch dafuer sind wieder etwas mehr Infos zur PKI-DB erforderlich.
	 * */
	@Override
	public boolean verifyCertificateWithCACertificate(X509Certificate cert){
		X509Certificate caCertificate = this.verifyHelper.getCACertificate();
		X509Certificate certificateToVerify = cert;
		
			try {
				certificateToVerify.checkValidity();
			} catch (CertificateExpiredException e) {
				e.printStackTrace();
			} catch (CertificateNotYetValidException e) {
				e.printStackTrace();
			}
	
		PublicKey caPubKey = caCertificate.getPublicKey();
		
			try {
				certificateToVerify.verify(caPubKey);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}
	
		System.out.println("Das Certificate wurde von der vertrauten CA unterschrieben!!!");
		return true;
	}
	

	/**
	 * Log fuer die Nachvollziehbarkeit
	 * TODO: doch in eine andere Klasse schreiben! Ist eine andere Aufgabe. Oder?
	 * */
	@Override
	public void logTransactionSecurely(TransactionRequest request) {
		
		
	}
	
}
