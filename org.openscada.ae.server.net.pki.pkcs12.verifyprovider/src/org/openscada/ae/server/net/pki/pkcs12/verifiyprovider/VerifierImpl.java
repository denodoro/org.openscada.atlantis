package org.openscada.ae.server.net.pki.pkcs12.verifiyprovider;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import org.openscada.ae.pki.common.EnDeCoderByteString;
import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.TransactionRequest;
import org.openscada.ae.pki.common.verifiy.Verifier;
import org.openscada.ae.pki.common.verifiy.Verify;
import org.openscada.ae.pki.common.verifiy.VerifyHelper;
import org.openscada.net.base.data.Message;
import org.openscada.net.base.data.StringValue;


public class VerifierImpl extends Verify implements Verifier{

private VerifyHelper verifyHelper = new VerifyHelperImpl();

	@Override
	public boolean verifyRequest(Object message){
		if(message instanceof Message){
			return verifyMessage((Message) message);
		}
		else {
			System.out.println("FALSE?????");
			return verifyMessage((Message) message);
//			return false;
		}
	}

	/**
	 * Extrahiert die erforderlichen Daten zum Verifizieren aus der Message und ruft damit
	 * verifySignatureData auf.
	 * */
	private boolean verifyMessage(Message requestToBeVerified) {
		if(requestToBeVerified==null){
		}
		if(requestToBeVerified.getValues()==null){
		}
		if(requestToBeVerified.getValues().get("stringIdentityOfUserCertificate")==null){
		}
		StringValue identifier = (StringValue)(requestToBeVerified.getValues().get("stringIdentityOfUserCertificate"));
		
		if(identifier==null){
			return false;
		}
		X509Certificate certificateOfUser = this.verifyHelper.getPublicKeyCertificateByStringIdentifier(identifier.getValue());
		if(certificateOfUser==null){
			return false;
		}
		
		System.out.println("verifying certificate with CA");
		boolean verifiedByCA = verifyCertificateWithCACertificate(certificateOfUser);
		System.out.println("verified by CA? " + verifiedByCA);
		if(verifiedByCA==false){
			return false;
		}
		/**
		 * TODO: nochmal pruefen, ob das decodieren so auch funktioniert, oder ob man da
		 * noch aufgrund der codierung (utf8 etc) etwas aendern muss.
		 * */
		byte[] signatureBytes = EnDeCoderByteString.getInstance().decodeStringToBytearray(((StringValue)requestToBeVerified.getValues().get("signature")).getValue());
		
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
