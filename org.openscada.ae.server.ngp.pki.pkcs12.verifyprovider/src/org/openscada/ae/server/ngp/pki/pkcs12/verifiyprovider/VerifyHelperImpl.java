package org.openscada.ae.server.ngp.pki.pkcs12.verifiyprovider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.TransactionRequest;
import org.openscada.ae.pki.common.verifiy.Verifier;
import org.openscada.ae.pki.common.verifiy.VerifyHelper;

public class VerifyHelperImpl implements VerifyHelper{


	private static final String PATH_TO_TRUSTED_CA_CERTIFICATE_CER = VerifyHelperImpl.class.getClassLoader().getResource("Test_CA.cer").getFile();

	@Override
	public X509Certificate getPublicKeyCertificateByStringIdentifier(
			String identifier) {
		/**
		 * TODO: richtig implementieren!
		 * Da noch nicht klar ist, wie die PublicKey-Zertifikate abgelegt sind und gefunden werden
		 * koennen, werden erstmal testweise zwei Hilfsmethoden aufgerufen, die diese Aufgabe
		 * mit einem Test-Zertifikat erledigen.
		 * */
		KeyStore keystore = null;
		try {
			keystore = searchKeystore("dennie");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		X509Certificate cert = null;
		try {
			cert = getPublicKeyCertificateFromPKCS12file(keystore);
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return cert;
	}
	
	/**
	 * TODO: loeschen, wenn erforderliche Funktionalitaet implementiert ist.
	 * Hilfsmethode zum Testen der ersten Funktionalitaeten. Eigentlich braucht der Server diese
	 * Methode nicht, sondern sollte gleich nach dem PublicKey-Zertifikat des Users
	 * in der DB suchen.
	 * */
	public static KeyStore searchKeystore(String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		KeyStore ks = KeyStore.getInstance("PKCS12");
		/**
		 * TODO
		 * Hier muss dann noch der Pfad zum Token/Smartcard/sonstigePKCS-Datei eingesetzt werden
		 * analog zur Methode isTokenAvailableForSigning(), die es nur prueft, ob eins vorhanden ist
		 * */
		String pathToPKCS = VerifyHelperImpl.class.getClassLoader().getResource("DennieCert.p12").getFile(); // uiMethodeDieDenPfadZurPKCS12DateiAbfragt()


		// Zertifikat in den KeyStore laden
		// mit den Parametern <Pfad zur Datei>, <passwort.toCharArray()>
		ks.load(new FileInputStream(pathToPKCS), password.toCharArray());
		return ks;
	}
	
	/**
	 * TODO: loeschen, wenn erforderliche Funktionalitaet implementiert ist.
	 * Hilfsmethode zum Testen der ersten Funktionalitaeten. Eigentlich braucht der Server diese
	 * Methode nicht, sondern sollte gleich nach dem PublicKey-Zertifikat des Users
	 * in der DB suchen.
	 * */
	public static X509Certificate getPublicKeyCertificateFromPKCS12file(KeyStore keystore) throws UnrecoverableKeyException, KeyStoreException{
		X509Certificate certOfPKCS12file = null;
		String typeOfKeystore = keystore.getType();
		if(!typeOfKeystore.equals("PKCS12")){
			throw new UnrecoverableKeyException("This is not a PKCS12 file!!");
		}
		int numberOfAliases = 0;
		String aliasOfPrivateKey = null;
		Enumeration<String> en = keystore.aliases();
		while (en.hasMoreElements()) {
			numberOfAliases +=1;
			String alias = (String) en.nextElement();
			System.out.println("found alias: " + alias);
			if (keystore.isCertificateEntry(alias)) {
				System.out.println("alias " + alias + " is certificate");
				certOfPKCS12file = (X509Certificate)keystore.getCertificate(alias); 
				return certOfPKCS12file;
			}
			else if(keystore.isKeyEntry(alias)){
				aliasOfPrivateKey = alias;
			}
		}
		System.out.println("No certificate found with keystore.isCertificateEntry. Now trying to get it directly");
		System.out.println("Number of aliases found in file: " + numberOfAliases);
		// wenn nur 1 alias gefunden wurde, wird es der alias vom private key sein und das dazugeh�rige
		// certificate wird mit dem gleichen alias gefunden werden
		if(numberOfAliases==1){
		certOfPKCS12file = (X509Certificate)keystore.getCertificate(aliasOfPrivateKey);
		}
		if(certOfPKCS12file!=null){
			System.out.println("Certificate found");
		}
		else{
			System.out.println("No certificate found in this file");
		}
		return certOfPKCS12file;
	}

/**
 * TODO: Methode verkuerzen!!
 * */
	@Override
	public X509Certificate getCACertificate() {
		X509Certificate caCert = null;
		KeyStore trustStore = null;
		try {
			trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
			try {
				trustStore.load(null);
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (CertificateException e1) {
				e1.printStackTrace();
			} catch (IOException e1) {
				e1.printStackTrace();
			}

		/**
		 * TODO Sicherheitsvorschriften fuer CA-Certificate beachten! (Darf eigentlich nicht so einfach "herumliegen")
		 * */
		InputStream fis = null;
		try {
			fis = new FileInputStream(PATH_TO_TRUSTED_CA_CERTIFICATE_CER);
		} catch (FileNotFoundException e) {
			System.out.println("An dem Ort, wo das Certificate der CA gesucht wurde, existiert es nicht.");
			e.printStackTrace();
		}
		BufferedInputStream bis = new BufferedInputStream(fis);

		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		
			try {
				while (bis.available() > 0) {
				    Certificate cert = cf.generateCertificate(bis);
				    trustStore.setCertificateEntry("irgendeinAlias"+bis.available(), cert);
				}
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		

			try {
				caCert = (X509Certificate)trustStore.getCertificate("irgendeinAlias"+bis.available());
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}


		return caCert;
	}

	/**
	 * Implementieren
	 * */
	@Override
	public boolean testTimeStampSingularity(TransactionRequest transaction){
		
	
	return true;
	}

	
	
	
}
