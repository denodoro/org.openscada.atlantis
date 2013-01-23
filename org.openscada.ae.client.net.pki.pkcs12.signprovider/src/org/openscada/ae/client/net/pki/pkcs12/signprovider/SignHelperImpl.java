package org.openscada.ae.client.net.pki.pkcs12.signprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.openscada.ae.pki.common.sign.SignHelper;


public class SignHelperImpl implements SignHelper{


	/**
	 * Der PrivateKey ist nur ein Interface, das heisst eine Referenz auf einen PrivateKey. 
	 * Deshalb braucht man sich auch keine Sorgen machen, dass er irgendwo falsch landet.
	 * */
	private PrivateKey getPrivateKeyFromPKCS12file(KeyStore keystore)
			throws KeyStoreException, UnrecoverableKeyException,
			NoSuchAlgorithmException {
		String typeOfKeystore = keystore.getType();
		System.out.println("Type of keystore: " + typeOfKeystore);
		if (!typeOfKeystore.equals("PKCS12")) {
			throw new UnrecoverableKeyException("This is not a PKCS12 file!!");
		}
		// Im PKCS-file koennen Certificate�s und PrivateKey�s unter aliases zu
		// finden sein.
		// Wenn ein alias eigentlich einem PrivateKey gehoert, kann das
		// zugehoerige Certificate auch
		// mit KeyStore.getCertificate(aliasDesPrivateKey) gefunden werden

		Enumeration<String> en = keystore.aliases();

		while (en.hasMoreElements()) {
			String alias = (String) en.nextElement();
			System.out.println("found alias: " + alias);
			/**
			 * Wenn der Eintrag ein Key ist, ist es der PrivateKey
			 * */
			if (keystore.isKeyEntry(alias)) {
				System.out.println("entry found for alias: " + alias
						+ " This is the privateKey");
				PrivateKey privateKey = (PrivateKey) keystore.getKey(alias,
						"dennie".toCharArray()); 
				return privateKey;
			}
		}
		return null;
	}

	/**
	 * Dieser PrivateKey ist nur eine Referenz auf den PrivateKey, der zum Signieren 
	 * benutzt werden soll. Er kann nach JCA/JCE-Art und Weise im JavaCode benutzt werden.
	 * */
	@Override
	public PrivateKey getPrivateKeyForSigning() {
		PrivateKey privateKeyForSigning = null;
		/**
		 * Wenn der Key schon in den letzten x Minuten in der ClientConnection
		 * zwischengespeichert wurde, nimm diesen. Ansonsten schaue, ob der Token drin steckt
		 * und nimm daraus den PrivateKey. Wenn das auch nicht der Fall ist, zeige in der GUI an, 
		 * dass der Token eingesteckt sein muss.
		 * */
		
		
		
		

		
		// Liefert erstmal testweise nur den festgelegten PrivateKey aus der festgelegten Datei
		try {
			privateKeyForSigning =  this.getPrivateKeyFromPKCS12file(this.getKeyStoreForSigning());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	return privateKeyForSigning;
	}

	/** TODO: weiterschauen
	 * Um den PrivateKey zum Signieren zu bekommen(bzw die Referenz darauf), wird hier erst einmal
	 * der KeyStore aus der vorhandenen PKCS12-Datei geholt. Sie m�sste, sollte es sich 
	 * weiter um eine zu erreichende Datei mit PKCS12-Zertifikat handeln,
	 * eine Callback-Methode zur GUI aufrufen, die nach dem Ort der Datei und dem Passwort
	 * fuer den PrivateKey fragt.
	 * */

	public KeyStore getKeyStoreForSigning() {
// /home/denniea/workspaceAlt/org.openscada.ae.client.ngp.pki.pkcs12.signprovider/pkiDateien/DennieCert.p12
		String pathToPKCS = File.separator + "home" + File.separator + "denniea" + File.separator + "workspaceAlt" + File.separator + "org.openscada.ae.client.ngp.pki.pkcs12.signprovider" + File.separator + "pkiDateien" + File.separator  + "DennieCert.p12"; // uiMethodeDieDenPfadZurPKCS12DateiAbfragt()
 
		String password = "dennie"; //uiMethodeDieDasPasswortAbfragt();
		
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		/**
		 * TODO Hier muss dann noch eine Methode an die GUI geschickt werden, die den Ort
		 * und das Passwort f�r eine variabel zu bestimmende Datei herausfindet.
		 * */
		
		
		// Zertifikat in den KeyStore laden
		// mit den Parametern <Pfad zur Datei>, <passwort.toCharArray()>
		try {
			ks.load(new FileInputStream(pathToPKCS), password.toCharArray());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return ks;
	}

	/**
	 * Soll einen String zurueckgeben, mit dem der Server den zum PrivateKey gehoerenden 
	 * Public Key finden kann. TODO: dazu brauchen wir noch Infos zur Datenbank der PKI bei EON (und 
	 * Infos, ob diese Art und Weise der Persistierung Standard ist oder inwiefern EON-spezifisch.)
	 * */
	@Override
	public String getIdentifierStringForCertificate() {

		
		return "cert_dennie";
	}

}
