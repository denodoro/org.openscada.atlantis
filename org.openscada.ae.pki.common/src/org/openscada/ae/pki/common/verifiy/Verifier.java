package org.openscada.ae.pki.common.verifiy;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.openscada.ae.pki.common.SignatureData;
import org.openscada.ae.pki.common.TransactionRequest;

public interface Verifier {
	
	public boolean verifyRequest(Object message);
	
	public boolean verifyCertificateWithCACertificate(X509Certificate cert);
	
	public void logTransactionSecurely(TransactionRequest request);
	
}
