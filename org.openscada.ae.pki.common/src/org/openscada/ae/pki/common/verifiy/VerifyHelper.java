package org.openscada.ae.pki.common.verifiy;

import java.security.cert.X509Certificate;

import org.openscada.ae.pki.common.TransactionRequest;

public interface VerifyHelper {

	public X509Certificate getPublicKeyCertificateByStringIdentifier(String identifier);
	
	public X509Certificate getCACertificate();
	
	public boolean testTimeStampSingularity(TransactionRequest transaction);
}
