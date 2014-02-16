package sslcheck.system;

import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class SSLInfo {

	URL url;
	Certificate[] certs;

	public SSLInfo(URL url, Certificate[] servercerts) {
		this.url = url;
		this.certs = servercerts;
	}	
	
	public Certificate[] getCertifcates() {
		return this.certs;
	}
	
	public URL getURL(){
		return this.url;
	}

	/**
	 * Calculates Thumbprint of given Certificate
	 * 
	 * @param cert
	 *            Certificate
	 * @return Thumb Print of Certificate
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @url 
	 *      https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an
	 *      -x509-certificates-thumbprint-in-java
	 */
	public String getThumbPrint(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		return md.digest().toString();
	}


}
