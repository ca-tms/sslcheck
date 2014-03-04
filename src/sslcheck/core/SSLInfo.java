package sslcheck.core;

import java.net.URL;

import sslcheck.notaries.Notary;

/**
 * SSLInfo is a class used for storing HTTPS/SSL-related information such as URL
 * of the website or the certificates given by the server during the SSL
 * Session. It does not provide any real functionality.
 * 
 * @author letzkus
 * 
 */
public class SSLInfo {

	String url;
	X509Certificate certificates;

	public X509Certificate getCertificates() {
		return certificates;
	}

	public SSLInfo(String url, java.security.cert.X509Certificate[] servercerts) {
		this.url = url;
		this.certificates = X509Certificate
				.constructX509CertificatePath(servercerts);
	}

	public float validateCertificates(Notary n) {
		return n.check(this.url, this.certificates);
	}

	/**
	 * Returns all parameters as a output
	 */
	@Override
	public String toString() {
		String str = "";
		str += "URL: " + this.url + "\n";
		str += "Certificates: " + this.certificates.getAvailPathLen() + "\n";
		X509Certificate cer = this.certificates;
		while (cer.hasIssuerCert()) {
			str += "----------------------------------------------------\n";
			try {
				str += "Subject: " + cer.getSubject() + "\n";
				str += "Issuer: " + cer.getIssuer() + "\n";
				str += "SHA-1 Hash: " + cer.getSHA1Fingerprint() + "\n";
			} catch (Exception e) {
				str += "SHA-1 Hash not available: " + e + "\n";
			}
			cer = cer.getIssuerCert();
		}
		str += "----------------------------------------------------\n";
		return str;
	}

	/**
	 * Returns
	 */

}
