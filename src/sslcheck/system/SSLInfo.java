package sslcheck.system;

import java.net.URL;
import sslcheck.system.X509Certificate;

/**
 * SSLInfo is a class used for storing HTTPS/SSL-related information such as URL
 * of the website or the certificates given by the server during the SSL
 * Session. It does not provide any real functionality.
 * 
 * @author letzkus
 * 
 */
public class SSLInfo {

	URL url;
	X509Certificate certificates;

	public X509Certificate getCertificates() {
		return certificates;
	}

	public SSLInfo(URL url, java.security.cert.X509Certificate[] servercerts) {
		this.url = url;
		this.certificates = X509Certificate
				.constructX509CertificatePath(servercerts, url.getHost());
	}
	
	/**
	 * Returns the URL
	 * @return the url
	 */
	public URL getURL() {
		return this.url;
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
