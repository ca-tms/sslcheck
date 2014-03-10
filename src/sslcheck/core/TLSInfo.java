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
public class TLSInfo {

	String url;
	TLSCertificate certificates;

	public TLSCertificate getCertificates() {
		return certificates;
	}

	public TLSInfo(String url, java.security.cert.Certificate[] servercerts) throws TLSCertificateException {
		this.url = url;
		this.certificates = TLSCertificate
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
		TLSCertificate cer = this.certificates;
		while (cer.hasIssuerCert()) {
			str += "----------------------------------------------------\n";
			try {
				str += "Subject: " + cer.getSubjectDN() + "\n";
				str += "Issuer: " + cer.getIssuerDN() + "\n";
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
