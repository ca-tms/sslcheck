package sslcheck.core;

import sslcheck.notaries.Notary;

/**
 * SSLInfo is a class used for storing HTTPS/SSL-related information such as URL
 * of the website or the certificates given by the server during the SSL
 * Session. It does not provide any real functionality.
 * 
 * @author letzkus
 * 
 */
public class TLSConnectionInfo {

	String remoteHost;
	int port;
	TLSCertificate certificates;

	public TLSCertificate getCertificates() {
		return certificates;
	}

	public TLSConnectionInfo(String remoteHost, int port, java.security.cert.Certificate[] servercerts) throws TLSCertificateException {
		this.remoteHost = remoteHost;
		this.certificates = TLSCertificate
				.constructX509CertificatePath(servercerts);
	}

	public float validateCertificates(Notary n) {
		return n.check(this);
	}

	/**
	 * Returns all parameters as a output
	 */
	@Override
	public String toString() {
		String str = "";
		str += "URL: " + this.remoteHost + "\n";
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

	public String getRemoteHost() {
		return this.remoteHost;
	}

	public int getRemotePort() {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * Returns
	 */

}
