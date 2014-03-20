package sslcheck.core;

import java.net.MalformedURLException;
import java.net.URL;

import sslcheck.notaries.Notary;
import sslcheck.notaries.NotaryException;

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
	int remotePort;
	TLSCertificate certificates;

	public TLSCertificate getCertificates() {
		return certificates;
	}

	public TLSConnectionInfo(String remoteHost, int port,
			java.security.cert.Certificate[] servercerts)
			throws TLSCertificateException, MalformedURLException {
		this.remoteHost = new URL(remoteHost).getHost();
		this.remotePort = port;
		this.certificates = TLSCertificate
				.constructX509CertificatePath(servercerts);
	}

	public TLSConnectionInfo(String host,
			java.security.cert.Certificate[] servercerts)
			throws TLSCertificateException, MalformedURLException {
		URL url = new URL(host);
		this.remoteHost = url.getHost();
		this.remotePort = (url.getPort() == -1) ? url.getPort() : url
				.getDefaultPort();
		this.certificates = TLSCertificate
				.constructX509CertificatePath(servercerts);
	}

	/**
	 * Validates itself using given Notary n
	 * 
	 * @param n
	 *            the Notary
	 * @return Result of validation. Can be -1 in case of an internal error.
	 */
	public float validateCertificates(Notary n) {
		try {
			return n.check(this);
		} catch (NotaryException e) {
			return -1;
		}
	}
	
	/**
	 * Detemines, whether the connection is trustworthy or not.
	 * @return true/false trusted/non trusted
	 */
	public boolean isTrusted() {
		NotaryRating nr = NotaryRating.getInstance();
		return nr.isPossiblyTrusted(hashCode());
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
		return this.remotePort;
	}

	@Override
	public int hashCode() {
		
		// Build string
		String hash = this.getRemoteHost()+";"+this.getRemotePort()+";";
		TLSCertificate issuer = this.certificates;
		do {
			hash.concat(issuer.getSHA1Fingerprint()+";");
			issuer = issuer.getIssuerCert();
		} while(issuer!=null);
		
		// uses hashCode of String
		return hash.hashCode();
			
	}
}
