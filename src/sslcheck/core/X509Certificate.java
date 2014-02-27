package sslcheck.core;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * X509Certificate represents an Certificate which was retrieved during an SSL
 * session from the server.
 * 
 * @author letzkus
 * 
 */
public class X509Certificate {

	private java.security.cert.X509Certificate x509cert;
	private X509Certificate issuerX509Cert;
	private final static Logger log = LogManager
			.getLogger("core.X509Certificate");

	/**
	 * Constructor to create a X509Certificate-Structure based upon a
	 * Certification Path
	 * 
	 * @param certPath
	 *            the Certification Path usually given during an SSL Session
	 * @return an X509Certificate-Object containing the certificates from the
	 *         certification path
	 */
	public static X509Certificate constructX509CertificatePath(
			java.security.cert.X509Certificate[] certPath) {
		log.debug("Constructing X509CertificatePatch with length "
				+ certPath.length);
		X509Certificate lastCert = new X509Certificate(
				certPath[certPath.length - 1]);
		log.debug("Adding certificate " + (certPath.length - 1) + ":");
		log.debug("--- Subject: " + lastCert.getSubject());
		log.debug("--- Issuer: " + lastCert.getIssuer());
		log.debug("--- SHA1: "+lastCert.getSHA1Fingerprint());
		log.debug("--- MD5: "+lastCert.getMD5Fingerprint());
		for (int i = certPath.length - 2; i >= 0; i--) {
			lastCert = new X509Certificate(certPath[i], lastCert);
			log.debug("Adding certificate " + i + ":");
			log.debug("--- Subject: " + lastCert.getSubject());
			log.debug("--- Issuer: " + lastCert.getIssuer());
			log.debug("--- SHA1: "+lastCert.getSHA1Fingerprint());
			log.debug("--- MD5: "+lastCert.getMD5Fingerprint());
		}
		
		return lastCert;
	}

	/**
	 * Constructor for X509Certificate
	 * 
	 * @param c
	 *            The X509Certificate which was given during an SSL session
	 * @param i
	 *            The issuer of this certificate
	 */
	public X509Certificate(java.security.cert.X509Certificate c,
			X509Certificate i) {
		this.x509cert = c;
		this.issuerX509Cert = i;
	}

	/**
	 * Constructor for X509Certificate without a issuer for the given
	 * certificate
	 * 
	 * @param c
	 *            The X509Certificate which was given during an SSL session
	 */
	public X509Certificate(java.security.cert.X509Certificate c) {
		this.x509cert = c;
	}

	/**
	 * Returns the issuerDN
	 * 
	 * @return the IssuerDN
	 */
	public String getIssuer() {
		return this.x509cert.getIssuerDN().toString();
	}

	/**
	 * Returns the subjectDN
	 * 
	 * @return the subjectDN
	 */
	public String getSubject() {
		return this.x509cert.getSubjectDN().toString();
	}

	/**
	 * Returns the fingerprint of the X509Certificate by using the message
	 * digest algorithm defined in algo
	 * 
	 * @param algo
	 *            the Algorithm used to calculate the fingerprint
	 * @return the fingerprint of the certificate as a string
	 */
	public String getFingerprint(String algo) {
		try {
			return SSLUtil.getFingerprint(this.x509cert, algo);
		} catch (CertificateEncodingException e) {
			log.error("CertificateEncodingError: " + e);
		} catch (NoSuchAlgorithmException e) {
			log.error("NoSuchAlgorithmError: " + e);
		}
		return "";
	}

	public String getMD5Fingerprint() {
		return getFingerprint("MD5");
	}

	public String getSHA1Fingerprint() {
		return getFingerprint("SHA-1");
	}

	/**
	 * Checks, whether the given Certificate is a valid SSL Certificate based on
	 * the following best practices: - TODO
	 * 
	 * @return true, if Certificate is a valid SSL Certificate false, else
	 */
	public boolean isSSLValid() {
		// check if extensions for ssl are valid
		// check if certificate has ocsp and/or crls
		// ... are there any best practices??
		return false;
	}

	/**
	 * Checks, whether the given certificate is a valid
	 * 
	 * @return true if valid, else false
	 */
	public boolean isValid() {
		//
		// Check if this certificate is valid and if
		// return this.issuerX509Cert.isValid();
		return false;
	}

	/**
	 * Checks whether path is valid
	 * 
	 * @return true if valid, else false
	 */
	public boolean isPathValid() {
		if (this.issuerX509Cert != null) { // Is there an issuer?
			if (this.getIssuer().equals(this.issuerX509Cert.getSubject())) {
				// TODO Check signatures!!
				return this.issuerX509Cert.isPathValid();
			}
			return false;
		}
		if (this.getIssuer().equals(this.getSubject())) { // .. or is it
															// self-signed
			// TODO Check signature
			return false;
		} // ... or is the issuer unknown?
		log.warn("There were no further intermediate or root certificates given during SSL handshake!");
		return false;
	}

	/**
	 * Returns the length of the available path.
	 * 
	 * @return length of available path
	 */
	public int getAvailPathLen() {
		if (this.issuerX509Cert != null)
			return 1 + this.issuerX509Cert.getAvailPathLen();
		return 1;
	}

	/**
	 * Checks whether there is a issuer certificate available.
	 * 
	 * @return true if there as issuer certificate available
	 */
	public boolean hasIssuerCert() {
		return this.issuerX509Cert != null;
	}

	/**
	 * returns the issuer certificate if there is one, else null.
	 * 
	 * @return
	 */
	public X509Certificate getIssuerCert() {
		if (this.hasIssuerCert())
			return this.issuerX509Cert;
		return null;
	}
	
	public String toString() {
		String msg = "";
		msg += "";
		return msg;
	}

}
