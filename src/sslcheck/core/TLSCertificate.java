package sslcheck.core;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * X509Certificate extends java.security.cert.X509Certificate and represents an
 * legitimate X509 Certificate which was retrieved during an TLS session from
 * the server. It is also able to hold issuing certificates like the ones of sub
 * CAs and root CAs, if they were delivered during TLS Handshake.
 * 
 * 
 * @author letzkus
 * 
 */
public class TLSCertificate extends java.security.cert.X509Certificate {

	private java.security.cert.X509Certificate x509cert;
	private TLSCertificate issuerX509Cert;
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
	 * @throws TLSCertificateException
	 */
	public static TLSCertificate constructX509CertificatePath(
			java.security.cert.Certificate[] certPath)
			throws TLSCertificateException {
		log.debug("Constructing X509CertificatePatch with length "
				+ certPath.length);
		TLSCertificate lastCert = new TLSCertificate(
				certPath[certPath.length - 1]);
		log.debug("Adding certificate " + (certPath.length - 1) + ":");
		log.debug("--- Subject: " + lastCert.getSubjectDN().toString());
		log.debug("--- Issuer: " + lastCert.getIssuerDN().toString());
		log.debug("--- SHA256: " + lastCert.getFingerprint("SHA-256"));
		log.debug("--- SHA1: " + lastCert.getSHA1Fingerprint());
		log.debug("--- MD5: " + lastCert.getMD5Fingerprint());
		for (int i = certPath.length - 2; i >= 0; i--) {
			lastCert = new TLSCertificate(certPath[i], lastCert);
			log.debug("Adding certificate " + i + ":");
			log.debug("--- Subject: " + lastCert.getSubjectDN());
			log.debug("--- Issuer: " + lastCert.getIssuerDN());
			log.debug("--- SHA256: " + lastCert.getFingerprint("SHA-256"));
			log.debug("--- SHA1: " + lastCert.getSHA1Fingerprint());
			log.debug("--- MD5: " + lastCert.getMD5Fingerprint());
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
	 * @throws TLSCertificateException
	 */
	public TLSCertificate(java.security.cert.Certificate c, TLSCertificate i)
			throws TLSCertificateException {
		if (c instanceof java.security.cert.X509Certificate) {
			this.x509cert = (java.security.cert.X509Certificate) c;
			this.issuerX509Cert = i;
		} else
			throw new TLSCertificateException(
					"Given Certificate is not a valid X509Certificate");
	}

	/**
	 * Constructor for X509Certificate without a issuer for the given
	 * certificate
	 * 
	 * @param c
	 *            The X509Certificate which was given during an SSL session
	 * @throws TLSCertificateException
	 */
	public TLSCertificate(java.security.cert.Certificate c)
			throws TLSCertificateException {
		if (c instanceof java.security.cert.X509Certificate)
			this.x509cert = (java.security.cert.X509Certificate) c;
		else
			throw new TLSCertificateException(
					"Given Certificate is not a valid X509Certificate");
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
	 * Checks whether path is valid.
	 * 
	 * @return true if valid, else false
	 */
	public boolean isPathValid() {
		try {
			if (this.hasIssuerCert()) { // Is there an issuer?
				if (this.getIssuerDN().equals(
						this.issuerX509Cert.getSubjectDN())) {
					this.verify(this.issuerX509Cert.getPublicKey());
					return this.issuerX509Cert.isPathValid();
				}
				return false;
			} else if (this.getIssuerDN().equals(this.getSubjectDN())) { // Self-Signed!
				this.verify(this.getPublicKey());
				return true;
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
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
	public TLSCertificate getIssuerCert() {
		if (this.hasIssuerCert())
			return this.issuerX509Cert;
		return null;
	}

	/**
	 * see java.security.cert.X509Cert.hashUnsupportedCriticalExtension()
	 * Unsupported Critical Extension can be in any certificate in the given
	 * chain.
	 */
	public boolean hasUnsupportedCriticalExtension() {
		boolean thisCert = this.x509cert.hasUnsupportedCriticalExtension();
		if (this.hasIssuerCert())
			return thisCert
					&& this.getIssuerCert().hasUnsupportedCriticalExtension();
		return thisCert;
	}

	public Set<String> getCriticalExtensionOIDs() {
		return this.x509cert.getCriticalExtensionOIDs();
	}

	public Set<String> getNonCriticalExtensionOIDs() {
		return this.x509cert.getNonCriticalExtensionOIDs();
	}

	public byte[] getExtensionValue(String oid) {
		return this.x509cert.getExtensionValue(oid);
	}

	@Override
	public int getVersion() {
		return this.x509cert.getVersion();
	}

	/**
	 * Checks validity of the whole chain. An Exception can also be raised at a
	 * sub-ca certificate.
	 */
	@Override
	public void checkValidity() throws CertificateExpiredException,
			CertificateNotYetValidException {
		this.x509cert.checkValidity();
		if (this.hasIssuerCert()) {
			this.issuerX509Cert.checkValidity();
		}

	}

	/**
	 * Checks validity of the whole chain. An Exception can also be raised at a
	 * sub-ca certificate.
	 */
	@Override
	public void checkValidity(Date date) throws CertificateExpiredException,
			CertificateNotYetValidException {
		this.x509cert.checkValidity(date);
		if (this.hasIssuerCert()) {
			this.issuerX509Cert.checkValidity(date);
		}
	}

	@Override
	public BigInteger getSerialNumber() {
		return this.x509cert.getSerialNumber();
	}

	@Override
	public Principal getIssuerDN() {
		return this.x509cert.getIssuerDN();
	}

	@Override
	public Principal getSubjectDN() {
		return this.x509cert.getSubjectDN();
	}

	/**
	 * Not before is determined by the maximum date of all given certificates
	 * 
	 * @return maximum not before date of all given certificates
	 */
	@Override
	public Date getNotBefore() {
		Set<Date> dates = this._getNotBeforeAll();
		Date highest = new Date(0);
		for (Date d : dates)
			if (d.after(highest))
				highest = d;
		return highest;
	}

	/**
	 * Returns all Not Before Dates
	 * 
	 * @return
	 */
	public Set<Date> _getNotBeforeAll() {
		HashSet<Date> dates = new HashSet<Date>();
		dates.add(this.x509cert.getNotBefore());
		if (this.hasIssuerCert())
			dates.addAll(this.issuerX509Cert._getNotBeforeAll());
		return dates;
	}

	@Override
	public Date getNotAfter() {
		return this.x509cert.getNotAfter();
	}

	@Override
	public byte[] getTBSCertificate() throws CertificateEncodingException {
		return this.x509cert.getTBSCertificate();
	}

	@Override
	public byte[] getSignature() {
		return this.x509cert.getSignature();
	}

	@Override
	public String getSigAlgName() {
		return this.x509cert.getSigAlgName();
	}

	@Override
	public String getSigAlgOID() {
		return this.x509cert.getSigAlgOID();
	}

	@Override
	public byte[] getSigAlgParams() {
		return this.x509cert.getSigAlgParams();
	}

	@Override
	public boolean[] getIssuerUniqueID() {
		return this.x509cert.getIssuerUniqueID();
	}

	@Override
	public boolean[] getSubjectUniqueID() {
		return this.x509cert.getSubjectUniqueID();
	}

	@Override
	public boolean[] getKeyUsage() {
		return this.x509cert.getKeyUsage();
	}

	@Override
	public int getBasicConstraints() {
		return this.x509cert.getBasicConstraints();
	}

	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		return this.x509cert.getEncoded();
	}

	@Override
	public void verify(PublicKey key) throws CertificateException,
			NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		this.x509cert.verify(key);
	}

	@Override
	public void verify(PublicKey key, String sigProvider)
			throws CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException, SignatureException {
		this.x509cert.verify(key, sigProvider);

	}

	@Override
	public PublicKey getPublicKey() {
		return x509cert.getPublicKey();
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return null;
	}

}
