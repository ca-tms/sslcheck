package sslcheck.server;

import java.net.MalformedURLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;

/**
 * NotaryServer implementes the sslcheck.server.Notary interface to be fully
 * compatible to the addon developed by another group during the Cryptography
 * Lab.
 * 
 * Although a server may provide a valid certificate chain, the server is not be
 * able to hand over those information to a notary-class, since this information
 * is simply not provided by the addon!
 * 
 * @author letzkus
 * 
 */
public class NotaryServer implements Notary {

	private final static Logger log = LogManager.getRootLogger();

	public ValidationResult queryNotary(Certificate cert) {

		/**
		 * This is a hard requirement!
		 */
		if (!(cert instanceof X509Certificate)) {
			return ValidationResult.UNKNOWN;
		}

		X509Certificate[] certs = { (X509Certificate) cert };

		TLSConnectionInfo ssli;
		try {
			ssli = new TLSConnectionInfo(((X509Certificate) cert)
					.getSubjectDN().toString(), 443, certs);
			
			// Possible initializations
			// ssli = new TLSConnectionInfo(String host, int port, X509Certificate[] certs)
			// ssli = new TLSConnectionInfo(String url, X509Certificate[] certs)

			// Initialize Notaries by using NotaryManager
			NotaryManager nm = new NotaryManager();

			ssli.validateCertificates(nm);

			if (ssli.isTrusted()) {
				log.info("Certificate "
						+ ssli.getCertificates().getSHA1Fingerprint()
						+ " is valid.");
				return ValidationResult.TRUSTED;
			} else {
				log.info("Certificate "
						+ ssli.getCertificates().getSHA1Fingerprint()
						+ " is invalid.");
				return ValidationResult.UNTRUSTED;
			}

		} catch (TLSCertificateException e1) {
			log.error("Can'parse certificate!!! Error: " + e1);
		} catch (MalformedURLException e) {
			log.debug("Url is malformed:" + e);
		}
		return ValidationResult.UNKNOWN;

	}

}
