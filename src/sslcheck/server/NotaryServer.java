package sslcheck.server;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.core.NotaryRating;
import sslcheck.core.NotaryRatingException;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSInfo;

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

		// TODO Implement real url..
		TLSInfo ssli;
		try {
			ssli = new TLSInfo(((X509Certificate) cert).getSubjectDN()
					.toString(), certs);

			// Initialize Notaries by using NotaryManager
			NotaryManager nm = new NotaryManager();
			NotaryRating nr = NotaryRating.getInstance();

			ssli.validateCertificates(nm);

			try {
				if (nr.isPossiblyTrusted()) {
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
			} catch (NotaryRatingException e) {
				log.debug("Error while checking Certificate "
						+ ssli.getCertificates().getSHA1Fingerprint() + ": "
						+ e);
			}
		} catch (TLSCertificateException e1) {
			log.error("Can'parse certificate!!! Error: " + e1);
		}
		return ValidationResult.UNKNOWN;

	}

}
