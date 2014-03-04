package sslcheck.server;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.core.NotaryRating;
import sslcheck.core.NotaryRatingException;
import sslcheck.core.SSLInfo;

/**
 * NotaryServer implementes the sslcheck.server.Notary interface to be fully
 * compatible to the addon developed by another group during the Cryptography
 * Lab.
 * 
 * Although a server may provide a valid certificate chain, the server
 * is not be able to hand over those information to a notary-class, since this
 * information is simply not provided by the addon!
 * 
 * @author letzkus
 * 
 */
public class NotaryServer implements Notary {

	private final static Logger log = LogManager.getRootLogger();

	public ValidationResult queryNotary(Certificate cert) {

		X509Certificate[] certs = { (X509Certificate) cert };

		// TODO Implement real url..
		SSLInfo ssli = new SSLInfo("cacert.org", certs);
		
		// Initialize Notaries by using NotaryManager
		NotaryManager nm = new NotaryManager();
		NotaryRating nr = NotaryRating.getInstance();
		
		ssli.validateCertificates(nm);
		
		try {
			if(nr.isPossiblyTrusted()) {
				return ValidationResult.TRUSTED;
			}else{
				return ValidationResult.UNTRUSTED;
			}
		} catch (NotaryRatingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return ValidationResult.UNKNOWN;
	}

}
