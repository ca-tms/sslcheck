package sslcheck.notaries;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.TLSCertificate;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Convergence");

	@Override
	public float check(String h, TLSCertificate c) {
		// First Phase, just print the certificate to check
		log.trace("-- BEGIN -- ConvergenceNotary.check() ");
		String convergenceCompatibleHash = this.convertHash(c
				.getSHA1Fingerprint());
		log.info("Checking Certificate for " + h
				+ " using convergenceCompatibleHash "
				+ convergenceCompatibleHash);
		float result = this.checkNotary(h, c);
		log.trace("-- DONE -- ConvergenceNotary.check() ");
		// Note to myself: What todo if getPresumedHost() == null -> Certificate
		// is CA Certificate...
		return result;
	}

	private float checkNotary(String url, TLSCertificate c) {
		
		return 0f;
	}

	/**
	 * Formats a standard hash a2b3b5... to the format A2:B3:B5...
	 * 
	 * @param h the Hash
	 * @return
	 */
	private String convertHash(String h) {
		String convergenceCompatibleHash = "";
		h = h.toUpperCase();
		for (int i = 0; i < h.length(); i++) {
			convergenceCompatibleHash += h.charAt(i);
			if (i % 2 == 1 && i != h.length() - 1)
				convergenceCompatibleHash += ":";
		}
		return convergenceCompatibleHash;
	}
}
