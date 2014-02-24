package sslcheck.notaries;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.system.X509Certificate;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Convergence");

	@Override
	public float check(String h, X509Certificate c) {
		// First Phase, just print the certificate to check
		log.info("Checking Host: " + h);
		log.info("Checking Certificate " + c.getSHA1Fingerprint());

		// Note to myself: What todo if getPresumedHost() == null -> Certificate
		// is CA Certificate...
		return 100;
	}
}
