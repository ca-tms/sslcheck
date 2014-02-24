package sslcheck.notaries;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.system.X509Certificate;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager.getLogger("notaries.Convergence");
	
	@Override
	public float check(X509Certificate c) {
		// First Phase, just print the certificate to check
		log.info("Checking Certificate "+c.getSHA1Fingerprint());
		return 100;
	}
}
