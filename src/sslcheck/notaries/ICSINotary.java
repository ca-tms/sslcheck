package sslcheck.notaries;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.system.X509Certificate;

public class ICSINotary extends Notary {

	private final static Logger log = LogManager.getLogger("notaries.ICSI");

	@Override
	public float check(String h, X509Certificate c) {
		// First Phase, just print the certificate to check
		log.info("Checking Host: "+h);
		log.info("Checking Certificate "+c.getSHA1Fingerprint());
		return 100;
	}

}
