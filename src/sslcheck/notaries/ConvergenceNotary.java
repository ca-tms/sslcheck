package sslcheck.notaries;

import java.security.cert.Certificate;

public class ConvergenceNotary extends Notary {

	@Override
	public int check(SSLInfo sslinfo) {
		// First Phase, just print the certificate to check
		for(Certificate cert : sslinfo.getCertifcates()) {
			System.out.println("[Convergence] Checking Certificate "+cert.hashCode());
		}
		return 0;
	}

	@Override
	public void configure(NotaryConfiguration conf) {
		// Nothing to do here for this notary :)
	}

}
