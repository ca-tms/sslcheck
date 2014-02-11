package sslcheck.notaries;

import java.security.cert.Certificate;

public class ICSINotary extends Notary {

	public ICSINotary() {
	}

	@Override
	public int check(SSLInfo sslinfo) {
		// First Phase, just print the certificate to check
		for(Certificate cert : sslinfo.getCertifcates()) {
			System.out.println("[ICSI] Checking Certificate "+cert.hashCode());
		}
		return 0;
	}

}
