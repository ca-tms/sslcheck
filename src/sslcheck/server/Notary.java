package sslcheck.server;

/**
 * Interface was provided by the other group implementing an addon for firefox
 * to check certificates from ssl connections. This interface will be
 * implemented by the server, so that it can be used within the mentioned addon.
 * 
 * @date 2014-02-28
 * 
 */
public interface Notary {
	public ValidationResult queryNotary(java.security.cert.Certificate cert);
}
