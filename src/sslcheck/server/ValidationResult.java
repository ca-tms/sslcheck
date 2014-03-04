package sslcheck.server;

/**
 * The Enumeration was provided as part of the sslcheck.server.Notary Interface
 * by the other group implementing an addon for firefox to check certificates
 * from ssl connections.
 * 
 * @date 2014-02-28
 * 
 */
public enum ValidationResult {
	TRUSTED, UNTRUSTED, UNKNOWN
}