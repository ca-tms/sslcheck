package sslcheck.notaries;

import sslcheck.system.X509Certificate;

public abstract class Notary {
	
	/**
	 * __notaryName__ contains the name of the notary
	 * This variable is used to select or deselect a notary.
	 * If the name is not set (e.g. ""), than the notary is not checked.
	 */
	String __notaryName__ = "";
	
	public String getNotaryName() {
		return this.__notaryName__;
	}
	
	public void setNotaryName(String s) {
		this.__notaryName__ = s;
	}
	
	/**
	 * 
	 * @param sslinfo
	 * @return Rating-Information derived from Notary Result
	 */
	public abstract float check(String h, X509Certificate c);
}
