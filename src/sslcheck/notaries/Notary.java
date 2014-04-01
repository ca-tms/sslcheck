package sslcheck.notaries;

import java.util.Properties;

import sslcheck.core.TLSConnectionInfo;

public abstract class Notary {
	
	/**
	 * __notaryName__ contains the name of the notary
	 * This variable is used to select or deselect a notary.
	 * If the name is not set (e.g. ""), than the notary is not checked.
	 */
	String __notaryName__ = "";
	Properties __config__;
	
	public String getNotaryName() {
		return this.__notaryName__;
	}
	
	public void setNotaryName(String s) {
		this.__notaryName__ = s;
	}
	
	public void setConfiguration(Properties p) {
		this.__config__ = p;
	}
	
	public String getConfigParam(String param) {
		if(this.__config__ != null)
			return this.__config__.getProperty(param);
		return null;
	}
	
	/**
	 * 
	 * @param sslinfo
	 * @return Rating-Information derived from Notary Result
	 */
	public abstract float check(TLSConnectionInfo tls) throws NotaryException;
	
}
