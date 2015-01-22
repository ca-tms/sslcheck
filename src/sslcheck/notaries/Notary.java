/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package sslcheck.notaries;

import java.util.Properties;

import javax.net.ssl.X509TrustManager;

import sslcheck.core.TLSConnectionInfo;

/**
 * @author Fabian Letzkus
 */
public abstract class Notary {
	
	/**
	 * __notaryName__ contains the name of the notary
	 * This variable is used to select or deselect a notary.
	 * If the name is not set (e.g. ""), than the notary is not checked.
	 */
	String __notaryName__ = "";
	Properties __config__;
	private X509TrustManager __trustManager__ = null;
	
	public String getNotaryName() {
		return this.__notaryName__;
	}
	
	public void setNotaryName(String s) {
		this.__notaryName__ = s;
	}
	
	public void setConfiguration(Properties p) {
		this.__config__ = p;
	}
	
	public String getParam(String param) {
		if(this.__config__ != null)
			return this.__config__.getProperty(param);
		return null;
	}
	
	public boolean hasTrustManager() {
		return !(this.__trustManager__ == null);
	}
	
	public X509TrustManager getTrustManager() {
		return this.__trustManager__;
	}
	
	protected void setTrustManager(X509TrustManager tm) {
		this.__trustManager__ = tm;
	}
	

	public void initialize() {
		// Default: do nothing..
	}

	
	/**
	 * 
	 * @param sslinfo
	 * @return Rating-Information derived from Notary Result
	 */
	public abstract float check(TLSConnectionInfo tls) throws NotaryException;


	
	
}
