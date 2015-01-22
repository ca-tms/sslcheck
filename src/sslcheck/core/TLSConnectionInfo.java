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
package sslcheck.core;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import sslcheck.notaries.Notary;
import sslcheck.notaries.NotaryException;

/**
 * SSLInfo is a class used for storing HTTPS/SSL-related information such as URL
 * of the website or the certificates given by the server during the SSL
 * Session. It does not provide any real functionality.
 * 
 * @author Fabian Letzkus
 */
public class TLSConnectionInfo{

	String remoteHost;
	int remotePort;
	TLSCertificate certificates;
	Iterator<Certificate> certIterator;

	public TLSCertificate getCertificates() {
		return certificates;
	}

	public TLSConnectionInfo(String remoteHost, int port,
			Certificate[] servercerts)
			throws TLSCertificateException, MalformedURLException {
		this.remoteHost = new URL(remoteHost).getHost();
		this.remotePort = port;
		this.certificates = TLSCertificate
				.constructX509CertificatePath(servercerts);
		ArrayList<Certificate> ci = new ArrayList<Certificate>();
		for(Certificate c : servercerts)
			ci.add(c);
		this.certIterator = ci.iterator();
	}

	public TLSConnectionInfo(String host,
			Certificate[] servercerts)
			throws TLSCertificateException, MalformedURLException {
		URL url = new URL(host);
		this.remoteHost = url.getHost();
		this.remotePort = (url.getPort() == -1) ? url.getPort() : url
				.getDefaultPort();
		this.certificates = TLSCertificate
				.constructX509CertificatePath(servercerts);
		ArrayList<Certificate> ci = new ArrayList<Certificate>();
		for(Certificate c : servercerts)
			ci.add(c);
		this.certIterator = ci.iterator();
	}

	/**
	 * Validates itself using given Notary n
	 * 
	 * @param n
	 *            the Notary
	 * @return Result of validation. Can be -1 in case of an internal error.
	 * @throws NotaryException 
	 */
	public float validateCertificates(Notary n) throws NotaryException {
		return n.check(this);
	}
	
	/**
	 * Detemines, whether the connection is trustworthy or not.
	 * @return true/false trusted/non trusted
	 * @throws NotaryRatingException 
	 */
	public boolean isTrusted() throws NotaryRatingException {
		NotaryRating nr = NotaryRating.getInstance();
		return nr.isPossiblyTrusted(hashCode());
	}

	/**
	 * Returns all parameters as a output
	 */
	@Override
	public String toString() {
		String str = "";
		str += "URL: " + this.remoteHost + "\n";
		str += "Certificates: " + this.certificates.getAvailPathLen() + "\n";
		TLSCertificate cer = this.certificates;
		while (cer.hasIssuerCert()) {
			str += "----------------------------------------------------\n";
			try {
				str += "Subject: " + cer.getSubjectDN() + "\n";
				str += "Issuer: " + cer.getIssuerDN() + "\n";
				str += "SHA-1 Hash: " + cer.getSHA1Fingerprint() + "\n";
			} catch (Exception e) {
				str += "SHA-1 Hash not available: " + e + "\n";
			}
			cer = cer.getIssuerCert();
		}
		str += "----------------------------------------------------\n";
		return str;
	}

	public String getRemoteHost() {
		return this.remoteHost;
	}

	public int getRemotePort() {
		return this.remotePort;
	}

	@Override
	public int hashCode() {
		
		// Build string
		String hash = this.getRemoteHost()+";"+this.getRemotePort()+";";
		TLSCertificate issuer = this.certificates;
		do {
			hash.concat(issuer.getSHA1Fingerprint()+";");
			issuer = issuer.getIssuerCert();
		} while(issuer!=null);
		
		// uses hashCode of String
		return hash.hashCode();
			
	}
	
	public Iterator<Certificate> getCertIterator() {
		return this.certIterator;
	}
}
