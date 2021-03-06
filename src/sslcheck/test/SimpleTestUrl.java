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
package sslcheck.test;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;
import sslcheck.notaries.NotaryException;
//import sslcheck.notaries.ICSINotary; // see lines 82-90
//import sslcheck.notaries.ConvergenceNotary; // see lines 82-90

/**
 * This is a simple Server accessing all objects in a direct way without
 * implementing the adapter mentioned in the documentation. This server does not
 * provide any interface but does everything automatically. It outputs
 * everything to stdout. This server is useful for debugging and testing
 * purposes and should not be used in any production environment.
 * 
 * @author Fabian Letzkus
 * 
 */
public class SimpleTestUrl {

	private final static Logger log = LogManager.getRootLogger();

	public static void main(String[] args) throws KeyManagementException,
			NoSuchAlgorithmException {
		log.trace("Initializing...");
		// NotaryConfiguration notaryConf = NotaryConfiguration.getInstance();
		// NotaryRating notaryRating = NotaryRating.getInstance();

		String[] hosts = { "https://www.comdirect.de/"
		// , "https://www.cacert.org/"
		};
		for (String host : hosts) {

			try {

				URL urlObject = new URL(host);
				int port = 443;

				// Initialize Notaries by using NotaryManager
				// Either...
				NotaryManager nm = new NotaryManager();
				// or...
				// ICSINotary nm = new ICSINotary();
				// or...
				// ConvergenceNotary nm = new ConvergenceNotary();

				log.trace("Connecting to Host...");

				// Install the all-trusting trust manager
				final SSLContext sslContext = SSLContext.getInstance("TLS");
				sslContext.init(null,
						new TrustManager[] { nm.getTrustManager() 
						},
						new java.security.SecureRandom());

				// Install as default TLS Socket Factory, so it is also used by
				// notaries!
				// https://stackoverflow.com/questions/6047996/ignore-self-signed-ssl-cert-using-jersey-client
				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
						.getSocketFactory());

				// Create an ssl socket factory with our all-trusting manager
				final SSLSocketFactory factory = sslContext.getSocketFactory();
				SSLSocket socket;
				Certificate[] servercerts = {};
				socket = (SSLSocket) factory.createSocket(urlObject.getHost(),
						port);
				socket.startHandshake();
				SSLSession session = socket.getSession();

				// Extract Certificates
				servercerts = session.getPeerCertificates();
				TLSConnectionInfo sslinfo;
				sslinfo = new TLSConnectionInfo(host, port,
						(X509Certificate[]) servercerts);

				// Print Information about Certificates
				// log.info("Printing Certificates: \n"+sslinfo.toString());

				// Check Certificates using NotaryManager
				log.trace("-- BEGIN -- Checking Certificates...");
				
				try {
					log.info("Rating: " + sslinfo.validateCertificates(nm));
					if (sslinfo.isTrusted())
						log.info("Trustworthy.");
					else
						log.info("Not trustworthy.");
				} catch (NotaryException e) {
					log.info("Trust could not be evaluated: "+e);
				}
				log.trace("-- END -- Checking Certificates...");

				// NotaryRating.getInstance().clear();

			} catch (UnknownHostException e) {
				e.printStackTrace();
			} catch (MalformedURLException e1) {
				e1.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (TLSCertificateException e) {
				log.error("Can'parse certificate!!! Error: " + e);
			}

		}
		log.trace("Done.");
	}
}
