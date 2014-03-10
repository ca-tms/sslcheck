package sslcheck.server;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;
//import sslcheck.notaries.ICSINotary; // see lines 82-90
//import sslcheck.notaries.ConvergenceNotary; // see lines 82-90

/**
 * This is a simple Server accessing all objects in a direct way without
 * implementing the adapter mentioned in the documentation. This server does not
 * provide any interface but does everything automatically. It outputs
 * everything to stdout. This server is useful for debugging and testing
 * purposes and should not be used in any production environment.
 * 
 * @author letzkus
 * 
 */
public class SimpleServerWithoutAdapter {

	private final static Logger log = LogManager.getRootLogger();

	public static void main(String[] args) throws KeyManagementException,
			NoSuchAlgorithmException {
		log.trace("Initializing...");
		// NotaryConfiguration notaryConf = NotaryConfiguration.getInstance();
		// NotaryRating notaryRating = NotaryRating.getInstance();
		
		String host = "cacert.org";
		int port = 443;

		try {
			log.trace("Connecting to Host...");

			// Code from https://code.google.com/p/misc-utils/wiki/JavaHttpsUrl
			final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

				public void checkClientTrusted(final X509Certificate[] chain,
						final String authType) {
				}

				public void checkServerTrusted(final X509Certificate[] chain,
						final String authType) {
				}

				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
			} };

			// Install the all-trusting trust manager
			final SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts,
					new java.security.SecureRandom());
			// Create an ssl socket factory with our all-trusting manager
			final SSLSocketFactory factory = sslContext.getSocketFactory();
			SSLSocket socket;
			Certificate[] servercerts = {};
			socket = (SSLSocket) factory.createSocket(host, port);
			socket.startHandshake();
			SSLSession session = socket.getSession();

			// Extract Certificates
			servercerts = session.getPeerCertificates();
			TLSConnectionInfo sslinfo;
			sslinfo = new TLSConnectionInfo(host, port,
					(X509Certificate[]) servercerts);

			// Initialize Notaries by using NotaryManager
			// Either...
			NotaryManager nm = new NotaryManager();
			// or...
			// ICSINotary nm = new ICSINotary();
			// or...
			// ConvergenceNotary nm = new ConvergenceNotary();
			
			// Print Information about Certificates
			// log.info("Printing Certificates: \n"+sslinfo.toString());

			// Check Certificates using NotaryManager
			log.trace("-- BEGIN -- Checking Certificates...");
			log.info("Rating: " + sslinfo.validateCertificates(nm));
			log.trace("-- END -- Checking Certificates...");

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (TLSCertificateException e) {
			log.error("Can'parse certificate!!! Error: " + e);
		}

		log.trace("Done.");
	}
}
