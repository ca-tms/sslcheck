package sslcheck.server;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.NotaryManager;
import sslcheck.system.SSLInfo;

/**
 * This is a simple Server accessing all objects in a direct way without implementing the adapter
 * mentioned in the documentation. This server does not provide any interface but does everything
 * automatically. It outputs everything to stdout. This server is useful for debugging and
 * testing purposes and should not be used in any production environment. 
 * 
 * @author letzkus
 *
 */
public class SimpleServerWithoutAdapter {
	
	private final static Logger log = LogManager.getRootLogger();
	
	public static void main(String[] args) {
		log.trace("Initializing...");
		//NotaryConfiguration notaryConf = NotaryConfiguration.getInstance();
		//NotaryRating notaryRating = NotaryRating.getInstance();
	    
		try {
			log.trace("Connecting to Host...");
		    SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
		    SSLSocket socket;
		    Certificate[] servercerts = {};
			socket = (SSLSocket) factory.createSocket("cert-test.sandbox.google.com", 443);
			socket.startHandshake();
			SSLSession session = socket.getSession();
			servercerts = session.getPeerCertificates();
			SSLInfo sslinfo = new SSLInfo(new URL("https://www.google.de/"), (X509Certificate[]) servercerts);
			
			log.info("Printing Certificates: \n"+sslinfo.toString());
			
			log.trace("Checking Certificates...");
			NotaryManager nm = new NotaryManager();
			log.info("Rating: "+nm.check(sslinfo));
			
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		log.trace("Done.");
	}
}
