package sslcheck.client;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import sslcheck.notaries.ConvergenceNotary;
import sslcheck.notaries.ICSINotary;
import sslcheck.server.system.NotaryConfiguration;
import sslcheck.server.system.NotaryManager;
import sslcheck.server.system.NotaryRating;
import sslcheck.system.SSLInfo;

public class SimpleClient {
	public static void main(String[] args) {
		System.out.println("Initializing...");
		NotaryConfiguration notaryConf = NotaryConfiguration.getInstance();
		NotaryRating notaryRating = NotaryRating.getInstance();
		NotaryManager notaries = new NotaryManager();
		
		System.out.println("Adding Notaries...");
		notaries.addNotary(new ICSINotary());
		notaries.addNotary(new ConvergenceNotary());

	    
		try {
			System.out.println("Connecting to Host...");
		    SSLSocketFactory factory = HttpsURLConnection.getDefaultSSLSocketFactory();
		    SSLSocket socket;
		    java.security.cert.Certificate[] servercerts = {};
			URL url = new URL("https://www.google.de/");
			socket = (SSLSocket) factory.createSocket("www.google.de", 443);
			socket.startHandshake();
			SSLSession session = socket.getSession();
			servercerts = session.getPeerCertificates();
			SSLInfo sslinfo = new SSLInfo(url, servercerts);
			
			System.out.println("Checking Certificates...");
			notaries.checkNotaries(sslinfo);
					
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Done.");
	}
}
