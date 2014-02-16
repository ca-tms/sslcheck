package sslcheck.system;

import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * SSLInfo is a class used for storing HTTPS/SSL-related information such as URL of the website
 * or the certificates given by the server during the SSL Session. It does not provide any real
 * functionality.
 * 
 * @author letzkus
 *
 */
public class SSLInfo {

	URL url;
	Certificate[] certs;

	public SSLInfo(URL url, Certificate[] servercerts) {
		this.url = url;
		this.certs = servercerts;
	}	
	
	public Certificate[] getCertifcates() {
		return this.certs;
	}
	
	public URL getURL(){
		return this.url;
	}

	/**
	 * Calculates Thumbprint of given Certificate
	 * 
	 * @param cert
	 *            Certificate
	 * @return Thumb Print of Certificate
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @url 
	 *      https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an
	 *      -x509-certificates-thumbprint-in-java
	 */
	public String getThumbPrint(Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		return md.digest().toString();
	}
	
	/**
	 * 
	 */
	@Override
	public String toString() {
		String str ="";
		str.concat("URL: "+this.url+"\n");
		for(Certificate cer : this.certs) {
			if(cer==null) { // do we really need this?
				str.concat("------- NULL Certificate found -------");
				continue;
			}
			str.concat("----------------------------------------------------");
			str.concat(cer.toString()+"\n");
			try {
				str.concat("SHA-1 Hash: "+this.getThumbPrint(cer));
			} catch (Exception e) {
				str.concat("SHA-1 Hash not available: "+e);
			}
			str.concat("----------------------------------------------------");
		}
		return str;
	}


}
