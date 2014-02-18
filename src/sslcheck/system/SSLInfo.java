package sslcheck.system;

import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
	X509Certificate[] certs;
	
	private final static Logger log = LogManager.getLogger("core.NotaryManager");

	public SSLInfo(URL url, X509Certificate[] servercerts) {
		this.url = url;
		this.certs = servercerts;
	}	
	
	public X509Certificate[] getCertifcates() {
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
	 * @return SHA-1 Fingerprint of Certificate
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @url 
	 *      https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an
	 *      -x509-certificates-thumbprint-in-java
	 */
	public static String getFingerprint(X509Certificate c) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
			return hexify(md.digest(c.getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			log.error("NoSuchAlgorithmException!!!!");
		} catch (CertificateEncodingException e) {
			log.error("CertificateEncodingException!!!!");
		}
		return "";
	}
	
	public static String hexify (byte bytes[]) {

    	char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', 
    			'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    	StringBuffer buf = new StringBuffer(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
        	buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

	
	/**
	 * Returns all parameters as a debug output
	 */
	@Override
	public String toString() {
		String str ="";
		str = str.concat("URL: "+this.url+"\n");
		str = str.concat("Certificates: "+this.certs.length+"\n");
		for(X509Certificate cer : this.certs) {
			if(cer==null) { // do we really need this?
				str = str.concat("------- NULL Certificate found -------\n");
				continue;
			}
			str = str.concat("----------------------------------------------------\n");
			try {
				str = str.concat("Subject: "+cer.getSubjectDN()+"\n");
				str = str.concat("Issuer: "+cer.getIssuerDN()+"\n");
				str = str.concat("SHA-1 Hash: "+getFingerprint(cer)+"\n");
			} catch (Exception e) {
				str = str.concat("SHA-1 Hash not available: "+e+"\n");
			}	
		}
		str = str.concat("----------------------------------------------------\n");
		return str;
	}


}
