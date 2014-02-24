package sslcheck.system;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class SSLUtil {
	/**
	 * Calculates Thumbprint of given Certificate
	 * 
	 * @param certificates
	 *            Certificate
	 * @return SHA-1 Fingerprint of Certificate
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateEncodingException
	 * @url 
	 *      https://stackoverflow.com/questions/1270703/how-to-retrieve-compute-an
	 *      -x509-certificates-thumbprint-in-java
	 */
	public static String getFingerprint(X509Certificate c, String algo) throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md;
		md = MessageDigest.getInstance(algo);
		return hexify(md.digest(c.getEncoded()));
	}

	public static String hexify(byte bytes[]) {

		char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };

		StringBuffer buf = new StringBuffer(bytes.length * 2);

		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}

		return buf.toString();
	}
}
