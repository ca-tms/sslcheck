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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * @author Fabian Letzkus
 */
public class SSLUtil {
	/**
	 * Calculates Thumbprint of given Certificate
	 * 
	 * @param certificates
	 *            Certificate
	 * @return Fingerprint of Certificate
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
