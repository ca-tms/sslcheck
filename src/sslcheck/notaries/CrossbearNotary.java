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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.TLSConnectionInfo;
import sslcheck.core.SSLUtil;
import sslcheck.notaries.Crossbear.CertVerifyRequest;
import sslcheck.notaries.Crossbear.Message;
import sslcheck.notaries.Crossbear.MessageSerializationException;

/**
 * @author Fabian Letzkus
 */
public class CrossbearNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Crossbear");

	@Override
	public void initialize() {
		this.setTrustManager(new X509TrustManager() {

			private String fingerprint = "86738EBCAD7129BAD09429E75F2C310A0B370A65";
			private String returnMessage = "";

			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) throws CertificateException {
				if (chain.length > 0 && chain[0] != null) {
					log.debug("Checking Crossbear TrustManager: "
							+ chain[0].getSubjectDN());
					try {
						if (SSLUtil.getFingerprint(chain[0], "SHA-1")
								.toUpperCase()
								.equals(fingerprint.toUpperCase())) {
							log.debug("Crossbear TrustManager: Found certificate -> trusted!");
							return;
						}
						log.debug("Crossbear TrustManager: Certificate not found in this TrustStore.");
						returnMessage = "Crossbear TrustManager: Certificate not found.";
					} catch (CertificateEncodingException e) {
						log.debug("Crossbear TrustManager: Error: Certificate not in correct encoding!");
						returnMessage = "Crossbear TrustManager: Checking TrustManager failed.";
					} catch (NoSuchAlgorithmException e) {
						log.debug("Crossbear TrustManager: Error: Certificate not in correct encoding!");
						returnMessage = "Crossbear TrustManager: Error: Checking TrustManager failed.";
					}
					throw new CertificateException(returnMessage);
				}
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
				// TODO
			}
		});
	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {
		CertVerifyRequest req = new CertVerifyRequest();

		try {

			// Easy Parameters..
			req.setHostName(tls.getRemoteHost());
			req.setHostPort(tls.getRemotePort());
			req.setHostIP(InetAddress.getByName(tls.getRemoteHost()));

			// 2014-04-01 Only LSB matters
			// 1 -> User is behind ssl proxy
			// 0 -> User is not behind ssl proxy
			req.setOptions(0);

			// Certificate chain.. (i know, it's ugly code...)
			Iterator<Certificate> it = tls.getCertIterator();
			X509Certificate[] c = new X509Certificate[tls.getCertificates()
					.getAvailPathLen()];
			int i = 0;
			while (it.hasNext()) {
				c[i] = (X509Certificate) it.next();
				i++;
			}
			req.setCertChain(c);

			URL cbServer = new URL(this.getParam("cbServer"));
			HttpsURLConnection conn = (HttpsURLConnection) cbServer
					.openConnection();

			conn.setDoOutput(true);

			OutputStream os = conn.getOutputStream();

			os.write(req.getBytes());
			os.flush();

			if (conn.getResponseCode() >= 400)
				throw new NotaryException("ResponseCode > 400: "
						+ Message.inputStreamToString(conn.getInputStream()));

			log.debug("Received response code: " + conn.getResponseCode());

			InputStream bin = conn.getInputStream(); // Actually sends the data..

			//parse CertVerifyResult message: 1 byte Message ID
			//2 bytes length
			//1 byte rating
			//the rest is the report as string.
			// - int msgType
			Message.byteArrayToInt(Message.readNBytesFromStream(bin, 1));
			// - int length
			Message.byteArrayToInt(Message.readNBytesFromStream(bin, 2));
			// Result: fourth byte
			int result = Message.byteArrayToInt(Message.readNBytesFromStream(bin, 1));

			// - String report
			// String report= new String(Message.readNBytesFromStream(bin, length-4));

			log.info("Score: " + String.valueOf(result));

			String res = Message.inputStreamToString(bin);
			//log.debug("Received response: " + String.valueOf(res));
			
			if(res.matches("(?s).*<crit>.*</crit>(?s).*")) {
				log.info("Response does contain CRIT-part!");
			}

			os.close();
			bin.close();

			//workaround, trust is proposed from rating 100 onwards
			if(result>150)
				return 150;

			return result;

		} catch (ClassCastException | IOException
				| MessageSerializationException e) {
			throw new NotaryException("Exception: " + e);
		}

	}

}
