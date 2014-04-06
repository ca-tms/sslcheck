package sslcheck.notaries;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.core.TLSConnectionInfo;
import sslcheck.notaries.Crossbear.CertVerifyRequest;
import sslcheck.notaries.Crossbear.Message;
import sslcheck.notaries.Crossbear.MessageSerializationException;

public class CrossbearNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Crossbear");

	@Override
	public void initialize() {
		this.setTrustManager(new X509TrustManager() {

			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) {
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

			OutputStreamWriter wr = new OutputStreamWriter(
					conn.getOutputStream());
			wr.write(new String(req.getBytes()));
			wr.flush();

			if (conn.getResponseCode() >= 400)
				throw new NotaryException("ResponseCode > 400: "
						+ Message.inputStreamToString(conn.getInputStream()));

			// First byte represents score
			int result = Message.byteArrayToInt(Message.readNBytesFromStream(
					conn.getInputStream(), 1));

			log.info("Received response: " + Integer.toString(result));

			return (float) result;

		} catch (ClassCastException | IOException
				| MessageSerializationException e) {
			throw new NotaryException("Exception: " + e);
		}

	}

}
