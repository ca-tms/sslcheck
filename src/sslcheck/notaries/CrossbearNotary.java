package sslcheck.notaries;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
				if(chain.length>0 && chain[0] != null)
					log.debug("Checking Crossbear TrustManager: "+chain[0].getSubjectDN());
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
			@SuppressWarnings("unused")
			int id=Message.byteArrayToInt(Message.readNBytesFromStream(bin, 1));
			// - int length
			int len= Message.byteArrayToInt(Message.readNBytesFromStream(bin, 2));
			// Result: fourth byte
			int result = Message.byteArrayToInt(Message.readNBytesFromStream(bin, 1));
			// - String report
			@SuppressWarnings("unused")
			String report= new String(Message.readNBytesFromStream(bin, len-4));
			
			log.info("Score: "+String.valueOf(result));
			
			String res = Message.inputStreamToString(bin);
			log.debug("Received response: " + String.valueOf(res));
			
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
