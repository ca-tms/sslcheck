package sslcheck.notaries;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jersey.core.util.Base64;

import sslcheck.core.TLSConnectionInfo;

public class SignatureCheck extends Notary { // Extends notary just for
												// implementation reasons

	private final static Logger log = LogManager
			.getLogger("notaries.SignatureCheck");

	@Override
	public void initialize() {

		this.setTrustManager(new X509TrustManager() {

			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) throws CertificateException {

				return;
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

		});

	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {

		String cNonce = "changeMePleaseImInsecure";

		String sigCheckHost = "http://signaturecheck.org/apiV1.php?";
		sigCheckHost = sigCheckHost.concat("url=" + tls.getRemoteHost());
		sigCheckHost = sigCheckHost.concat("&cnonce=" + cNonce);

		URL url;
		HttpURLConnection conn;
		BufferedReader rd;
		String line;
		String res = "";

		try {
			url = new URL(sigCheckHost);
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			rd = new BufferedReader(
					new InputStreamReader(conn.getInputStream()));
			while ((line = rd.readLine()) != null) {
				res += line;
			}
			rd.close();

			res = res.replaceAll("(.*?)\"([a-zA-Z0-9]+)=(.*?)", "$1\" $2=$3"); // XML
																				// is
																				// malformed,
																				// so
																				// we
																				// have
																				// to
																				// fix
																				// it...
			System.out.println(res);

			XMLInputFactory factory = XMLInputFactory.newInstance();
			XMLStreamReader parser = factory
					.createXMLStreamReader(new ByteArrayInputStream(res
							.getBytes(StandardCharsets.UTF_8)));
			boolean resultElement = false;

			while (parser.hasNext()) {
				if (parser.getEventType() == XMLStreamConstants.START_ELEMENT) {
					if (parser.getLocalName().equals("Result")) {
						log.debug("Found Result-Element.");
						for (int i = 0; i < parser.getAttributeCount(); i++) {
							if (parser.getAttributeLocalName(i)
									.equals("status")) {
								// <Result status="..">
								if (!parser.getAttributeValue(i).equals("ok")) {
									log.debug("Error connecting to given host via TLS: "
											+ parser.getAttributeValue(i));
									return 0; // TODO maybe better throw
												// NotaryException?
								} else {
									resultElement = true;
								}
							}
						}
					} else if (parser.getLocalName().equals("CertificateInfo")
							&& resultElement) {
						log.debug("Found CertificateInfo-Element.");
						for (int i = 0; i < parser.getAttributeCount(); i++) {
							if (parser.getAttributeLocalName(i)
									.equals("cNonce")) {
								log.debug("Found cNonce-Attribute.");
								if (!parser.getAttributeValue(i).equals(cNonce)) {
									log.debug("XML was malformed: cNonce is not "
											+ cNonce);
									return 0;
								}
							}
							if (parser.getAttributeLocalName(i).equals(
									"sha1thumbprint")) {
								log.debug("Found sha1thumbprint-Element.");
								if (parser
										.getAttributeValue(i)
										.toLowerCase()
										.equals(tls.getCertificates()
												.getSHA1Fingerprint()
												.toLowerCase())) {
									log.info("Score: 10");
									return 10;
								}
								log.info("Score: 0.");
							}
						}
					}
				}
				parser.next();
			}

		} catch (IOException e) {
			log.debug("Error checking SignatureCheck: IOException: " + e);
			return 0;
		} catch (XMLStreamException e) {
			log.debug("Error checking SignatureCheck: XMLStreamException: " + e);
			return 0;
		} catch (Exception e) {
			log.debug("Error checking SignatureCheck: General Exception: " + e);
			return 0;
		}

		return 0;
	}

}
