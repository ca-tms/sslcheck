package sslcheck.notaries;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.json.JSONConfiguration;
import com.sun.jersey.core.util.MultivaluedMapImpl;

import sslcheck.core.TLSCertificate;
import sslcheck.core.TLSConnectionInfo;
import sslcheck.notaries.Convergence.Response;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Convergence");

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {
		String h = tls.getRemoteHost();
		TLSCertificate c = tls.getCertificates();
		int port = tls.getRemotePort();

		// First Phase, just print the certificate to check
		log.trace("-- BEGIN -- ConvergenceNotary.check() ");
		String convergenceCompatibleHash = this.convertHash(c
				.getSHA1Fingerprint());
		log.info("Checking Certificate for " + h + "+" + Integer.toString(port)
				+ " using hash " + convergenceCompatibleHash.substring(0, 29)
				+ "... ");

		ClientConfig jerseyClientConfig = new DefaultClientConfig();
		jerseyClientConfig.getFeatures().put(
				JSONConfiguration.FEATURE_POJO_MAPPING, Boolean.TRUE);
		Client client = Client.create(jerseyClientConfig);

		// TODO using https://notary.thoughtcrime.org:443/target/cacert.org for
		// testing purposes
		String[] notaryURLs = { "https://notary.thoughtcrime.org:443/target/" };
		float result = 0f;
		
		final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {

			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		} };
			

		try {
			
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, trustAllCerts,
					new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
					.getSocketFactory());

			for (String notaryURL : notaryURLs) {
				WebResource service = client.resource(notaryURL);

				// Creating POST-Request
				// MultivaluedMap -> see
				// https://stackoverflow.com/questions/2136119/using-the-jersey-client-to-do-a-post-operation
				MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
				formData.add("fingerprint", convergenceCompatibleHash);
				ClientResponse data = service
						.path(h + "+" + Integer.toString(port))
						.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
						.post(ClientResponse.class, formData);

				if (data.hasEntity()) {

					String json = data.getEntity(String.class);
					int status = data.getStatus();

					log.debug("Received answer: Status "
							+ Integer.toString(data.getStatus()) + " | Body: "
							+ json + "...");

					if (status == 303 || status == 400 || status == 503) {

						log.error(String.format("%1: Internal error: %2",
								notaryURL, json));
						continue;

					} else if (status == 200 || status == 409) {

						// Let's parse the answer and make it a POJO
						// ObjectMapper Example -> see
						// http://blogs.steeplesoft.com/posts/2012/01/26/a-jersey-pojomapping-clientserver-example/

						ObjectMapper mapper = new ObjectMapper();
						Response resp = mapper.readValue(json,
								new TypeReference<Response>() {
								});
						log.debug("JSON parsed successfully!");

						switch (status) {
						case 200:
							log.info(String.format("%s: Received 200.",
									notaryURL));
							result += 10;
							break;
						case 409:
							log.info(String.format("%s: Received 409.",
									notaryURL));
							result += 0;
							break;
						default:
							log.info(String.format("%s: Received %s.",
									notaryURL, Integer.toString(status)));
							return 0;
						}

					}

				}

				if (notaryURLs.length > 0)
					result = result / notaryURLs.length;

				return result;

			}

		} catch (JsonParseException e) {
			log.error("Error parsing json... " + e);
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			log.error("General exception: " + e);
		}

		log.trace("-- DONE -- ConvergenceNotary.check() ");
		return 0f;
	}

	/**
	 * Formats a standard hash a2b3b5... to the format A2:B3:B5...
	 * 
	 * @param h
	 *            the Hash
	 * @return
	 */
	private String convertHash(String h) {
		String convergenceCompatibleHash = "";
		h = h.toUpperCase();
		for (int i = 0; i < h.length(); i++) {
			convergenceCompatibleHash += h.charAt(i);
			if (i % 2 == 1 && i != h.length() - 1)
				convergenceCompatibleHash += ":";
		}
		return convergenceCompatibleHash;
	}

}
