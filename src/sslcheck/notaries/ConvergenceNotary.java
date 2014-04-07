package sslcheck.notaries;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.json.JSONConfiguration;
import com.sun.jersey.core.util.MultivaluedMapImpl;

import sslcheck.core.TLSCertificate;
import sslcheck.core.TLSConnectionInfo;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Convergence");

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
			}
		});

	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {
		String h = tls.getRemoteHost();
		TLSCertificate c = tls.getCertificates();
		int port = tls.getRemotePort();

		// First Phase, just print the certificate to check
		log.trace("-- BEGIN -- ConvergenceNotary.check() ");
		String convergenceCompatibleHash = this.convertHash(c
				.getSHA1Fingerprint());
		log.debug("Checking Certificate for " + h + "+" + Integer.toString(port)
				+ " using hash " + convergenceCompatibleHash.substring(0, 29)
				+ "... ");

		ClientConfig jerseyClientConfig = new DefaultClientConfig();
		jerseyClientConfig.getFeatures().put(
				JSONConfiguration.FEATURE_POJO_MAPPING, Boolean.TRUE);
		Client client = Client.create(jerseyClientConfig);

		String _configuredNotaries = this.getParam("notaries");
		String configuredNotaries = (_configuredNotaries != null) ? _configuredNotaries
				: "https://notary.thoughtcrime.org:443/target/";
		String[] notaryURLs = configuredNotaries.split(",");

		// see
		// https://github.com/moxie0/Convergence/blob/master/client/chrome/content/ssl/ActiveNotaries.js
		int checkedNotaryCount = 0;
		int successCount = 0;

		float result = 0f;

		for (String notaryURL : notaryURLs) {

			try {

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

					log.debug(notaryURL + ": Status "
							+ Integer.toString(data.getStatus()) + " | Body: "
							+ json.substring(0,25) + "...");

					// See documentation for details
					if (status == 400 || status == 503) {

						log.error(String.format("%s: Internal error: %s",
								notaryURL, json));
						continue;

					} else if (status == 200) {

						successCount++;

					} else if (status == 303) {

						checkedNotaryCount--;

					} else if (status == 409) {

						log.info(String.format(
								"%s: POSSIBLE SECURITY PROBLEM!!!", notaryURL));

					} else {

						log.info(String.format(
								"%s: Received unknown status code!", notaryURL));

					}

					checkedNotaryCount++;

				}

			} catch (Exception e) {
				log.error("General Exception... " + e);
				throw new NotaryException("General Exception... " + e);
			}

		}

		String _tmp = this.getParam("decisionMethod");
		String decisionMethod = (_tmp != null) ? _tmp : "minority";

		// See documentation for details
		if (decisionMethod.equals("minority") && successCount > 0) { // Minority

			result = 10;

		} else if (successCount <= 0 || (decisionMethod.equals("consensus") // Consensus
				&& (successCount < checkedNotaryCount))) {

			result = 0;

		} else { // Majority

			int maj = (int) Math.floor(checkedNotaryCount / 2);
			if ((checkedNotaryCount / 2) % 2 != 0)
				maj++;
			if (successCount >= maj)
				result = 10;

		}

		log.trace("-- DONE -- ConvergenceNotary.check() ");
		return result;
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
