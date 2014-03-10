package sslcheck.notaries;

import java.io.IOException;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.UniformInterfaceException;
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
	public float check(TLSConnectionInfo tls) {
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
		WebResource service = client
				.resource("https://notary.thoughtcrime.org:443/target/");

		// Creating POST-Request
		// MultivaluedMap -> see
		// https://stackoverflow.com/questions/2136119/using-the-jersey-client-to-do-a-post-operation
		MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
		formData.add("fingerprint", convergenceCompatibleHash);
		ClientResponse data = service.path(h + "+" + Integer.toString(port))
				.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
				.post(ClientResponse.class, formData);

		if (data.hasEntity()) {

			String json = data.getEntity(String.class);
			int status = data.getStatus();

			log.debug("Received answer: Status "
					+ Integer.toString(data.getStatus()) + " | Body: "
					+ json.substring(0, 30) + "...");

			if (status == 303 || status == 400 || status == 503) {

				log.error("Internal error: " + json);
				return 0;

			} else if (status == 200 || status == 409) {

				try {

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
						return 10;
					case 409:
						return 0;
					default:
						return 0;
					}
				} catch (JsonParseException e) {
					log.error("Error parsing json... " + e);
				} catch (Exception e) {
					log.error("General exception: " + e);
				}

			}

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
