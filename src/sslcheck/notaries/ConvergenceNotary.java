package sslcheck.notaries;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.json.JSONConfiguration;
import com.sun.jersey.core.util.Base64;
import com.sun.jersey.core.util.MultivaluedMapImpl;

import sslcheck.core.TLSCertificate;
import sslcheck.core.TLSConnectionInfo;

public class ConvergenceNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.Convergence");

	@Override
	public void initialize() {

		final String[] base64Certificates = {
				/* Convergence */
				"MIIDkjCCAnoCCQCiafEhF0D5qzANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xGjAYBgNVBAoTEVRob3VnaHRjcmltZSBMYWJzMQ8wDQYDVQQLEwZOb3RhcnkxIDAeBgNVBAMTF25vdGFyeS50aG91Z2h0Y3JpbWUub3JnMCAXDTExMDYyOTIwNTc0OVoYDzE5MTUwNTE0MTQyOTMzWjCBiTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xGjAYBgNVBAoTEVRob3VnaHRjcmltZSBMYWJzMQ8wDQYDVQQLEwZOb3RhcnkxIDAeBgNVBAMTF25vdGFyeS50aG91Z2h0Y3JpbWUub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt02qTwZFohBLbOPzo+DN+EMTYpF9l23lmGlKzoM3W2c7CCosZhg8bRscmzl0SOAALbVKRrogrqhghnv03psqb2oznyD16rrF6R2rhYOT/u9XPkuw+l5o11JFt5YSthLobTtt7BHGXcpHCtsd6rvZn/bWVg9s1cV+5Q+wZ8saDEJbKkt2MoswnzueP/cslAYOIeDsxXQHOiGMlNYG/RLHUw1ISFXmVGE2qq+riwTcneglngqjfi7AEnXjPsc++bnZ5aCeT168ViLrhyj2UYep+U30vuKyO26Nv/SJWSY2Ax/nGbr2COOCiFTAdkGJSsM+bmd902BarFZqIbl+y/Iy+wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQASDKkpnPMSfhAAnjvkNJFlFjYHGGZ1ZCFPEbyD7ABhSebT/yv33cw3bmO+1X0ZSQ11yAXBS7vIv8ORE8hOtvS6GHtwP3OYblYOW+aRNjPNqQ1xzuPvKo8MHZfSu8dBgCVUMzjYxg0vVNAlVh6pqDaLecNDjHdCTLOESycKuy9sd5nnI96zfy9PWk+4pesuUOqNPend17DyXB4JkETvCnMQfxH9LDg6dm+AtFCAfcdoQGzalwvKG8YIZbAYVS3/rZGa4oYbYcr15ae5Ria17mALrWOZTMpXys2x+OfIc2lB/B56Wm9fLhQYfznCKXpHtrIhSE0N4tuTgu0sIY42yv8q",
				/* Void.gr */
				"MIIDmDCCAoACCQDDe5eJWmzhSjANBgkqhkiG9w0BAQUFADCBjDELMAkGA1UEBhMCR1IxDzANBgNVBAgTBkF0dGljYTEPMA0GA1UEBxMGQXRoZW5zMRIwEAYDVQQKEwlHUi1OT1RBUlkxDzANBgNVBAsTBk5vdGFyeTEXMBUGA1UEAxMObm90YXJ5LnZvaWQuZ3IxHTAbBgkqhkiG9w0BCQEWDm5vdGFyeUB2b2lkLmdyMCAXDTExMDkwOTA4MjI1OFoYDzIwNTEwODMwMDgyMjU4WjCBjDELMAkGA1UEBhMCR1IxDzANBgNVBAgTBkF0dGljYTEPMA0GA1UEBxMGQXRoZW5zMRIwEAYDVQQKEwlHUi1OT1RBUlkxDzANBgNVBAsTBk5vdGFyeTEXMBUGA1UEAxMObm90YXJ5LnZvaWQuZ3IxHTAbBgkqhkiG9w0BCQEWDm5vdGFyeUB2b2lkLmdyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA00geBHCs63ozhz38UbbABUVUKHWswa9OlI3H3s0PSZENcG+YEWQFTzeavIzFC9EcPzrp2E/uhnf9uOIOJRa8diB6km6sg6swBoTuoyDi7H5JswNqfmaFwUVuIfYo6VCeTi4MXD0Qrq3Yi8wC6dD5qjw3QANu0LvBQa6so/jemrKSQ2X8U4b8nLpi+WJcMPv+aU02Rk/bS5uSVaZtLx15TFtG6JMN29F6IdPp/uAd4E8A/3gIenwne6FYFp49qXK84GFlTVxUCdW5f/muacm5FIneDggpjAZ5KIxJSAhHRlt+7TcH9m07TOm8HZUCKZXyJsqdU355jH9J7viVvTH4+wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQByugHOKVcANI2zrHBkeZPDaTgcDJHE+u2KKVH9RG5+Ksl3LBFdwIuK+xQmvWynM0fHRi4WY7XdTSm1pw9EwDG9vpmZDufDVoFDSl4QOouk1aD2O/DX6rQG/2sBffeG04MQWYxaRuKJOs4eGqi9QWNfCRMYu6VxZYnPMPmgJdqH/PZyCzg9ZJjocNMQFzDZ9hZ3MAM/EIfgGEVCL7jvMLthsoGVTPByIZh+JmL8ev2INN9j/NLvKQ1Flc1K8MmEqQf5zGgAIQpcghMXrZ9ZLHdjaFYr4F4dgf8XOP8AhWF26lHaFEWY/HqDIhxK+f67nnFblzsQ2xxIuXNmLbslr0QH" };

		this.setTrustManager(new X509TrustManager() {

			@Override
			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) throws CertificateException {
				if (chain.length > 0 && chain[0] != null) { // Server gibt mind.
															// ein Zertifikat
															// zurück
					log.debug("Checking Convergence TrustManager: "
							+ chain[0].getSubjectDN());

					int unsuccessful = 0;

					for (String base64Certificate : base64Certificates) {

						try {

							CertificateFactory cf = CertificateFactory
									.getInstance("X.509");
							X509Certificate srvCert = (X509Certificate) cf
									.generateCertificate(new ByteArrayInputStream(
											Base64.decode(base64Certificate)));

							if (srvCert.equals(chain[0])) {
								log.debug("Convergence TrustManager: Found certificate -> trusted!");
								return;
							} else {
								throw new CertificateException();
							}

						} catch (CertificateException e) {
							unsuccessful++;
						}

					}

					/*
					 * this is not really needed, because if certificate was
					 * found, the method ends.
					 */
					if (unsuccessful == base64Certificates.length) {
						log.debug("Convergence TrustManager: Certificate not found in this TrustStore.");
						throw new CertificateException(
								"Convergence TrustManager: Certificate not found.");
					}

				} else {
					log.debug("Checking Convergence TrustManager failed.");
					throw new CertificateException(
							"Convergence TrustManager: Checking Convergence TrustManager failed.");
				}
			}

			@Override
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
		log.debug("Checking Certificate for " + h + "+"
				+ Integer.toString(port) + " using hash "
				+ convergenceCompatibleHash.substring(0, 29) + "... ");

		ClientConfig jerseyClientConfig = new DefaultClientConfig();
		jerseyClientConfig.getFeatures().put(
				JSONConfiguration.FEATURE_POJO_MAPPING, Boolean.TRUE);
		Client client = Client.create(jerseyClientConfig);

		int timeout = Integer.valueOf(this.getParam("timeout"));
		client.setConnectTimeout(timeout);
		client.setReadTimeout(timeout);

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
							+ json.substring(0, 25) + "...");

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

						log.debug(String.format(
								"%s: POSSIBLE SECURITY PROBLEM!!!", notaryURL));

					} else {

						log.debug(String.format(
								"%s: Received unknown status code!", notaryURL));

					}

					checkedNotaryCount++;

				}

			} catch (ClientHandlerException e) {

				log.error("Client Handler Exception, will ommit notary "
						+ notaryURL + " due to " + e);

			} catch (Exception e) {
				log.error("General Exception... " + e);
				throw new NotaryException("General Exception... " + e);
			}

		}

		if (checkedNotaryCount <= 0) {
			throw new NotaryException("No notary checked. Aborting.");
		}

		String _tmp = this.getParam("decisionMethod");
		String decisionMethod = (_tmp != null) ? _tmp : "minority";

		// See documentation for details
		if (decisionMethod.equals("minority") && successCount > 0) { // Minority

			log.info("Minority Voting successful.");

			result = 10;

		} else if (successCount <= 0 || (decisionMethod.equals("consensus") // Consensus
				&& (successCount < checkedNotaryCount))) {

			log.info("Minority/Consensus Voting unsuccessful.");
			result = 0;

		} else { // Majority

			int maj = (int) Math.floor(checkedNotaryCount / 2);
			if ((checkedNotaryCount / 2) % 2 != 0)
				maj++;
			if (successCount >= maj) {
				log.info("Majority/Consensus Voting successful.");
				result = 10;
			} else {
				log.info("Majority Voting unsuccessful.");
			}

		}

		log.info("Score: " + result + "/" + this.getParam("maxRating"));
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
