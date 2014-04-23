package sslcheck.notaries;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
import com.sun.jersey.core.util.Base64;
import com.sun.jersey.core.util.MultivaluedMapImpl;

import sslcheck.core.TLSConnectionInfo;

public class SSLObservatoryNotary extends Notary {

	private final static Logger log = LogManager
			.getLogger("notaries.SSLObservatory");

	@Override
	public void initialize() {

		this.setTrustManager(new X509TrustManager() {

			public void checkClientTrusted(final X509Certificate[] chain,
					final String authType) {
			}

			public void checkServerTrusted(final X509Certificate[] chain,
					final String authType) throws CertificateException {
				
				final String[] base64Certificates = {"MIIJiTCCCHGgAwIBAgIDAYLpMA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3MgMiBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTMwNzE2MTQyOTEwWhcNMTUwNzE3MDc1NTIyWjCB0zEZMBcGA1UEDRMQdzR2eGFmNVlQNkhReTBYdDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xLTArBgNVBAoTJEVsZWN0cm9uaWMgRnJvbnRpZXIgRm91bmRhdGlvbiwgSW5jLjEeMBwGA1UEAxQVKi50cm9sbGluZ2VmZmVjdHMub3JnMS0wKwYJKoZIhvcNAQkBFh5ob3N0bWFzdGVyQHRyb2xsaW5nZWZmZWN0cy5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDNd0G/DNQ7pEvA/03gkER0k92v59PVEj0MkiRUpAzwaOk+hVvYahy76xv9FJ8V5xacBZypk6dOx5+FxB3BI+2XPcKim752O8P3eetdl2IexNTwxK72TZ1po9ZnRvs4EcQl6edeQc+YSPCWRhQlQEHyefxEUoNjLIfbmrKgAiabL24ddJGyzeDIPa4e00PexJyR2uezFmW/Y5R4rpxO9v5wp188wixLZmaaJSk3c5O8h5SUEnjkQ6JTQSwwaMVQqtfsIGaQg/8duTn3LfTF1kkC/cfnQXPHONY7CQ3Ru8RZOuK3B4MC32YfJYzAZopAY80Kfw4y8h5MLM+pYh1ISvJfrD6+PevnZwiyTkjuoiNr0D9WGVrZGXMRjy9jcBD0GTGlqu6XE9mAxetx9psmg959+OoMFOxjKWBJvwVUyo1cf2W3ORLzeSZXP7XZAr16S58TU3ePA5sA9lPyqrz0prdxQRGTW1S1MAPvmfGHiPmW++tMPTe69i/mpPTfnAlUx3AHeuuoRdgha0aPrXFW+yfleHWaAbziNf2TzcjUB9OOahFWmVkByVlZ135/GuEZAVHjhQwYhqP8JVSVTFo5BG8hQP1sVRmcT9OMBbqKjDea65K0Bpo3lxapf/FDlxp/oCIVyIVksgB38tM5vOyEMJm3tS2r0yDbwJNctED6jDh0AQIDAQABo4IEqTCCBKUwCQYDVR0TBAIwADALBgNVHQ8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBQdMeMKwFW5cJ+byJSspXrMQussrzAfBgNVHSMEGDAWgBQR2yNF/VTManFvhIoD1773AS8mhjCCAeMGA1UdEQSCAdowggHWghUqLnRyb2xsaW5nZWZmZWN0cy5vcmeCE3Ryb2xsaW5nZWZmZWN0cy5vcmeCE2NvcHlyaWdodC13YXRjaC5vcmeCFSouY29weXJpZ2h0LXdhdGNoLm9yZ4IVKi5jb3B5cmlnaHQtd2F0Y2gub3JnghRkZWZlbmRpbm5vdmF0aW9uLm9yZ4IVKi50cm9sbGluZ2VmZmVjdHMub3JnghYqLmRlZmVuZGlubm92YXRpb24ub3JnggdlZmYub3JnggkqLmVmZi5vcmeCFWdsb2JhbGNob2tlcG9pbnRzLm9yZ4IXKi5nbG9iYWxjaG9rZXBvaW50cy5vcmeCG2phaWxicmVha2luZ2lzbm90YWNyaW1lLm9yZ4IdKi5qYWlsYnJlYWtpbmdpc25vdGFjcmltZS5vcmeCHW5lY2Vzc2FyeWFuZHByb3BvcnRpb25hdGUubmV0gh8qLm5lY2Vzc2FyeWFuZHByb3BvcnRpb25hdGUubmV0gh1uZWNlc3NhcnlhbmRwcm9wb3J0aW9uYXRlLm9yZ4IOcmlwbWl4bWFrZS5vcmeCECoucmlwbWl4bWFrZS5vcmeCHyoubmVjZXNzYXJ5YW5kcHJvcG9ydGlvbmF0ZS5vcmcwggFWBgNVHSAEggFNMIIBSTAIBgZngQwBAgIwggE7BgsrBgEEAYG1NwECAzCCASowLgYIKwYBBQUHAgEWImh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL3BvbGljeS5wZGYwgfcGCCsGAQUFBwICMIHqMCcWIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MAMCAQEagb5UaGlzIGNlcnRpZmljYXRlIHdhcyBpc3N1ZWQgYWNjb3JkaW5nIHRvIHRoZSBDbGFzcyAyIFZhbGlkYXRpb24gcmVxdWlyZW1lbnRzIG9mIHRoZSBTdGFydENvbSBDQSBwb2xpY3ksIHJlbGlhbmNlIG9ubHkgZm9yIHRoZSBpbnRlbmRlZCBwdXJwb3NlIGluIGNvbXBsaWFuY2Ugb2YgdGhlIHJlbHlpbmcgcGFydHkgb2JsaWdhdGlvbnMuMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuc3RhcnRzc2wuY29tL2NydDItY3JsLmNybDCBjgYIKwYBBQUHAQEEgYEwfzA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Auc3RhcnRzc2wuY29tL3N1Yi9jbGFzczIvc2VydmVyL2NhMEIGCCsGAQUFBzAChjZodHRwOi8vYWlhLnN0YXJ0c3NsLmNvbS9jZXJ0cy9zdWIuY2xhc3MyLnNlcnZlci5jYS5jcnQwIwYDVR0SBBwwGoYYaHR0cDovL3d3dy5zdGFydHNzbC5jb20vMA0GCSqGSIb3DQEBBQUAA4IBAQAitW8P2SwcXb3+oazLsElTmgPquaSxz4zqlbpuQDBE7Zhfe+bjYlmNRqS1e+w4twaXtxEXoCS1LcGx9FHpSE4xSTpxGOYPl60f98qBgG4Gy/ANkagxGjMNHua5DkesiKEKoURk2Mbt8t8SzkloyL0UEHS3vcjNVfU6arBe/Yw5+of4fo0d/f8heFLB1d7XtvH32YO+o/Q/nAqJYuljh/0ShbZUypBWopC9o1zXEJfKqugQJkCiIm0Y0hULRZB60aAS7E9Irhb4NH+N1Eo46ek9F5ZF/OH7jwelMPFtMfo+z8TXPflykQZATiAmRVL5Jbzx1g5Pm4iIzk2PWNUsjyHs"};
				
				if (chain.length > 0 && chain[0] != null) { // Server gibt mind.
					// ein Zertifikat
					// zurück
					log.debug("Checking SSLObservatory TrustManager: "
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
								log.debug("SSLObservatory TrustManager: Found certificate -> trusted!");
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
						log.debug("SSLObservatory TrustManager: Certificate not found in this TrustStore.");
						throw new CertificateException(
								"SSLObservatory TrustManager: Certificate not found.");
					}

				} else {
					log.debug("Checking SSLObservatory TrustManager failed.");
					throw new CertificateException(
							"SSLObservatory TrustManager: Checking SSLObservatory TrustManager failed.");
				}
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		});

	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {

		log.trace("-- BEGIN -- SSLObervatory.check()");

		ClientConfig jerseyClientConfig = new DefaultClientConfig();
		jerseyClientConfig.getFeatures().put(
				JSONConfiguration.FEATURE_POJO_MAPPING, Boolean.TRUE);
		Client client = Client.create(jerseyClientConfig);

		float result = 0f;

		try {

			client.setConnectTimeout(Integer.valueOf(this
					.getParam("serverTimeout")));
			WebResource service = client
					.resource("https://observatory.eff.org/");

			// Adding request data
			MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
			formData.add("domain", tls.getRemoteHost());
			formData.add("remote_ip", InetAddress
					.getByName(tls.getRemoteHost()).getHostAddress());
			formData.add("client_asn", "-1");
			formData.add("private_opt_in", "1");
			formData.add("padding", "0");
			formData.add("certlist", "{\"" + tls.getCertificates().getEncoded()
					+ "\"}");

			// Sending request
			log.trace("Sending request...");
			ClientResponse data = service.path("submit_cert")
					.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
					.post(ClientResponse.class, formData);

			// Processing request
			log.trace("Processing response...");
			if (data.hasEntity()) {

				String observatoryResult = data.getEntity(String.class);
				int status = data.getStatus();

				if (status == 200) {
					log.info("Received 200. Everything ok.");
					if (observatoryResult.equals("1")) {
						log.debug("Observatory: Fingerprint unknown -> Certificate was added to database.");
					} else if (observatoryResult.equals("0")) {
						log.debug("Observatory: Certificate was not added to database.");
					}
					result = 10;
				} else if (status == 403) {
					log.info("ATTENTION: Certificate was consided harmful.");
					log.debug("Message: " + observatoryResult);
					result = 0;
				} else {
					log.error("Received an error message: " + observatoryResult);
				}

			}

			log.trace("-- END -- SSLObervatory.check()");

		} catch (UnknownHostException | CertificateEncodingException e) {
			log.error("Java Exception thrown: " + e);
			throw new NotaryException("Java Exception thrown: " + e);
		} catch (Exception e) {
			log.debug("General Exception thrown: " + e);
			throw new NotaryException(e.toString());
		}

		return result;
	}

}
