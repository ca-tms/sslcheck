package sslcheck.notaries;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
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
					final String authType) {
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

			WebResource service = client
					.resource("https://observatory.eff.org/");
			
			// Adding request data
			MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
			formData.add("domain", tls.getRemoteHost());
			formData.add("remote_ip", InetAddress.getByName(tls.getRemoteHost()).getHostAddress());
			formData.add("client_asn", "-1");
			formData.add("private_opt_in", "1");
			formData.add("padding", "0");
			formData.add("certlist", "{\""+ tls.getCertificates().getEncoded() +"\"}");
			
			// Sending request
			log.trace("Sending request...");
			ClientResponse data = service
					.path("submit_cert")
					.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
					.post(ClientResponse.class, formData);
			
			// Processing request
			log.trace("Processing response...");
			if (data.hasEntity()) {

				String observatoryResult = data.getEntity(String.class);
				int status = data.getStatus();
				
				if(status == 200) {
					log.info("Received 200. Everything ok.");
					if(observatoryResult.equals("1")) {
						log.debug("Observatory: Fingerprint unknown -> Certificate was added to database.");
					}else if(observatoryResult.equals("0")){
						log.debug("Observatory: Certificate was not added to database.");
					}
					result = 10;
				}else if(status == 403) {
					log.info("ATTENTION: Certificate was consided harmful.");
					log.debug("Message: "+observatoryResult);
					result = 0;
				}else{
					log.error("Received an error message: "+observatoryResult);
				}
				
			}
			
			log.trace("-- END -- SSLObervatory.check()");	

		} catch (UnknownHostException | CertificateEncodingException e) {
			log.error("Java Exception thrown: "+e);
			throw new NotaryException("Java Exception thrown: "+e);
		}
		
		return result;
	}

}
