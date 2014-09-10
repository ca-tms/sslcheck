package sslcheck.notaries;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.base.Charsets;
import com.sun.jersey.api.client.Client;

import sslcheck.core.TLSConnectionInfo;

public class PerspectivesNotary extends Notary {

	@XmlRootElement(name="notary_reply")
	public static class NotaryReply {
	    @XmlElement(name="key") public Key[] keys;
	    @XmlAttribute(name="version") public String version;
	    @XmlAttribute(name="sig") public String signature;
	    @XmlAttribute(name="sig_type") public String signatureType;
	}

	public static class Key {
	    @XmlElement(name="timestamp") public Timestamp[] timestamps;
	    @XmlAttribute(name="fp")  public String fingerprint;
	    @XmlAttribute(name="type") public String type;
	}

	public static class Timestamp {
		@XmlAttribute(name="start") public long start;
		@XmlAttribute(name="end") public long end;
	}

	private final static Logger log = LogManager
			.getLogger("notaries.Perspectives");

	private final KeyFactory keyFactory;
	private final Signature signature;
	private Map<String, String> notaryHosts;

	public PerspectivesNotary() throws NoSuchAlgorithmException {
		keyFactory = KeyFactory.getInstance("RSA");
		signature = Signature.getInstance("MD5withRSA");
	}

	private boolean isParamValueSet(String param) {
		return param != null && !param.isEmpty();
	}

	private PublicKey publicKeyFromString(String base64String)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
				DatatypeConverter.parseBase64Binary(base64String));
		return keyFactory.generatePublic(keySpec);
	}

	private boolean verifySignature(PublicKey publicKey, String base64Signature,
			String data)
			throws InvalidKeyException, SignatureException {
		signature.initVerify(publicKey);
		signature.update(data.getBytes(Charsets.UTF_8));
		return signature.verify(DatatypeConverter.parseBase64Binary(
				base64Signature));
	}

	private void updateNotaryServers() {
		if (notaryHosts == null)
			notaryHosts = new HashMap<>();

		int index = 0;
		while (true) {
			String host = getParam(index + ".server");
			String publicKey = getParam(index + ".publicKey");
			if (!isParamValueSet(host) && !isParamValueSet(publicKey))
				break;

			if (!host.substring(0,4).equals("http"))
				host = "http://" + host;

			notaryHosts.put(host, publicKey);
			index++;
		}
	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {
		if (notaryHosts == null)
			updateNotaryServers();

		log.trace("-- BEGIN -- PerspectivesNotary.check()");

		String host = tls.getRemoteHost();
		int port = tls.getRemotePort();
		if (port == -1)
			port = 443;

		Client client = Client.create();
		client.setConnectTimeout(Integer.valueOf(getParam("timeout")));

		List<Future<NotaryReply>> futures = new ArrayList<>(notaryHosts.size());

		for (String notaryHost : notaryHosts.keySet())
			futures.add(client
				.asyncResource(notaryHost)
				.queryParam("host", host)
				.queryParam("port", String.valueOf(port))
				.queryParam("service_type", "2")
				.get(NotaryReply.class));

		List<NotaryReply> responses = new ArrayList<>(notaryHosts.size());
		for (Future<NotaryReply> future : futures)
			try {
				responses.add(future.get());
			}
			catch (InterruptedException | ExecutionException e) {
				log.info("Java Exception thrown: " + e);
				responses.add(null);
			}

		for (NotaryReply response : responses)
			if (response != null) {
				// TODO: verify response signature and interpret responses
			}

		client.getExecutorService().shutdown();
		client.destroy();

		log.trace("-- BEGIN -- PerspectivesNotary.check()");
		return 0;
	}
}
