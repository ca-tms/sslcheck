package sslcheck.notaries;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
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
	    @XmlElement(name="key") public Observation[] observations;
	    @XmlAttribute(name="version") public String version;
	    @XmlAttribute(name="sig") public String signature;
	    @XmlAttribute(name="sig_type") public String signatureType;
	}

	public static class Observation {
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
	private List<String> notaryHosts;
	private List<PublicKey> notaryKeys;

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
			byte[] data) {
		try {
			signature.initVerify(publicKey);
			signature.update(data);
			return signature.verify(DatatypeConverter.parseBase64Binary(
					base64Signature));
		}
		catch (InvalidKeyException | SignatureException e) {
			log.error("Java exception thrown verifying signature: " + e);
			return false;
		}
	}

	private void updateNotaryServers() throws NotaryException {
		if (notaryHosts == null || notaryKeys == null) {
			notaryHosts = new ArrayList<>();
			notaryKeys = new ArrayList<>();
		}

		int index = 0;
		while (true) {
			String host = getParam(index + ".server");
			String publicKey = getParam(index + ".publicKey");

			if (!isParamValueSet(host) && !isParamValueSet(publicKey))
				break;

			if (isParamValueSet(host) != isParamValueSet(publicKey))
				throw new NotaryException(
					"Missing host or public key parameter for " +
					"Perspectives notary (index" + index + ")");

			if (!host.substring(0,4).equals("http"))
				host = "http://" + host;

			try {
				notaryKeys.add(publicKeyFromString(publicKey));
				notaryHosts.add(host);
			}
			catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new NotaryException("Exception: " + e);
			}

			index++;
		}
	}

	@Override
	public float check(TLSConnectionInfo tls) throws NotaryException {
		if (notaryHosts == null)
			updateNotaryServers();

		log.trace("-- BEGIN -- PerspectivesNotary.check()");

		final long quorumNotariesCount = Long.valueOf(getParam("quorum.notariesCount"));
		final long quorumDurationMillis = Long.valueOf(getParam("quorum.durationMillis"));
		final long quorumDistanceMillis = Long.valueOf(getParam("quorum.distanceMillis"));
		final String fingerprint = tls.getCertificates().getMD5Fingerprint().toLowerCase();

		// initialize request parameters
		String host = tls.getRemoteHost();
		int port = tls.getRemotePort();
		if (port == -1)
			port = 443;
		int serviceType = 2;

		Client client = Client.create();
		client.setConnectTimeout(Integer.valueOf(getParam("timeout")));

		// perform asynchronous requests
		List<Future<NotaryReply>> futures = new ArrayList<>(notaryHosts.size());
		for (String notaryHost : notaryHosts)
			futures.add(client
				.asyncResource(notaryHost)
				.path("/")
				.queryParam("host", host)
				.queryParam("port", String.valueOf(port))
				.queryParam("service_type", String.valueOf(serviceType))
				.get(NotaryReply.class));

		// wait for all replies
		List<NotaryReply> replies = new ArrayList<>(notaryHosts.size());
		for (Future<NotaryReply> future : futures)
			try {
				replies.add(future.get());
			}
			catch (InterruptedException | ExecutionException e) {
				log.info("Java Exception thrown: " + e);
				replies.add(null);
			}

		client.getExecutorService().shutdown();
		client.destroy();

		// verify signature for all replies
		// add all valid replies to the responses list
		List<NotaryReply> responses = new ArrayList<>(notaryHosts.size());
		for (int i = 0, length = replies.size(); i < length; i++) {
			NotaryReply reply = replies.get(i);
			PublicKey key = notaryKeys.get(i);

			if (reply == null) {
				log.info("No response from " + notaryHosts.get(i));
				continue;
			}

			final byte[] serviceId =
				(host + ":" + port + "," + serviceType).getBytes(Charsets.UTF_8);

			// the signature is computed over the following binary data
			// (numbers are in big endian / network byte order):
			// - service-id (variable length, terminated with null-byte)
			//   host:port,service_type
			// - list of observations (in reverse order); each observation has:
			//   - number of timespans [2 bytes]
			//   - fingerprint size in bytes [2 bytes]
			//     always has value of 16 for now since MD5 fingerprint is used
			//   - type [1 byte]
			//     always has a value of 3 for SSL
			//   - fingerprint data
			//   - list of timespan start-end pairs
			//     [2 * 4 * (number of timespans) bytes]
			int capacity = serviceId.length + 1;
			for (Observation observation : reply.observations)
				capacity += 2 + 2 + 1 + 16 +
				            2 * 4 * observation.timestamps.length;

			ByteBuffer buffer = ByteBuffer.allocate(capacity);

			buffer.put(serviceId);
			buffer.put((byte) 0);
			for (int j = reply.observations.length - 1; j >= 0; j--) {
				Observation observation = reply.observations[j];

				buffer.putShort((short) observation.timestamps.length);
				buffer.putShort((short) 16);
				buffer.put((byte) 3);

				observation.fingerprint = observation.fingerprint
						.toLowerCase().replaceAll("[^0-9a-f]", "");
				if (observation.fingerprint.length() == 2 * 16)
					for (int k = 0; k < observation.fingerprint.length(); k += 2)
						buffer.put((byte) (short) Short.valueOf(
								observation.fingerprint.substring(k, k + 2), 16));

				for (Timestamp timestamp : observation.timestamps) {
					buffer.putInt((int) timestamp.start);
					buffer.putInt((int) timestamp.end);
				}
			}

			buffer.flip();
			byte[] data = new byte[buffer.limit()];
			buffer.get(data);

			if (verifySignature(key, reply.signature, data))
				responses.add(reply);
			else
				log.info("Signature from " + notaryHosts.get(i) +
				         " could not be verified");
		}

		// count notaries which satisfy the quorum duration constraint
		// and check if the count satisfies the quorum count constraint
		float count = 0;
		long nowMillis = new Date().getTime();
		for (NotaryReply response : responses)
			for (Observation observation : response.observations)
				if (observation.fingerprint.equals(fingerprint)) {
					float score = 0;
					for (Timestamp timestamp : observation.timestamps) {
						// convert timestamps from s to ms
						long start = timestamp.start * 1000;
						long end = timestamp.end * 1000;

						// For every notary that has seen the certificate
						// for the quorum duration time span, increment count
						// by one.
						// Additionally, for every notary that has seen the
						// certificate for a fraction of the quorum duration
						// time span, increment count by that fraction.
						if (nowMillis - end <= quorumDistanceMillis)
							score = Math.max(score, Math.min(1,
									(float) (end - start) / quorumDurationMillis));
					}
					count += score;
					break;
				}
		count = Math.min(1, count / quorumNotariesCount);

		log.trace("-- BEGIN -- PerspectivesNotary.check()");

		return Math.min(1, count);
	}
}
