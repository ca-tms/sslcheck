package sslcheck.notaries.Convergence;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;

/**
 * Generated using http://www.jsonschema2pojo.org/
 * 
 * @author letzkus
 * 
 */
@JsonPropertyOrder({ "timestamp", "fingerprint" })
public class Fingerprint {

	@JsonProperty("timestamp")
	private Timestamp timestamp;
	@JsonProperty("fingerprint")
	private String fingerprint;

	@JsonProperty("timestamp")
	public Timestamp getTimestamp() {
		return timestamp;
	}

	@JsonProperty("timestamp")
	public void setTimestamp(Timestamp timestamp) {
		this.timestamp = timestamp;
	}

	@JsonProperty("fingerprint")
	public String getFingerprint() {
		return fingerprint;
	}

	@JsonProperty("fingerprint")
	public void setFingerprint(String fingerprint) {
		this.fingerprint = fingerprint;
	}

}
