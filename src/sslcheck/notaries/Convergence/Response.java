package sslcheck.notaries.Convergence;

import java.util.ArrayList;
import java.util.List;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;

/**
 * Generated using http://www.jsonschema2pojo.org/
 * 
 * @author letzkus
 *
 */
@JsonPropertyOrder({ "fingerprintList", "signature" })
public class Response {

	@JsonProperty("fingerprintList")
	private List<Fingerprint> fingerprintList = new ArrayList<Fingerprint>();
	@JsonProperty("signature")
	private String signature;

	@JsonProperty("fingerprintList")
	public List<Fingerprint> getFingerprintList() {
		return fingerprintList;
	}

	@JsonProperty("fingerprintList")
	public void setFingerprintList(List<Fingerprint> fingerprintList) {
		this.fingerprintList = fingerprintList;
	}

	@JsonProperty("signature")
	public String getSignature() {
		return signature;
	}

	@JsonProperty("signature")
	public void setSignature(String signature) {
		this.signature = signature;
	}

}
