package sslcheck.notaries.Convergence;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;

/**
 * Generated using http://www.jsonschema2pojo.org/
 * 
 * @author letzkus
 * 
 */
@JsonPropertyOrder({ "start", "finish" })
public class Timestamp {

	@JsonProperty("start")
	private String start;
	@JsonProperty("finish")
	private String finish;

	@JsonProperty("start")
	public String getStart() {
		return start;
	}

	@JsonProperty("start")
	public void setStart(String start) {
		this.start = start;
	}

	@JsonProperty("finish")
	public String getFinish() {
		return finish;
	}

	@JsonProperty("finish")
	public void setFinish(String finish) {
		this.finish = finish;
	}
}
