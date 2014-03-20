package sslcheck.core;

import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NotaryRating {

	private NotaryConfiguration notaryConf;
	private static NotaryRating instance = null;
	private HashMap<Integer, Float> ratings = new HashMap<Integer, Float>();

	private final static Logger log = LogManager.getLogger("core.NotaryRating");

	public static NotaryRating getInstance() { // NotaryRating is a singleton!!
		if (instance == null)
			instance = new NotaryRating();
		return instance;
	}

	public NotaryRating() {
		log.debug("Loading Configuration...");
		this.notaryConf = NotaryConfiguration.getInstance();
	}

	public void addRating(Integer i, String notary, float f)
			throws NotaryRatingException {
		try {

			log.debug("Adding Rating for Connection " + Integer.toString(i) + " and Notary " + notary + ": "
					+ Float.toString(f) + " [max: "
					+ this.notaryConf.getValue("maxRating", notary)
					+ " | min: "
					+ this.notaryConf.getValue("minRating", notary) + "]");
			f = normalizeResult(notary, f); // Normalisierung, um eine
											// Verrechnung mit anderen Notaries
											// zu ermöglichen
			log.debug("Normalized result: " + Float.toString(f));
			synchronized (this.ratings) {
				if (this.ratings.containsKey(i)) {
					float r = this.ratings.get(i);
					r += f
							* ((Float.parseFloat(this.notaryConf.getValue(
									"ratingFactor", notary))));
					r /= 2;
					//this.ratings.remove(host);
					this.ratings.put(i, r);
				} else {
					this.ratings
							.put(i,
									f
											* ((Float.parseFloat(this.notaryConf
													.getValue("ratingFactor",
															notary)))));
				}
			}
		} catch (NumberFormatException e) {
			log.error("Error converting value to float");
			throw new NotaryRatingException(
					"Error while converting during adding the rating of "
							+ notary);
		} catch (NotaryConfigurationException e) {
			log.error("Error reading ratingFactor from Configuration.");
			throw new NotaryRatingException(
					"Error reading configuration properties during adding the rating of "
							+ notary);
		}
	}

	public void clear(int ident) {
		synchronized (this.ratings) {
			this.ratings.remove(ident);
		}
	}

	@Deprecated
	public float calculateScore(int h) {
		return this.getScore(h);
	}
	
	public float getScore(int i) {
		float r = this.ratings.get(i);
		//this.ratings.remove(i);
		return r;
	}

	public float normalizeResult(String notary, float f)
			throws NotaryRatingException {
		int max_default, max_notary;
		int min_default, min_notary;
		try {
			max_default = Integer.parseInt(this.notaryConf
					.getValue("maxRating"));
			min_default = Integer.parseInt(this.notaryConf
					.getValue("minRating"));
			max_notary = Integer.parseInt(this.notaryConf.getValue("maxRating",
					notary));
			min_notary = Integer.parseInt(this.notaryConf.getValue("minRating",
					notary));
			return (max_default - min_default) * (f - min_notary)
					/ (max_notary - min_notary) + min_default;
		} catch (NumberFormatException e) {
			log.error("Error converting value to int");
			throw new NotaryRatingException(
					"Error while converting during normalization.");
		} catch (NotaryConfigurationException e) {
			log.error("Error reading min/maxRating from Configuration.");
			throw new NotaryRatingException(
					"Error reading configuration properties during normalization.");
		}
	}

	public boolean isPossiblyTrusted(int ident) {
		try {
			int max = Integer.parseInt(this.notaryConf.getValue("maxRating"));
			float trustLimit = Float.parseFloat(this.notaryConf
					.getValue("trustLimit"));
			synchronized (this.ratings) {
				return this.getScore(ident) > max * trustLimit;
			}

		} catch (NumberFormatException e) {
			log.error("Error converting value to int or float in isPossiblyTrusted");
			return false;
		} catch (NotaryConfigurationException e) {
			log.error("Error reading maxRating/trustLimit from Configuration in isPossiblyTrusted.");
			return false;
		}
	}
}
