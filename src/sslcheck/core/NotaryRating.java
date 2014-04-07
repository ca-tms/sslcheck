package sslcheck.core;

import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NotaryRating {

	private NotaryConfiguration notaryConf;
	private static NotaryRating instance = null;
	private HashMap<Integer, HashMap<String, Float>> ratings = new HashMap<Integer, HashMap<String, Float>>(); // <ConnectionID,
																												// CumulatedRating>

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

			if (this.notaryConf.getValue("countable", notary).equals("false")) {
				log.info("Rating for " + notary + " not added.");
				return;
			}

			float minRating = Float.parseFloat(this.notaryConf.getValue(
					"minRating", notary));
			float maxRating = Float.parseFloat(this.notaryConf.getValue(
					"maxRating", notary));
			float ratingFactor = Float.parseFloat(this.notaryConf.getValue(
					"ratingFactor", notary));

			// Es gibt immer einen kleinsten Wert.
			if (f < minRating)
				f = minRating;
			// Es gibt immer einen groeßten Wert.
			if (f > maxRating)
				f = maxRating;

			log.debug("Adding Rating for Connection (" + Integer.toString(i)
					+ ") and Notary " + notary + ": " + Float.toString(f)
					+ " [max: " + Float.toString(maxRating) + " | min: "
					+ Float.toString(minRating) + "]");

			f = normalizeResult(notary, f); // Normalisierung, um eine
											// Verrechnung mit anderen Notaries
											// zu ermöglichen
			log.debug("Normalized result: " + Float.toString(f));

			synchronized (this.ratings) {
				if (this.ratings.containsKey(i)) {
					HashMap<String, Float> rs = this.ratings.get(i);
					float r = f * ratingFactor;
					rs.put(notary, r);
					this.ratings.put(i, rs);
				} else {
					HashMap<String, Float> rs = new HashMap<String, Float>();
					float r = f * ratingFactor;
					rs.put(notary, r);
					this.ratings.put(i, rs);
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

	public float calculateScore(int h) throws NotaryRatingException {
		return this.getScore(h);
	}

	public float getScore(int i) throws NotaryRatingException {
		float r = 0;
		if (this.ratings.get(i) != null && this.ratings.get(i).size() > 0) {
			HashMap<String, Float> rs = this.ratings.get(i);
			for (float rating : rs.values()) {
				// Calculate cumulative result
				r += rating;
			}
			r /= this.ratings.get(i).size();
		} else
			throw new NotaryRatingException(
					"There were no notaries to calculate a valid score.");
		// this.ratings.remove(i);
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

	public boolean isPossiblyTrusted(int ident) throws NotaryRatingException {
		try {
			int max = Integer.parseInt(this.notaryConf.getValue("maxRating"));
			float trustLimit = Float.parseFloat(this.notaryConf
					.getValue("trustLimit"));
			String trustMode = this.notaryConf.getValue("trustMode");
			float threshold = max * trustLimit;
			synchronized (this.ratings) {
				if (this.ratings.get(ident) != null
						&& this.ratings.get(ident).size() > 0) {
					boolean minority = false, consensus = false, majority = false;
					int countMaj = this.ratings.get(ident).size() / 2;
					if (this.ratings.get(ident).size() % 2 == 1)
						countMaj++;
					int countTrust = 0;
					for (Float rating : this.ratings.get(ident).values()) {
						if (rating >= threshold) {
							minority = true;
							countTrust++;
							if (countTrust > countMaj) {
								majority = true;
							}
							if (countTrust == this.ratings.get(ident).size()) {
								consensus = true;
							}
						}

					}
					switch (trustMode) {
					case "minority":
						return minority;
					case "majority":
						return majority;
					case "consensus":
						return consensus;
					default:
						return false;
					}
				} else
					throw new NotaryRatingException(
							"No ratings available to decide trustworthyness.");
			}
		} catch (NumberFormatException e) {
			log.error("Error converting value to int or float in isPossiblyTrusted");
			throw new NotaryRatingException("Internal Error -> not decidable: "
					+ e);
		} catch (NotaryConfigurationException e) {
			log.error("Error reading maxRating/trustLimit from Configuration in isPossiblyTrusted.");
			throw new NotaryRatingException("Internal Error -> not decidable!");
		}
	}
}
