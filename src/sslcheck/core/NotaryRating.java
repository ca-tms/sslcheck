package sslcheck.core;

import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NotaryRating {

	private NotaryConfiguration notaryConf;
	private static NotaryRating instance = null;
	private ArrayList<Float> ratings = new ArrayList<Float>();
	private float _RATING_ = -1f;

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

	public void addRating(String notary, float f) throws NotaryRatingException {
		try {

			log.debug("Adding Rating for " + notary + ": " + Float.toString(f)
					+ " [max: " + this.notaryConf.getValue("maxRating", notary)
					+ " | min: "
					+ this.notaryConf.getValue("minRating", notary) + "]");
			f = normalizeResult(notary, f); // Normalisierung, um eine
											// Verrechnung mit anderen Notaries
											// zu ermöglichen
			synchronized (this.ratings) {
				this.ratings.add(f
						* ((Float.parseFloat(this.notaryConf.getValue(
								"ratingFactor", notary)))));
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

	public void clear() {
		synchronized (this.ratings) {
			this.ratings.clear();
		}
	}

	public float calculateScore() {
		synchronized (this.ratings) {
			float r = 0;
			for (float f : this.ratings)
				r += f;
			if (this.ratings.size() > 0)
				this._RATING_ = r / this.ratings.size(); // (r1 + r2 + r3 + ...
															// +
															// rn)/n
			else
				this._RATING_ = 0;
			return this._RATING_;
		}
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

	public boolean isPossiblyTrusted() throws NotaryRatingException {
		try {
			int max = Integer.parseInt(this.notaryConf.getValue("maxRating"));
			float trustLimit = Float.parseFloat(this.notaryConf
					.getValue("trustLimit"));
			synchronized (this.ratings) {
				if (this._RATING_ < 0)
					return this.calculateScore() > max * trustLimit;
				return this._RATING_ > max * trustLimit;
			}

		} catch (NumberFormatException e) {
			log.error("Error converting value to int or float in isPossiblyTrusted");
			throw new NotaryRatingException(
					"Error while converting during isPoissibleTrusted.");
		} catch (NotaryConfigurationException e) {
			log.error("Error reading maxRating/trustLimit from Configuration in isPossiblyTrusted.");
			throw new NotaryRatingException(
					"Error reading configuration properties during isPossiblyTrusted.");
		}
	}
}
