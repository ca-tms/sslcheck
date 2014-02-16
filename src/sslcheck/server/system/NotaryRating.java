package sslcheck.server.system;

import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NotaryRating { 
	
	private NotaryConfiguration notaryConf;
	private static NotaryRating instance = null;
	
	private final static Logger log = LogManager.getLogger("NotaryRating");
	
	public static NotaryRating getInstance() { // NotaryRating is a singleton!!
		if(instance == null)
			return new NotaryRating();
		return instance;
	}
	
	public NotaryRating() {
		this.notaryConf = NotaryConfiguration.getInstance();
	}

	private ArrayList<Float> ratings = new ArrayList<Float>();
	
	public void addRating(String notary, int result) throws NotaryRatingException {
		result = normalizeResult(notary, result);
		try {
			this.ratings.add(result*((Float.parseFloat(this.notaryConf.getValue("ratingFactor", notary)))));
		} catch (NumberFormatException e) {
			log.error("Error converting value to float");
			throw new NotaryRatingException("Error while converting during adding the rating of "+notary);
		} catch (NotaryConfigurationException e) {
			log.error("Error reading ratingFactor from Configuration.");
			throw new NotaryRatingException("Error reading configuration properties during adding the rating of "+notary);
		}
	}
	
	public void clear() {
		this.ratings.clear();
	}
	
	public int calculateScore() {
		return 0;
	}

	public int normalizeResult(String notary, int check) throws NotaryRatingException {
		int max;
		int min;
		try {
			max = Integer.parseInt(this.notaryConf.getValue("maxRating",notary));
			min = Integer.parseInt(this.notaryConf.getValue("minRating",notary));
			return (max-min)*check+min;
		} catch (NumberFormatException e) {
			log.error("Error converting value to int");
			throw new NotaryRatingException("Error while converting during normalization.");
		} catch (NotaryConfigurationException e) {
			log.error("Error reading min/maxRating from Configuration.");
			throw new NotaryRatingException("Error reading configuration properties during normalization.");
		}
	}

}
