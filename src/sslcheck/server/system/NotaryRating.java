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
	
	public void addRating(String notary, int result) {
		result = normalizeResult(notary, result);
		try {
			this.ratings.add(result*((Float.parseFloat(this.notaryConf.getValue("ratingFactor", notary)))));
		} catch (NumberFormatException e) {
			log.error("Error converting value to float");
			e.printStackTrace();
		} catch (NotaryConfigurationException e) {
			log.error("Error reading ratingFactor from Configuration.");
		}
	}
	
	public void clear() {
		this.ratings.clear();
	}
	
	public int calculateScore() {
		return 0;
	}

	public int normalizeResult(String notary, int check) {
		int max;
		int min;
		try {
			max = Integer.parseInt(this.notaryConf.getValue("maxRating",notary));
			min = Integer.parseInt(this.notaryConf.getValue("minRating",notary));
			return (max-min)*check+min;
		} catch (NumberFormatException e) {
			log.error("Error converting value to int");
			e.printStackTrace();
		} catch (NotaryConfigurationException e) {
			log.error("Error reading min/maxRating from Configuration.");
			e.printStackTrace();
		}
		return 0;
		
	}

}
