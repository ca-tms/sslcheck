package sslcheck.notaries;

import java.util.ArrayList;

public class NotaryRating { 
	
	private NotaryConfiguration notaryConf;
	private static NotaryRating instance = null;
	
	public static NotaryRating getInstance() { // NotarRating is a singleton!!
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
		this.ratings.add(result*this.notaryConf.getRatingFactor(notary));
	}
	
	public void clear() {
		this.ratings.clear();
	}
	
	public int calculateScore() {
		return 0;
	}

	public int normalizeResult(String notary, int check) {
		int max = this.notaryConf.getMaxRating(notary);
		int min = this.notaryConf.getMinRating(notary);
		return (max-min)*check+min;
	}

}
