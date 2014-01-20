package sslcheck.notaries;

import java.io.IOException;
import java.util.ArrayList;

public class NotaryManager {

	ArrayList<Notary> notaries;
	NotaryConfiguration notaryConf;
	NotaryRating notaryRating;
	
	public NotaryManager() {
		this.notaries = new ArrayList<Notary>();
		this.notaryRating = NotaryRating.getInstance();
		try {
			this.notaryConf = new NotaryConfiguration();
		} catch (IOException e) {
			e.printStackTrace();
		}	
	}
	
	public void addNotary(Notary n) {
		if(n!=null) {
			this.notaries.add(n);
			n.configure(notaryConf);
		}		
	}
	
	public void checkNotaries(SSLInfo sslinfo) { // TODO maybe this can be executed in parallel?
		for (Notary n : this.notaries) {
			notaryRating.addRating(n.getNotaryName(),n.check(sslinfo));
		}
	}
	
	public void clearNotaryList() {
		this.notaries.clear();
	}
}
