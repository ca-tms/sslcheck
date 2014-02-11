package sslcheck.notaries;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

public class NotaryManager extends Notary {

	ArrayList<Notary> notaries;
	Iterator<Notary> iterNot;
	NotaryConfiguration notaryConf;
	NotaryRating notaryRating;
	
	public NotaryManager() {
		this.notaries = new ArrayList<Notary>();
		this.notaryRating = NotaryRating.getInstance();
		try {
			this.notaryConf = new NotaryConfiguration();
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		for(String notary : this.notaryConf.getNotariesFromConfiguration()) {
			if(this.notaryConf.isEnabled(notary)) {
				try {
					Notary n = (Notary) Class.forName("sslcheck.notaries."+notary).newInstance();
					n.setNotaryName(this.notaryConf.getName(notary));
					this.addNotary(n);
				} catch (InstantiationException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	public void addNotary(Notary n) {
		if(n!=null) {
			this.notaries.add(n);
		}		
	}
	
	public void checkNotaries(SSLInfo sslinfo) { // TODO maybe this can be executed in parallel?
		for (Notary n : this.notaries) {
			notaryRating.addRating(n.getNotaryName(),n.check(sslinfo));
		}
	}
	
	public Iterator<Notary> notaryIterator() {
		return this.notaries.iterator();
	}
	
	public void clearNotaryList() {
		this.notaries.clear();
	}

	@Override
	public int check(SSLInfo sslinfo) {
		// TODO Auto-generated method stub
		return 0;
	}
}
