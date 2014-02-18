package sslcheck.core;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.notaries.Notary;
import sslcheck.system.SSLInfo;

public class NotaryManager extends Notary {

	ArrayList<Notary> notaries;
	ArrayList<Notary> enabledNotaries;
	Iterator<Notary> iterNot;
	NotaryConfiguration notaryConf;
	NotaryRating notaryRating;
	
	private final static Logger log = LogManager.getLogger("core.NotaryManager");

	public NotaryManager() {
		this.notaries = new ArrayList<Notary>();
		this.enabledNotaries = new ArrayList<Notary>();
		this.notaryRating = NotaryRating.getInstance();
		try {
			log.trace("Loading Configuration...");
			this.notaryConf = NotaryConfiguration.getInstance();
			for (String notary : this.notaryConf.getNotariesFromConfiguration()) {
				if (this.notaryConf.getValue("enabled", notary).equals("true")) {
					Notary n = (Notary) Class.forName(
							"sslcheck.notaries." + notary).newInstance();
					n.setNotaryName(this.notaryConf.getName(notary));
					this.addNotary(n);

				}
			}
		} catch (InstantiationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotaryConfigurationException e) {
			log.error("Error reading enabled-Value from Configuration.");
		}
	}
	
	public void enableNotary(String nn) {
		for(Notary n : this.notaries){
			if(n.getNotaryName().equals(nn)){
				this.enabledNotaries.add(n);
				break;
			}
		}
	}
	
	public void disableNotary(String nn) {
		for(Notary n : this.enabledNotaries){
			if(n.getNotaryName().equals(nn)){
				if(!this.enabledNotaries.remove(n))
					log.error("Disabling Notary "+nn+" failed.");
				break;
			}
		}
	}

	public void addNotary(Notary n) {
		if (n != null) {
			this.notaries.add(n);
			this.enabledNotaries.add(n); // All notaries enabled by default
		}
	}

	private void _checkNotaries(SSLInfo sslinfo) { // TODO maybe this can be
													// executed in parallel?
		for (Notary n : this.enabledNotaries) {
			try {
				log.trace("Checking notary "+n.getNotaryName());
				notaryRating.addRating(n.getNotaryName(), n.check(sslinfo));
			} catch (NotaryRatingException e) {
				log.error(e.getMessage());
			}
		}
	}

	@Override
	public float check(SSLInfo sslinfo) {
		this._checkNotaries(sslinfo);
		return notaryRating.calculateScore();
	}
}
