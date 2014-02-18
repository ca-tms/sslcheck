package sslcheck.core;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.notaries.Notary;
import sslcheck.system.SSLInfo;

public class NotaryManager extends Notary {

	ArrayList<Notary> notaries;
	Iterator<Notary> iterNot;
	NotaryConfiguration notaryConf;
	NotaryRating notaryRating;
	
	private final static Logger log = LogManager.getLogger("core.NotaryManager");

	public NotaryManager() {
		this.notaries = new ArrayList<Notary>();
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

	public void addNotary(Notary n) {
		if (n != null) {
			this.notaries.add(n);
		}
	}

	public void clearNotaryList() {
		this.notaries.clear();
	}

	private void _checkNotaries(SSLInfo sslinfo) { // TODO maybe this can be
													// executed in parallel?
		for (Notary n : this.notaries) {
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
