package sslcheck.core;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.notaries.Notary;
import sslcheck.system.X509Certificate;

/**
 * NotaryManager acts as a proxy class for normal notaries. It creates every
 * enabled notary-objects and calls the check-Method to check the certificate
 * the notaryManager gets from the caller itself.
 * 
 * It enables a caller to handle multiple notaries by just using one notary. It
 * itself can be used as a notary.
 * 
 * @author letzkus
 * 
 */
public class NotaryManager extends Notary {

	ArrayList<Notary> notaries;
	ArrayList<Notary> enabledNotaries;
	Iterator<Notary> iterNot;
	NotaryConfiguration notaryConf;
	NotaryRating notaryRating;

	private final static Logger log = LogManager
			.getLogger("core.NotaryManager");

	/**
	 * The constructor initializes the notaries based on the
	 * notaries.properties-File.
	 */
	public NotaryManager() {
		this.setNotaryName("NotaryManager"); // We have to set the name
												// manually, since it is not
												// initialized using the
												// configuration
		this.notaries = new ArrayList<Notary>();
		this.enabledNotaries = new ArrayList<Notary>();
		this.notaryRating = NotaryRating.getInstance();
		try {
			log.trace("Loading Configuration...");
			this.notaryConf = NotaryConfiguration.getInstance();
			log.trace("Adding notaries...");
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

	/**
	 * Enables a already existing notary. If you want to simply add a new
	 * notary, use addNotary(Notary n).
	 * 
	 * @param nn
	 *            The name of a notary to be enabled.
	 */
	public void enableNotary(String nn) {
		for (Notary n : this.notaries) {
			if (n.getNotaryName().equals(nn)) {
				this.enabledNotaries.add(n);
				return;
			}
		}
		log.error("Enabling Notary " + nn + " failed: Notary not found.");
	}

	/**
	 * Disables a notary.
	 * 
	 * @param nn
	 *            the name of the notary to be disabled.
	 */
	public void disableNotary(String nn) {
		for (Notary n : this.enabledNotaries) {
			if (n.getNotaryName().equals(nn)) {
				if (!this.enabledNotaries.remove(n))
					log.error("Disabling Notary " + nn + " failed.");
				return;
			}
		}
	}

	/**
	 * Adds a new notary to the list of existing and enabled notaries.
	 * 
	 * @param n
	 *            the notary object to be added
	 */
	public void addNotary(Notary n) {
		if (n != null) {
			log.trace("Adding notary " + n.getNotaryName());
			this.notaries.add(n);
			this.enabledNotaries.add(n); // All notaries enabled by default
		}
	}

	/**
	 * Checks the certificate by calling check-Method on all enabled Notaries
	 * 
	 * @param c
	 *            the X509Certificate to check
	 * @return Validity score
	 */
	@Override
	public float check(X509Certificate c) {
		for (Notary n : this.enabledNotaries) {
			try {
				log.trace("-- BEGIN -- Checking notary " + n.getNotaryName());
				notaryRating.addRating(n.getNotaryName(), n.check(c));
				log.trace("-- END -- Checking notary " + n.getNotaryName());
			} catch (NotaryRatingException e) {
				log.error(e.getMessage());
			}
		}
		return notaryRating.calculateScore();
	}
}
