package sslcheck.core;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import sslcheck.notaries.Notary;
import sslcheck.notaries.NotaryException;

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
	ArrayList<X509TrustManager> trustManagers = new ArrayList<X509TrustManager>();

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

					// Create Instance
					Notary n = (Notary) Class.forName(
							"sslcheck.notaries." + notary).newInstance();

					// Set name and configuration and initialize
					n.setNotaryName(this.notaryConf.getName(notary));
					n.setConfiguration(this.notaryConf
							.getNotaryConfiguration(this.notaryConf
									.getName(notary)));
					n.initialize();

					// Get TrustManagers if available
					if (n.hasTrustManager()) {
						log.debug("Adding TrustManager for "
								+ n.getNotaryName());
						trustManagers.add(n.getTrustManager());
					}

					// Add Notary to list of available notaries
					this.addNotary(n);

				}
			}
			// Add TrustManagers

			this.setTrustManager(new X509TrustManager() {

				@Override
				public void checkClientTrusted(X509Certificate[] arg0,
						String arg1) throws CertificateException {
					int unsuccessful = 0;
					for (X509TrustManager tm : trustManagers)
						try {
							tm.checkClientTrusted(arg0, arg1);
						} catch (CertificateException e) {
							unsuccessful++;
						}
					if (unsuccessful == trustManagers.size()) {
						throw new CertificateException(
								"No TrustManager found for this certificate.");
					}
				}

				@Override
				public void checkServerTrusted(X509Certificate[] arg0,
						String arg1) throws CertificateException {
					int unsuccessful = 0;
					for (X509TrustManager tm : trustManagers) {
						try {
							tm.checkServerTrusted(arg0, arg1);
						} catch (CertificateException e) {
							unsuccessful++;
						}
					}
					if (unsuccessful == trustManagers.size()) {
						throw new CertificateException(
								"No TrustManager found for this certificate.");
					}

				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
					X509Certificate[] accIss;
					for (X509TrustManager tm : trustManagers) {
						accIss = tm.getAcceptedIssuers();
						if (accIss != null && accIss.length > 0)
							for (X509Certificate c : accIss)
								certs.add(c);
					}
					if (certs.size() > 0) {
						X509Certificate result[] = new X509Certificate[certs
								.size()];
						return certs.toArray(result);
					} else {
						return null;
					}
				}

			});
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
		if (n != null && !n.getNotaryName().equals("")) {
			log.trace("Adding notary " + n.getNotaryName());
			this.notaries.add(n);
			this.enabledNotaries.add(n); // All notaries enabled by default
		} else {
			log.error("Notary was not added, because there Object was null or name was not set.");
		}
	}

	/**
	 * Checks the certificate by calling check-Method on all enabled Notaries
	 * 
	 * @param tls Information regarding the tls connection, e.g. certificates,
	 *            host, port
	 * @return Validity score
	 * @throws NotaryException
	 */
	@Override
	public float check(final TLSConnectionInfo tls) throws NotaryException {
		final int id = tls.hashCode();

		if (!this.enabledNotaries.isEmpty() &&
				this.notaryConf.getValue("concurrentChecks").equals("true"))
		{
			ExecutorService executor =
					Executors.newFixedThreadPool(this.enabledNotaries.size());
			try {
				List<Callable<Void>> tasks = new ArrayList<>(this.enabledNotaries.size());
				for (final Notary notary : this.enabledNotaries)
					tasks.add(new Callable<Void>() {
						@Override
						public Void call() {
							check(tls, 0, notary);
							return null; // dummy value for Void return type
						}
					});
				executor.invokeAll(tasks);
			}
			catch (InterruptedException e) {
				throw new NotaryException("Concurrent notary queries interrupted");
			}
			finally {
			    executor.shutdown();
			}
		}
		else
			for (Notary notary : this.enabledNotaries)
				check(tls, 0, notary);

		return notaryRating.getScore(id);
	}

	/**
	 * Checks a single given notary for the given connection information and
	 * adds the rating for the given id
	 * @param tls
	 * @param id
	 * @param notary
	 */
	private void check(TLSConnectionInfo tls, int id, Notary notary) {
		log.trace("-- BEGIN -- Checking notary " + notary.getNotaryName());
		try {
			notaryRating.addRating(tls.hashCode(), notary.getNotaryName(),
					notary.check(tls));
		} catch (NotaryException e) {
			log.info("Error while checking Notary " + notary.getNotaryName()
					+ ". Will ommit notary. " + e);
		}
		log.trace("-- END -- Checking notary " + notary.getNotaryName());
	}
}
