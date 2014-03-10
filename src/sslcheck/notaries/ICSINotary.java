package sslcheck.notaries;

import java.net.UnknownHostException;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import sslcheck.core.TLSCertificate;

public class ICSINotary extends Notary {

	private final static Logger log = LogManager.getLogger("notaries.ICSI");

	@Override
	public float check(String h, TLSCertificate c) {
		float score = 0f;
		// First Phase, just print the certificate to check
		log.trace("-- BEGIN -- ICSINotary.check() ");

		try {
			score = this.checkNotary(c.getSHA1Fingerprint());
		} catch (UnknownHostException e) {
			log.error("UnknownHost: " + e);
		} catch (TextParseException e) {
			log.error("TextParse: " + e);
		}

		log.trace("-- DONE -- ICSINotary.check() ");

		return score;
	}

	/**
	 * Method as described in documentation
	 * 
	 * @param hash
	 * @return
	 * @throws UnknownHostException
	 * @throws TextParseException
	 * @see http://www.dnsjava.org/dnsjava-current/examples.html
	 */
	private float checkNotary(String hash) throws UnknownHostException,
			TextParseException {
		float result = 0f;
		log.trace("--- BEGIN --- Checking A-RR...");
		Lookup l = new Lookup(hash + ".notary.icsi.berkeley.edu", Type.A);
		Record[] records = l.run();
		if (l.getResult() != Rcode.NXDOMAIN && records.length > 0) {
			// --- 1 --- Checking A-RR
			for (int i = 0; i < records.length; i++) { // records.length == 1 ->
														// should always be
														// true...
				ARecord a = (ARecord) records[i];
				if (a.getAddress().getHostAddress().equals("127.0.0.1")) {
					result += 5;
					log.debug("A-RR = 127.0.0.1; Adding 5.");
				} else if (a.getAddress().getHostAddress().equals("127.0.0.2")) {
					result += 10;
					log.debug("A-RR = 127.0.0.2; Adding 10.");
				} else {
					log.error("Recieved malformed IPADDR"
							+ a.getAddress().getHostAddress());
				}				
			}
			result /= records.length; // if there were multiple A-RRs added,
										// calculate average.
			log.debug("Result after checking all A-RRs: " + Float.toString(result));
			log.trace("--- DONE --- Checking A-RR.");

			log.trace("--- BEGIN --- Checking TXT-RR.");
			// --- 2 --- Checking TXT-RR
			l = new Lookup(hash + ".notary.icsi.berkeley.edu", Type.TXT);
			records = l.run();
			String s = "";
			for (int i = 0; i < records.length; i++) {
				TXTRecord txt = (TXTRecord) records[i];
				for (Iterator<?> j = txt.getStrings().iterator(); j.hasNext();)
					s += j.next();
			}
			log.debug("TXT-RR = " + s);
			String[] params = s.split(" ");
			if (params.length != 5) {
				log.error("Recieved malformed txt-RR: " + s);
			} else {
				float result_last = 0, result_first = 0, result_times = 0;
				float last_seen = 0, first_seen = 0;
				for (String param : params) {// params should be: version=1
												// first_seen=15387
												// last_seen=15646
												// times_seen=260 validated=1
					String[] p = param.split("=");
					if (p.length != 2) {
						log.error("Recieved malformed txt-RR: " + s);
					} else {
						if (p[0].equals("version")) {
							// there is nothing to do here, since version does
							// not affect validity of result
							continue;
						} else if (p[0].equals("last_seen")) {
							// The older the certificate, the lower the score to
							// be added
							// Lowest Value: 15339
							// Highest Value: Today
							// ... but: Certificate first seen today means, that
							// the
							// certificate is not that old! This could possibly
							// be an attack!
							java.util.Date date = new java.util.Date();
							float max_seen = date.getTime() / 1000 / 60 / 60
									/ 24;
							float min_seen = max_seen - 30;
							last_seen = Float.parseFloat(p[1]);

							// [min_seen,max_seen] —> [0,10]
							result_last = 10 * (last_seen - min_seen)
									/ (max_seen - min_seen);
							if (result_last < 0)
								result_last = 0;

							log.debug("last_seen: (min,max,last,result) = ("
									+ min_seen + "," + max_seen + ","
									+ last_seen + "," + result_last + ")");

						} else if (p[0].equals("first_seen")) {
							// The older the certificate, the lower the score to
							// be added. Optimal "age" is 1 year, Maximum "age"
							// is 2 years.
							// For Pseudocode see Documentation.
							java.util.Date date = new java.util.Date();
							float max_seen = date.getTime() / 1000 / 60 / 60
									/ 24;

							float min_seen = max_seen - 2 * 356;
							float optimal_seen = max_seen - 356;
							first_seen = Long.parseLong(p[1]);

							if (first_seen == optimal_seen) {
								result_first = 10;
							} else if (first_seen > optimal_seen) {
								result_first = 10 - 10
										* (first_seen - optimal_seen)
										/ (max_seen - optimal_seen);
							} else {
								result_first = 10 * (first_seen - min_seen)
										/ (optimal_seen - min_seen);
							}

							log.debug("first_seen: (min,max,optimal,first,result) = ("
									+ min_seen
									+ ","
									+ max_seen
									+ ","
									+ optimal_seen
									+ ","
									+ first_seen
									+ ","
									+ result_first + ")");

						} else if (p[0].equals("times_seen")) {
							// The higher the certificate, the higher the score
							// to be added
							// Highest Value: last_seen - first_seen; today -
							// 15339
							// Lowest Value: 0
							float max_seen = 0, times_seen = 0;
							if (first_seen > 0 && last_seen > 0) {
								max_seen = last_seen - first_seen;
								times_seen = Float.parseFloat(p[1]);
								result_times = 10 * times_seen / max_seen;
							}

							log.debug("times_seen: (max,times,result) = ("
									+ max_seen + "," + times_seen + ","
									+ result_times + ")");

						} else if (p[0].equals("validated")) {
							// 1 -> Certificate can be validated using Mozilla
							// Root Store => +10
							// 0 -> Certificate can't be validated using Mozilla
							// Root Store => +0
							if (p[1].equals("1")) {
								result += 10;
							} // else: result+=0;
						} else {
							log.error("Recieved malformed part of txt-RR: " + p);
						}
					}
				}
				if (result_last > 0 && result_first > 0)
					result += result_last + result_first + result_times;
			}
			log.debug("Calculated score: " + result);
			log.trace("--- DONE --- Checking TXT-RR.");
		} else {
			log.error("Received NXDOMAIN for Hash " + hash + ".");
			log.trace("--- DONE --- Checking A-RR");
		}
		return result;
	}

}
