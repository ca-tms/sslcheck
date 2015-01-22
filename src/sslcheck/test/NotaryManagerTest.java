package sslcheck.test;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.sun.jersey.core.util.Base64;

import sslcheck.core.NotaryManager;
import sslcheck.core.NotaryRating;
import sslcheck.core.NotaryRatingException;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;
import sslcheck.notaries.Notary;
import sslcheck.notaries.NotaryException;
import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

public class NotaryManagerTest {
	
	/**
	 * Preconfigured Notaries 
	 */

	public Notary testNotaryResultTen = new Notary() {

		@Override
		public float check(TLSConnectionInfo tls) throws NotaryException {
			return 10;
		}

	};

	public Notary testNotaryResultZero = new Notary() {

		@Override
		public float check(TLSConnectionInfo tls) throws NotaryException {
			return 0;
		}

	};

	/**
	 *  Other preconfigured objects
	 */
	
	public TLSConnectionInfo _getTLSInfo() {
		CertificateFactory cf;
		TLSConnectionInfo tlsi = null;

		try {
			cf = CertificateFactory.getInstance("X.509");

			String base64Cert = "MIIDmzCCAoOgAwIBAgIJAPDxpOSQbn4wMA0GCSqGSIb3DQEBBQUAMGQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKDApHb29nbGUgSW5jMRMwEQYDVQQDDApnb29nbGUuY29tMB4XDTE0MDQwNTEyMDY0NFoXDTE1MDQwNTEyMDY0NFowZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJbmMxEzARBgNVBAMMCmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/W9/4mL8cobYxLpX/i9tAxF8NWwgb+Q/xt5GIYPHc6ilNkYifUcyGMxSXhulqIvaGV2bEYTien7VE2sVzkc7+kwJg2sjicY93gJD3v9E59zscnmLxvScqADOssIBiMsija3TahMHQp/heu3cKciocucG9P8CElwJV9qJgA6pQIziX/xp7HGp+EC4Lkmi/ACc44Zwd3y2feFscuF9Nt2YFI4/vlfZTfoJyQ3WhU6DdNPW+Jx9SPZ4qhXWvgxNujl9ywbrPsmWO1S3VPWwmic/VUmAQML3STQ1dV06hzxMFxdkgQvhS8pVuAzYKg3LrMiPLk8eKGekRFiIwGQ8ln5wRAgMBAAGjUDBOMB0GA1UdDgQWBBQwO4WJJADe6tzyX5PpGGFQvJHv4jAfBgNVHSMEGDAWgBQwO4WJJADe6tzyX5PpGGFQvJHv4jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBaoqm47J59CJjR8KzDrFXMuhat24ORUBe4Wdxf5iYHcvupIA+qpMwB3WqSg3HmWUUUKpWCRNmR4HmsHGVPAXnoh0IOrm9DjizVvRyNWxac4JSVokqILLa513+tUEYAgqrGwmkqRAwacPF4k8qN1NTs11aLhVBFX9IOCGpnR26b83h2TX1Ki2zV05k9xhZLdNXyucTMy66ZXuWAuaWpRfz/p4JfHDFQ+gGVjrndRPJUR9P136UIrZd99OrCsSIWUZtKTfeFa/6KtOw/mUvMxW1r/htnGChldpHqjKsLDb9nzTLNv18+CdQJKsXkx8W57jvikwBZxZ8AgNAeTVAMr78l";
			byte[] rawCert = Base64.decode(base64Cert);
			ByteArrayInputStream bais = new ByteArrayInputStream(rawCert);

			tlsi = new TLSConnectionInfo("https://google.com",
					new X509Certificate[] { (X509Certificate) cf
							.generateCertificate(bais) });
		} catch (CertificateException | MalformedURLException
				| TLSCertificateException e) {
			e.printStackTrace();
		}

		return tlsi;
	}
	
	public NotaryManager _getPreconfiguredNM() {
		NotaryManager nm = new NotaryManager();
		nm.disableNotary("ICSINotary");
		nm.disableNotary("ConvergenceNotary");
		nm.disableNotary("SSLObservatoryNotary");
		nm.disableNotary("CrossbearNotary");
		nm.disableNotary("PerspectivesNotary");
		nm.disableNotary("SignatureCheck");
		return nm;
	}
	
	/**
	 * BEFORE
	 */
	
	/**
	 * AFTER
	 */
	@After
	public void resetRatings() {
		NotaryRating nr = NotaryRating.getInstance();
		nr.clear(this._getTLSInfo().hashCode());
	}

	/**
	 * TESTS
	 */
	@Test
	public void NMCheckOnlyAddedAndEnabledNotaries() {

		TLSConnectionInfo tlsi = this._getTLSInfo();
		if(tlsi==null) {
			return;
		}

		NotaryManager nm = this._getPreconfiguredNM();

		testNotaryResultTen.setNotaryName("testNotaryResultTen");
		nm.addNotary(testNotaryResultTen);
		testNotaryResultZero.setNotaryName("testNotaryResultZero");
		nm.addNotary(testNotaryResultZero);

		nm.disableNotary("testNotaryResultTen");
		nm.enableNotary("testNotaryResultTen");

		try {
			assertTrue(nm.check(tlsi)==5.0);
		} catch (NotaryException e) {
			e.printStackTrace();
		}

	}
	
	@Test(expected=NotaryRatingException.class)
	public void NMDisableAllNotaries() throws NotaryException {
		
		TLSConnectionInfo tlsi = this._getTLSInfo();
		if(tlsi==null) {
			return;
		}
		
		NotaryManager nm = this._getPreconfiguredNM();

		nm.check(tlsi);

	}
}
