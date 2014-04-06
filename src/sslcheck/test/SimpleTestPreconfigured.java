package sslcheck.test;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jersey.core.util.Base64;

import sslcheck.core.NotaryManager;
import sslcheck.core.NotaryRatingException;
import sslcheck.core.TLSCertificateException;
import sslcheck.core.TLSConnectionInfo;

public class SimpleTestPreconfigured {
	private final static Logger log = LogManager.getRootLogger();

	public static void main(String[] args) {

		log.trace("Initializing...");
		// NotaryConfiguration notaryConf = NotaryConfiguration.getInstance();
		// NotaryRating notaryRating = NotaryRating.getInstance();

		// Some certificates to check...
		HashMap<String, String[]> config = new HashMap<String, String[]>();
		// Correct certificate
		config.put(
				"https://google.com",
				new String[] { "MIIdqjCCHJKgAwIBAgIIPPkk1gzn33MwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTM0MzQxWhcNMTQwNTI5MDAwMDAwWjBkMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzETMBEGA1UEAwwKZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK93kJBXatIYUgGOMSECmbb1f1ugKCzc1f/AGNHEpVsg7Kp9exiE9blh5psM/H9tKrjwL2JJ6crECchU5Y3jK3FkC5L7Eh2m64m9AUhPV0BXj1z8wn+Itourd4YKCc+cTLLe/yyOo5Fbb9PRZXtGo2eSxYaL6eYWPB8kXiT65D0sdEpvr6U3/6OVD1VOiuyPdqkvG0nvoG57f3rJle0EjmI/FPojJxiB8jxFG4Ria7zvZPe6RPb1fXk2vGNN6ZEMXpM+aG1pLwmfOLx2o6GvCo/R5o+5ER4vQyClKsX9WWy7YivD61PNR3RdhJjVWdR6Hjwkq16cKkWaUXFslL95LJcCAwEAAaOCGnkwghp1MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCCGU8GA1UdEQSCGUYwghlCggpnb29nbGUuY29tgg0qLmFuZHJvaWQuY29tghYqLmFwcGVuZ2luZS5nb29nbGUuY29tghIqLmNsb3VkLmdvb2dsZS5jb22CFiouZ29vZ2xlLWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmFjggsqLmdvb2dsZS5hZIILKi5nb29nbGUuYWWCCyouZ29vZ2xlLmFmggsqLmdvb2dsZS5hZ4ILKi5nb29nbGUuYWyCCyouZ29vZ2xlLmFtggsqLmdvb2dsZS5hc4ILKi5nb29nbGUuYXSCCyouZ29vZ2xlLmF6ggsqLmdvb2dsZS5iYYILKi5nb29nbGUuYmWCCyouZ29vZ2xlLmJmggsqLmdvb2dsZS5iZ4ILKi5nb29nbGUuYmmCCyouZ29vZ2xlLmJqggsqLmdvb2dsZS5ic4ILKi5nb29nbGUuYnSCCyouZ29vZ2xlLmJ5ggsqLmdvb2dsZS5jYYIMKi5nb29nbGUuY2F0ggsqLmdvb2dsZS5jY4ILKi5nb29nbGUuY2SCCyouZ29vZ2xlLmNmggsqLmdvb2dsZS5jZ4ILKi5nb29nbGUuY2iCCyouZ29vZ2xlLmNpggsqLmdvb2dsZS5jbIILKi5nb29nbGUuY22CCyouZ29vZ2xlLmNugg4qLmdvb2dsZS5jby5hb4IOKi5nb29nbGUuY28uYneCDiouZ29vZ2xlLmNvLmNrgg4qLmdvb2dsZS5jby5jcoIOKi5nb29nbGUuY28uaHWCDiouZ29vZ2xlLmNvLmlkgg4qLmdvb2dsZS5jby5pbIIOKi5nb29nbGUuY28uaW2CDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qZYIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLmtlgg4qLmdvb2dsZS5jby5rcoIOKi5nb29nbGUuY28ubHOCDiouZ29vZ2xlLmNvLm1hgg4qLmdvb2dsZS5jby5teoIOKi5nb29nbGUuY28ubnqCDiouZ29vZ2xlLmNvLnRogg4qLmdvb2dsZS5jby50eoIOKi5nb29nbGUuY28udWeCDiouZ29vZ2xlLmNvLnVrgg4qLmdvb2dsZS5jby51eoIOKi5nb29nbGUuY28udmWCDiouZ29vZ2xlLmNvLnZpgg4qLmdvb2dsZS5jby56YYIOKi5nb29nbGUuY28uem2CDiouZ29vZ2xlLmNvLnp3ggwqLmdvb2dsZS5jb22CDyouZ29vZ2xlLmNvbS5hZoIPKi5nb29nbGUuY29tLmFngg8qLmdvb2dsZS5jb20uYWmCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYmSCDyouZ29vZ2xlLmNvbS5iaIIPKi5nb29nbGUuY29tLmJugg8qLmdvb2dsZS5jb20uYm+CDyouZ29vZ2xlLmNvbS5icoIPKi5nb29nbGUuY29tLmJ5gg8qLmdvb2dsZS5jb20uYnqCDyouZ29vZ2xlLmNvbS5jboIPKi5nb29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20uY3WCDyouZ29vZ2xlLmNvbS5jeYIPKi5nb29nbGUuY29tLmRvgg8qLmdvb2dsZS5jb20uZWOCDyouZ29vZ2xlLmNvbS5lZ4IPKi5nb29nbGUuY29tLmV0gg8qLmdvb2dsZS5jb20uZmqCDyouZ29vZ2xlLmNvbS5nZYIPKi5nb29nbGUuY29tLmdogg8qLmdvb2dsZS5jb20uZ2mCDyouZ29vZ2xlLmNvbS5ncoIPKi5nb29nbGUuY29tLmd0gg8qLmdvb2dsZS5jb20uaGuCDyouZ29vZ2xlLmNvbS5pcYIPKi5nb29nbGUuY29tLmptgg8qLmdvb2dsZS5jb20uam+CDyouZ29vZ2xlLmNvbS5raIIPKi5nb29nbGUuY29tLmt3gg8qLmdvb2dsZS5jb20ubGKCDyouZ29vZ2xlLmNvbS5seYIPKi5nb29nbGUuY29tLm1tgg8qLmdvb2dsZS5jb20ubXSCDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLm15gg8qLmdvb2dsZS5jb20ubmGCDyouZ29vZ2xlLmNvbS5uZoIPKi5nb29nbGUuY29tLm5ngg8qLmdvb2dsZS5jb20ubmmCDyouZ29vZ2xlLmNvbS5ucIIPKi5nb29nbGUuY29tLm5ygg8qLmdvb2dsZS5jb20ub22CDyouZ29vZ2xlLmNvbS5wYYIPKi5nb29nbGUuY29tLnBlgg8qLmdvb2dsZS5jb20ucGeCDyouZ29vZ2xlLmNvbS5waIIPKi5nb29nbGUuY29tLnBrgg8qLmdvb2dsZS5jb20ucGyCDyouZ29vZ2xlLmNvbS5wcoIPKi5nb29nbGUuY29tLnB5gg8qLmdvb2dsZS5jb20ucWGCDyouZ29vZ2xlLmNvbS5ydYIPKi5nb29nbGUuY29tLnNhgg8qLmdvb2dsZS5jb20uc2KCDyouZ29vZ2xlLmNvbS5zZ4IPKi5nb29nbGUuY29tLnNsgg8qLmdvb2dsZS5jb20uc3aCDyouZ29vZ2xlLmNvbS50aoIPKi5nb29nbGUuY29tLnRugg8qLmdvb2dsZS5jb20udHKCDyouZ29vZ2xlLmNvbS50d4IPKi5nb29nbGUuY29tLnVhgg8qLmdvb2dsZS5jb20udXmCDyouZ29vZ2xlLmNvbS52Y4IPKi5nb29nbGUuY29tLnZlgg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmN2ggsqLmdvb2dsZS5jeoILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmRqggsqLmdvb2dsZS5ka4ILKi5nb29nbGUuZG2CCyouZ29vZ2xlLmR6ggsqLmdvb2dsZS5lZYILKi5nb29nbGUuZXOCCyouZ29vZ2xlLmZpggsqLmdvb2dsZS5mbYILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmdhggsqLmdvb2dsZS5nZYILKi5nb29nbGUuZ2eCCyouZ29vZ2xlLmdsggsqLmdvb2dsZS5nbYILKi5nb29nbGUuZ3CCCyouZ29vZ2xlLmdyggsqLmdvb2dsZS5neYILKi5nb29nbGUuaGuCCyouZ29vZ2xlLmhuggsqLmdvb2dsZS5ocoILKi5nb29nbGUuaHSCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pZYILKi5nb29nbGUuaW2CDSouZ29vZ2xlLmluZm+CCyouZ29vZ2xlLmlxggsqLmdvb2dsZS5pc4ILKi5nb29nbGUuaXSCDiouZ29vZ2xlLml0LmFvggsqLmdvb2dsZS5qZYILKi5nb29nbGUuam+CDSouZ29vZ2xlLmpvYnOCCyouZ29vZ2xlLmpwggsqLmdvb2dsZS5rZ4ILKi5nb29nbGUua2mCCyouZ29vZ2xlLmt6ggsqLmdvb2dsZS5sYYILKi5nb29nbGUubGmCCyouZ29vZ2xlLmxrggsqLmdvb2dsZS5sdIILKi5nb29nbGUubHWCCyouZ29vZ2xlLmx2ggsqLmdvb2dsZS5tZIILKi5nb29nbGUubWWCCyouZ29vZ2xlLm1nggsqLmdvb2dsZS5ta4ILKi5nb29nbGUubWyCCyouZ29vZ2xlLm1uggsqLmdvb2dsZS5tc4ILKi5nb29nbGUubXWCCyouZ29vZ2xlLm12ggsqLmdvb2dsZS5td4ILKi5nb29nbGUubmWCDiouZ29vZ2xlLm5lLmpwggwqLmdvb2dsZS5uZXSCCyouZ29vZ2xlLm5nggsqLmdvb2dsZS5ubIILKi5nb29nbGUubm+CCyouZ29vZ2xlLm5yggsqLmdvb2dsZS5udYIPKi5nb29nbGUub2ZmLmFpggsqLmdvb2dsZS5wa4ILKi5nb29nbGUucGyCCyouZ29vZ2xlLnBuggsqLmdvb2dsZS5wc4ILKi5nb29nbGUucHSCCyouZ29vZ2xlLnJvggsqLmdvb2dsZS5yc4ILKi5nb29nbGUucnWCCyouZ29vZ2xlLnJ3ggsqLmdvb2dsZS5zY4ILKi5nb29nbGUuc2WCCyouZ29vZ2xlLnNoggsqLmdvb2dsZS5zaYILKi5nb29nbGUuc2uCCyouZ29vZ2xlLnNtggsqLmdvb2dsZS5zboILKi5nb29nbGUuc2+CCyouZ29vZ2xlLnN0ggsqLmdvb2dsZS50ZIILKi5nb29nbGUudGeCCyouZ29vZ2xlLnRrggsqLmdvb2dsZS50bIILKi5nb29nbGUudG2CCyouZ29vZ2xlLnRuggsqLmdvb2dsZS50b4ILKi5nb29nbGUudHSCCyouZ29vZ2xlLnVzggsqLmdvb2dsZS51eoILKi5nb29nbGUudmeCCyouZ29vZ2xlLnZ1ggsqLmdvb2dsZS53c4IPKi5nb29nbGVhcGlzLmNughQqLmdvb2dsZWNvbW1lcmNlLmNvbYIRKi5nb29nbGV2aWRlby5jb22CDSouZ3N0YXRpYy5jb22CDCoudXJjaGluLmNvbYIQKi51cmwuZ29vZ2xlLmNvbYIWKi55b3V0dWJlLW5vY29va2llLmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0dWJlZWR1Y2F0aW9uLmNvbYILKi55dGltZy5jb22CC2FuZHJvaWQuY29tggRnLmNvggZnb28uZ2yCFGdvb2dsZS1hbmFseXRpY3MuY29tgglnb29nbGUuYWOCCWdvb2dsZS5hZIIJZ29vZ2xlLmFlgglnb29nbGUuYWaCCWdvb2dsZS5hZ4IJZ29vZ2xlLmFsgglnb29nbGUuYW2CCWdvb2dsZS5hc4IJZ29vZ2xlLmF0gglnb29nbGUuYXqCCWdvb2dsZS5iYYIJZ29vZ2xlLmJlgglnb29nbGUuYmaCCWdvb2dsZS5iZ4IJZ29vZ2xlLmJpgglnb29nbGUuYmqCCWdvb2dsZS5ic4IJZ29vZ2xlLmJ0gglnb29nbGUuYnmCCWdvb2dsZS5jYYIKZ29vZ2xlLmNhdIIJZ29vZ2xlLmNjgglnb29nbGUuY2SCCWdvb2dsZS5jZoIJZ29vZ2xlLmNngglnb29nbGUuY2iCCWdvb2dsZS5jaYIJZ29vZ2xlLmNsgglnb29nbGUuY22CCWdvb2dsZS5jboIMZ29vZ2xlLmNvLmFvggxnb29nbGUuY28uYneCDGdvb2dsZS5jby5ja4IMZ29vZ2xlLmNvLmNyggxnb29nbGUuY28uaHWCDGdvb2dsZS5jby5pZIIMZ29vZ2xlLmNvLmlsggxnb29nbGUuY28uaW2CDGdvb2dsZS5jby5pboIMZ29vZ2xlLmNvLmplggxnb29nbGUuY28uanCCDGdvb2dsZS5jby5rZYIMZ29vZ2xlLmNvLmtyggxnb29nbGUuY28ubHOCDGdvb2dsZS5jby5tYYIMZ29vZ2xlLmNvLm16ggxnb29nbGUuY28ubnqCDGdvb2dsZS5jby50aIIMZ29vZ2xlLmNvLnR6ggxnb29nbGUuY28udWeCDGdvb2dsZS5jby51a4IMZ29vZ2xlLmNvLnV6ggxnb29nbGUuY28udmWCDGdvb2dsZS5jby52aYIMZ29vZ2xlLmNvLnphggxnb29nbGUuY28uem2CDGdvb2dsZS5jby56d4INZ29vZ2xlLmNvbS5hZoINZ29vZ2xlLmNvbS5hZ4INZ29vZ2xlLmNvbS5haYINZ29vZ2xlLmNvbS5hcoINZ29vZ2xlLmNvbS5hdYINZ29vZ2xlLmNvbS5iZIINZ29vZ2xlLmNvbS5iaIINZ29vZ2xlLmNvbS5iboINZ29vZ2xlLmNvbS5ib4INZ29vZ2xlLmNvbS5icoINZ29vZ2xlLmNvbS5ieYINZ29vZ2xlLmNvbS5ieoINZ29vZ2xlLmNvbS5jboINZ29vZ2xlLmNvbS5jb4INZ29vZ2xlLmNvbS5jdYINZ29vZ2xlLmNvbS5jeYINZ29vZ2xlLmNvbS5kb4INZ29vZ2xlLmNvbS5lY4INZ29vZ2xlLmNvbS5lZ4INZ29vZ2xlLmNvbS5ldIINZ29vZ2xlLmNvbS5maoINZ29vZ2xlLmNvbS5nZYINZ29vZ2xlLmNvbS5naIINZ29vZ2xlLmNvbS5naYINZ29vZ2xlLmNvbS5ncoINZ29vZ2xlLmNvbS5ndIINZ29vZ2xlLmNvbS5oa4INZ29vZ2xlLmNvbS5pcYINZ29vZ2xlLmNvbS5qbYINZ29vZ2xlLmNvbS5qb4INZ29vZ2xlLmNvbS5raIINZ29vZ2xlLmNvbS5rd4INZ29vZ2xlLmNvbS5sYoINZ29vZ2xlLmNvbS5seYINZ29vZ2xlLmNvbS5tbYINZ29vZ2xlLmNvbS5tdIINZ29vZ2xlLmNvbS5teIINZ29vZ2xlLmNvbS5teYINZ29vZ2xlLmNvbS5uYYINZ29vZ2xlLmNvbS5uZoINZ29vZ2xlLmNvbS5uZ4INZ29vZ2xlLmNvbS5uaYINZ29vZ2xlLmNvbS5ucIINZ29vZ2xlLmNvbS5ucoINZ29vZ2xlLmNvbS5vbYINZ29vZ2xlLmNvbS5wYYINZ29vZ2xlLmNvbS5wZYINZ29vZ2xlLmNvbS5wZ4INZ29vZ2xlLmNvbS5waIINZ29vZ2xlLmNvbS5wa4INZ29vZ2xlLmNvbS5wbIINZ29vZ2xlLmNvbS5wcoINZ29vZ2xlLmNvbS5weYINZ29vZ2xlLmNvbS5xYYINZ29vZ2xlLmNvbS5ydYINZ29vZ2xlLmNvbS5zYYINZ29vZ2xlLmNvbS5zYoINZ29vZ2xlLmNvbS5zZ4INZ29vZ2xlLmNvbS5zbIINZ29vZ2xlLmNvbS5zdoINZ29vZ2xlLmNvbS50aoINZ29vZ2xlLmNvbS50boINZ29vZ2xlLmNvbS50coINZ29vZ2xlLmNvbS50d4INZ29vZ2xlLmNvbS51YYINZ29vZ2xlLmNvbS51eYINZ29vZ2xlLmNvbS52Y4INZ29vZ2xlLmNvbS52ZYINZ29vZ2xlLmNvbS52boIJZ29vZ2xlLmN2gglnb29nbGUuY3qCCWdvb2dsZS5kZYIJZ29vZ2xlLmRqgglnb29nbGUuZGuCCWdvb2dsZS5kbYIJZ29vZ2xlLmR6gglnb29nbGUuZWWCCWdvb2dsZS5lc4IJZ29vZ2xlLmZpgglnb29nbGUuZm2CCWdvb2dsZS5mcoIJZ29vZ2xlLmdhgglnb29nbGUuZ2WCCWdvb2dsZS5nZ4IJZ29vZ2xlLmdsgglnb29nbGUuZ22CCWdvb2dsZS5ncIIJZ29vZ2xlLmdygglnb29nbGUuZ3mCCWdvb2dsZS5oa4IJZ29vZ2xlLmhugglnb29nbGUuaHKCCWdvb2dsZS5odIIJZ29vZ2xlLmh1gglnb29nbGUuaWWCCWdvb2dsZS5pbYILZ29vZ2xlLmluZm+CCWdvb2dsZS5pcYIJZ29vZ2xlLmlzgglnb29nbGUuaXSCDGdvb2dsZS5pdC5hb4IJZ29vZ2xlLmplgglnb29nbGUuam+CC2dvb2dsZS5qb2Jzgglnb29nbGUuanCCCWdvb2dsZS5rZ4IJZ29vZ2xlLmtpgglnb29nbGUua3qCCWdvb2dsZS5sYYIJZ29vZ2xlLmxpgglnb29nbGUubGuCCWdvb2dsZS5sdIIJZ29vZ2xlLmx1gglnb29nbGUubHaCCWdvb2dsZS5tZIIJZ29vZ2xlLm1lgglnb29nbGUubWeCCWdvb2dsZS5ta4IJZ29vZ2xlLm1sgglnb29nbGUubW6CCWdvb2dsZS5tc4IJZ29vZ2xlLm11gglnb29nbGUubXaCCWdvb2dsZS5td4IJZ29vZ2xlLm5lggxnb29nbGUubmUuanCCCmdvb2dsZS5uZXSCCWdvb2dsZS5uZ4IJZ29vZ2xlLm5sgglnb29nbGUubm+CCWdvb2dsZS5ucoIJZ29vZ2xlLm51gg1nb29nbGUub2ZmLmFpgglnb29nbGUucGuCCWdvb2dsZS5wbIIJZ29vZ2xlLnBugglnb29nbGUucHOCCWdvb2dsZS5wdIIJZ29vZ2xlLnJvgglnb29nbGUucnOCCWdvb2dsZS5ydYIJZ29vZ2xlLnJ3gglnb29nbGUuc2OCCWdvb2dsZS5zZYIJZ29vZ2xlLnNogglnb29nbGUuc2mCCWdvb2dsZS5za4IJZ29vZ2xlLnNtgglnb29nbGUuc26CCWdvb2dsZS5zb4IJZ29vZ2xlLnN0gglnb29nbGUudGSCCWdvb2dsZS50Z4IJZ29vZ2xlLnRrgglnb29nbGUudGyCCWdvb2dsZS50bYIJZ29vZ2xlLnRugglnb29nbGUudG+CCWdvb2dsZS50dIIJZ29vZ2xlLnVzgglnb29nbGUudXqCCWdvb2dsZS52Z4IJZ29vZ2xlLnZ1gglnb29nbGUud3OCEmdvb2dsZWNvbW1lcmNlLmNvbYIKdXJjaGluLmNvbYIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbTBoBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29jc3AwHQYDVR0OBBYEFKZ10rrYVnjAKpyzvIljr+2XB2DdMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBtrtiGrpagS8wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcmwwDQYJKoZIhvcNAQEFBQADggEBAHn3kpPfFCHOXnYXpyUN7sXqdKieCdfBvG73UjsiH3ofGwARyVjzVnqiqQVqva5kx7rBhibsK1jnqUn8AlXgoyJQDT7J3au5DMFzFgEXWqiuucDjiQ6PoAJvKfhAEo4lCPBpuOTAsDG/hChs24Jua+4xr+DdXvGuzQEjWfGqTneQBfeNB8Gt4le6f1zITw2rUZfEywOG2G8drMgmiy9ZErJhsXswM2hIYCTtCAZZfrRGE2y7gFztTD7jUshAgn7EjdIceNtqwfGoruNNeu3B7prMzrYulsUeIT0FQrkDyaikBtkW/8By+TnvbMq9Fn52icmAcIoAfojJJA9CBzn/Eu8=" });
		// config.put(
		// "https://cacert.com",
		// new String[]
		// {"MIIFZDCCA0ygAwIBAgIDC7PGMA0GCSqGSIb3DQEBBQUAMHkxEDAOBgNVBAoTB1Jvb3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEiMCAGA1UEAxMZQ0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJARYSc3VwcG9ydEBjYWNlcnQub3JnMB4XDTEyMDUwNjE4NDY0MVoXDTE0MDUwNjE4NDY0MVowWzELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA05TVzEPMA0GA1UEBxMGU3lkbmV5MRQwEgYDVQQKEwtDQWNlcnQgSW5jLjEXMBUGA1UEAxMOd3d3LmNhY2VydC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeNSAxSFtymeN6rQD69eXIJEnCCP7Z24/fdOgxRDSBhfQDUVhdmsuDOvuziOoWGqRxZPcWdMEMRcJ5SrA2aHIstvnaLhUlxp2fuaeXx9XMCJ9ZmzHZbH4wqLaU+UlhcSsdkPzapf3N3HaUAW8kT4bHEGzObYVCUBxxhpY01EoGRQmnFojzLNF3+0O1npQzXg5MeIWHW/Z+9jE+6odL6IXgg1bvrP4dFgoveTcG6BmJu+50RwHaUad7hQuNeS+pNsVzCiDdMF2qoCQXtAGhnEQ9/KHpBD2zISBVIyEbYxdyU/WxnkaOof63Mf/TAgMNzVN9duqEtFyvvMrQY1XkBBwfAgMBAAGjggERMIIBDTAMBgNVHRMBAf8EAjAAMDQGA1UdJQQtMCsGCCsGAQUFBwMCBggrBgEFBQcDAQYJYIZIAYb4QgQBBgorBgEEAYI3CgMDMAsGA1UdDwQEAwIFoDAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmNhY2VydC5vcmcvMIGEBgNVHREEfTB7gg53d3cuY2FjZXJ0Lm9yZ4IRc2VjdXJlLmNhY2VydC5vcmeCEnd3d21haWwuY2FjZXJ0Lm9yZ4IKY2FjZXJ0Lm9yZ4IOd3d3LmNhY2VydC5uZXSCCmNhY2VydC5uZXSCDnd3dy5jYWNlcnQuY29tggpjYWNlcnQuY29tMA0GCSqGSIb3DQEBBQUAA4ICAQA2+uCGX18kZD8gyfj44TlwV4TXJ5BrT0M9qogg2k5u057i+X2ePy3DiE2REyLkU+i5ekH5gvTl74uSJKtpSf/hMyJEByyPyIULhlXCl46z2Z60drYzO4igapCdkm0JthVGvk6/hjdaxgBGhUvSTEP5nLNkDa+uYVHJI58wfX2oh9gqxf8VnMJ8/A8Zi6mYCWUlFUobNd/ozyDZ6WVntrLib85sAFhds93nkoUYxgx1N9Xg/I31/jcL6bqmpRAZcbPtvEom0RyqPLM+AOgySWiYbg1Nl8nKx25C2AuXk63NN4CVwkXpdFF3q5qk1izPruvJ68jNW0pG7nrMQsiY2BCesfGyEzY8vfrMjeR5MLNv5r+obeYFnC1juYp6JBt+thW+xPFzHYLjohKPwo/NbMOjIUM9gv/Pq3rVRPgWru4/8yYWhrmEK370rtlYBUSGRUdR8xed1Jvs+4qJ3s9t41mLSXvUfwyPsT7eoloUAfw3RhdwOzXoC2P6ftmniyu/b/HuYH1AWK+HFtFi9CHiMIqOJMhj/LnzL9udrQOpir7bVej/mlb3kSRo2lZymKOvuMymMpJkvBvUU/QEbCxWZAkTyqL2qlcQhHv7W366DOFjxDqpthaTRD69T8i/2AnsBDjYFxa47DisIvR57rLmE+fILjSvd94N/IpGs3lSOS5JeA=="});//
		// Incorrent, fraudulent, invalid, ... certificates
		config.put(
				"https://google.com",
				new String[] { "MIIDmzCCAoOgAwIBAgIJAPDxpOSQbn4wMA0GCSqGSIb3DQEBBQUAMGQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKDApHb29nbGUgSW5jMRMwEQYDVQQDDApnb29nbGUuY29tMB4XDTE0MDQwNTEyMDY0NFoXDTE1MDQwNTEyMDY0NFowZDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJbmMxEzARBgNVBAMMCmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/W9/4mL8cobYxLpX/i9tAxF8NWwgb+Q/xt5GIYPHc6ilNkYifUcyGMxSXhulqIvaGV2bEYTien7VE2sVzkc7+kwJg2sjicY93gJD3v9E59zscnmLxvScqADOssIBiMsija3TahMHQp/heu3cKciocucG9P8CElwJV9qJgA6pQIziX/xp7HGp+EC4Lkmi/ACc44Zwd3y2feFscuF9Nt2YFI4/vlfZTfoJyQ3WhU6DdNPW+Jx9SPZ4qhXWvgxNujl9ywbrPsmWO1S3VPWwmic/VUmAQML3STQ1dV06hzxMFxdkgQvhS8pVuAzYKg3LrMiPLk8eKGekRFiIwGQ8ln5wRAgMBAAGjUDBOMB0GA1UdDgQWBBQwO4WJJADe6tzyX5PpGGFQvJHv4jAfBgNVHSMEGDAWgBQwO4WJJADe6tzyX5PpGGFQvJHv4jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBaoqm47J59CJjR8KzDrFXMuhat24ORUBe4Wdxf5iYHcvupIA+qpMwB3WqSg3HmWUUUKpWCRNmR4HmsHGVPAXnoh0IOrm9DjizVvRyNWxac4JSVokqILLa513+tUEYAgqrGwmkqRAwacPF4k8qN1NTs11aLhVBFX9IOCGpnR26b83h2TX1Ki2zV05k9xhZLdNXyucTMy66ZXuWAuaWpRfz/p4JfHDFQ+gGVjrndRPJUR9P136UIrZd99OrCsSIWUZtKTfeFa/6KtOw/mUvMxW1r/htnGChldpHqjKsLDb9nzTLNv18+CdQJKsXkx8W57jvikwBZxZ8AgNAeTVAMr78l" });

		// Internal processing to convert information in correct format -
		// nevermind that code..
		HashMap<URL, X509Certificate[]> certificates;
		try {
			certificates = new HashMap<URL, X509Certificate[]>();
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			for (String url : config.keySet()) {
				X509Certificate[] certs = new X509Certificate[config.get(url).length];
				int i = 0;
				for (String base64Cert : config.get(url)) {
					byte[] rawCert = Base64.decode(base64Cert);
					ByteArrayInputStream bais = new ByteArrayInputStream(
							rawCert);
					certs[i] = (X509Certificate) cf.generateCertificate(bais);
					i++;
				}
				certificates.put(new URL(url), certs);
			}
		} catch (CertificateException | MalformedURLException e) {
			System.out.println("ERROR!!!!\n" + e);
			return;
		}

		// Manage Trust

		for (URL url : certificates.keySet()) {

			log.trace("Checking certificates for " + url.getHost());

			try {

				/*
				 * Initialize Notaries by using NotaryManager
				 */
				log.trace("Initializing NotaryManager...");
				NotaryManager nm = new NotaryManager();
				/*
				 * You can also instantiate the notaries directly:
				 * 	ICSINotary icsi = new ICSINotary();
				 *	ConvergenceNotary convergence = new ConvergenceNotary();
				 *	SSLObservatoryNotary sslobservatory = new SSLObservatoryNotary();
				 * Or remove them from NotaryManager:
				 *  nm.disableNotary("ICSINotary");
				 *  nm.disableNotary("ConvergenceNotary");
				 *  nm.disableNotary("SSLObservatoryNotary");
				 * Or enable previously disabled Notaries (but you can not enable Notaries disabled via configuration file!)
				 *	nm.enableNotary("ICSINotary");
				 * You can add new Notaries to the NotaryManager (setting Name, Configuration and TrustManager has to be done manually!):
				 *	CrossbearNotary crossbear = new CrossbearNotary();
				 *	crossbear.setNotaryName("CrossbearNotary"); // Name
				 *	crossbear.setConfiguration(....); // Configuration
				 *	crossbear.initialize(); // for example: TrustManager, Session Management, ...
				 * 	nm.addNotary(crossbear);
				 * 
				 * PLEASE BEWARE: If you don't use NotaryManager, there will be no integration of NotaryRating or NotaryConfiguration
				 */
				

				/*
				 * Install Trust Managers
				 */
				log.trace("Configuring Trust Managers...");
				final SSLContext sslContext = SSLContext.getInstance("TLS");
				sslContext.init(null,
						new TrustManager[] { nm.getTrustManager() },
						new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
						.getSocketFactory());

				/*
				 * Build TLSConnectionInfo
				 */
				log.trace("Building TLSConnectionInfo-Object...");
				TLSConnectionInfo sslinfo = new TLSConnectionInfo(
						url.toString(), url.getDefaultPort(),
						certificates.get(url));

				/*
				 * Check Certificates using NotaryManager
				 */
				log.trace("-- BEGIN -- Checking Certificates...");
				log.info("Rating: " + sslinfo.validateCertificates(nm));
				/*
				 * Check Certificates using Notaries:
				 * 	try{
				 * 		crossbear.check(sslinfo)
				 * 	}catch(NotaryException e)
				 * 		// Do something...
				 * 	}
				 * 
				 * By using NotaryManager, one will not be concerned with exceptions
				 */
				
				/* 
				 * Is Certificate/Host-Relationship trustworthy?
				 */
				try {
					if (sslinfo.isTrusted())
						/*
						 * Yes
						 */
						log.info("Trustworthy.");
					else
						/*
						 * No
						 */
						log.info("Not trustworthy.");
				} catch (NotaryRatingException e) {
					/*
					 * Not decidable. 
					 */
					log.info("Trust could not be evaluated: "+e);
				}
				log.trace("-- END -- Checking Certificates...");

			} catch (TLSCertificateException | MalformedURLException e) {
				log.error("Can'parse certificate!!! Error: " + e);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyManagementException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		log.trace("Done.");
	}
}
