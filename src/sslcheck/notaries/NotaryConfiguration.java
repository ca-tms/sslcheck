package sslcheck.notaries;

import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.Properties;

public class NotaryConfiguration {
	
	Properties param = null;
	
	private static NotaryConfiguration instance = null;
	
	public static NotaryConfiguration getInstance() { // NotarConfiguration is a singleton!!
		if(instance == null)
			try {
				return new NotaryConfiguration();
			} catch (IOException e) {
				e.printStackTrace();
			}
		return instance;
	}
	
	public NotaryConfiguration() throws IOException {
		this.param = new Properties();
		BufferedInputStream stream = new BufferedInputStream(new FileInputStream("notaries.properties"));
		this.param.load(stream);
		stream.close();
	}

	public float getRatingFactor(String notary) { 
		String factor = this.param.getProperty(notary + ".ratingFactor",this.param.getProperty("DefaultNotary.ratingFactor"));
		return Float.parseFloat(factor.trim()); // TODO catch exceptions..
	}
	
	public int getMinRating(String notary) {
		String factor = this.param.getProperty(notary + ".resultMin",this.param.getProperty("DefaultNotary.ratingFactor","1"));
		return Integer.parseInt(factor.trim()); // TODO catch exceptions..
	}

	public int getMaxRating(String notary) {
		String factor = this.param.getProperty(notary + ".resultMin",this.param.getProperty("DefaultNotary.ratingFactor","1"));
		return Integer.parseInt(factor.trim()); // TODO catch exceptions..
	}

}
