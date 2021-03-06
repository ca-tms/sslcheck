/*
    This file is part of Crossbear.

    Crossbear is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Crossbear is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Crossbear.  If not, see <http://www.gnu.org/licenses/>.

    Original authors: Thomas Riedmaier, Ralph Holz (TU Muenchen, Germany)
*/

package sslcheck.notaries.Crossbear;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.net.InetAddresses;

/**
 * The communication between the Crossbear server and its clients is entirely performed by sending messages. Each message has a one-byte "Type"-field and a two-byte "Length"-field as Header. These two
 * fields are necessary to tell the messages apart and to decode them effectively.
 * 
 * This class is created to give all subclasses a common interface (i.e. force all Messages to provide a "getBytes"-method that will always generate valid Crossbear-Messages) and to store
 * functionality that a lot of Messages need in a single location.
 * 
 * @author Thomas Riedmaier
 * 
 */
public abstract class Message {
	
	/*
	 * The currently implemented Messages use the following Message-Type-Identifiers:
	 */

	// Messages telling from which IP a request was issued
	public static final byte MESSAGE_TYPE_PUBLIC_IP_NOTIF4 = 0;
	public static final byte MESSAGE_TYPE_PUBLIC_IP_NOTIF6= 1;
	
	// Message to request that Public IP Notification:
	public static final byte MESSAGE_TYPE_PUBLIC_IP_NOTIFICATION_REQUEST=2;
	
	// Message telling which is the current local time at the server (to loosely synchronize clocks)
	public static final byte MESSAGE_TYPE_CURRENT_SERVER_TIME = 5;

	// Message containing a signature of the preceding messages.
	public static final byte MESSAGE_TYPE_SIGNATURE = 6;

	
	// Messages representing hunting tasks
	public static final byte MESSAGE_TYPE_IPV4_SHA256_TASK = 10;
	public static final byte MESSAGE_TYPE_IPV6_SHA256_TASK = 11;
	
	// Messages representing replies for hunting tasks
	public static final byte MESSAGE_TYPE_TASK_REPLY_NEW_CERT = 20;
	public static final byte MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT = 21;
	
	// Messages to request a host key fingerprint verification and to receive it's result
	public static final byte MESSAGE_TYPE_FP_VERIFY_REQUEST = 50;
	public static final byte MESSAGE_TYPE_FP_VERIFY_RESULT = 60;
	
	// Messages to request a certificate verification and to receive it's result
	public static final byte MESSAGE_TYPE_CERT_VERIFY_REQUEST = 100;
	public static final byte MESSAGE_TYPE_CERT_VERIFY_RESULT = 110;
	
	/**
	 * Get The Hex-String representation of a byte[].
	 * 
	 * e.g.: {192,168,0,1} -> "C0A80001"
	 * 
	 * @param b
	 *            An array of Bytes signed or unsigned
	 * @return The String that would be observed if one would look at the memory that stores b using a debugger (= the HEX-Representation of b)
	 */
	public static String byteArrayToHexString(byte[] b) {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
	
	/**
	 * Convert a byte[] of length 1-4 into an integer. The byte[] is assumed to be in network byte-order (i.e. big-endian byte-order)
	 * 
	 * @param bytes The byte[] to convert (max length: 4)
	 * @return The integer representation of the byte[]
	 */
	public static int byteArrayToInt( byte[] bytes ) {
	    int result = 0;
	    int byteCount = Math.min(4, bytes.length);
	    for (int i=0; i<byteCount; i++) {
	      result +=  (0xFF & (int) bytes[i])<<(byteCount-i-1)*8;
	    }
	    return result;
	 }
	
	/**
	 * Take a HexString and convert it to its byte[] representation
	 * 
	 * e.g.: "C0A80001" -> {192,168,0,1}
	 * 
	 * @param s The HeyString to convert (e.g. 60d31eb37595dd44584be5ef363283e3)
	 * @return The byte[] representation of s
	 */
	public static byte[] hexStringToByteArray(String s) {
		
		// Pad the string to an even number of characters
		if(s.length() %2 != 0){
			s = "0"+s;
		}
		
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
	
	/**
	 * Calculate the HMAC of type "HMac/SHA256" for a byte[] using a certain key.
	 * 
	 * Please Note: "HMac/SHA256" requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @param data The data to generate the HMAC on
	 * @param keyBytes The key to use for the HMAC generation
	 * @return The HMAC of data (32 bytes)
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 */
	protected static byte[] HMAC(byte[] data, byte[] keyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException  {

		SecretKey key = new SecretKeySpec(keyBytes, "HMac/SHA256");
		Mac mac = Mac.getInstance("HMac/SHA256", "BC");

		mac.init(key);
		mac.reset();
		mac.update(data, 0, data.length);

		return mac.doFinal();

	}
	
	/**
	 * Read all the bytes from an InputStrem (i.e. read until a "-1" is read) and return the result as a String.
	 * 
	 * @param in The InputStream to read from
	 * @return The bytes that were read converted into a String
	 * @throws IOException
	 */
	public static String inputStreamToString (InputStream in) throws IOException  {
	    StringBuffer out = new StringBuffer();
	    byte[] b = new byte[1024];
	    for (int n; (n = in.read(b)) != -1;) {
	        out.append(new String(b, 0, n));
	    }
	    return out.toString();
	}

	/**
	 * Convert an integer into a byte[] of length 4. The byte[] will be in network byte-order (i.e. big-endian byte-order)
	 * 
	 * @param val The integer to convert
	 * @return The byte[]-representation of val
	 */
	public static byte[] intToByteArray(int val) {

		ByteBuffer buffer = ByteBuffer.allocate(4);
		buffer.putInt(val);
		return buffer.array();
	}
	
	/**
	 * Check if a String implements either a valid IPv4-Address or a valid IPv6-Address
	 * 
	 * @param stringToCheck The string to check
	 * @return True if stringToCheck is either a valid IPv4-Address or a valid IPv6-Address else false
	 */
	public static boolean isValidIPAddress(String stringToCheck){
		return InetAddresses.isInetAddress(stringToCheck);
	}
	
	/**
	 * Read N Chars from an InputStream and return them as String
	 * 
	 * @param in The InputStream to read from
	 * @param n The number of chars to read
	 * @return n chars read from the InputStream as String
	 * @throws IOException
	 */
	public static String readNCharsFromStream(InputStream in, int n) throws IOException  {
		
		return new String(readNBytesFromStream(in, n));
	}
	
	/**
	 * Read N Bytes from an InputStream
	 * 
	 * @param in The InputStream to read from
	 * @param n The number of bytes ro read
	 * @return n bytes read from the InputStream as byte[]
	 * @throws IOException
	 */
	public static byte[] readNBytesFromStream(InputStream in, int n) throws IOException {
		if (n < 0) {
			throw new IOException("n was requested to be <0");
		}

		byte[] b = new byte[n];
		int bytesRead = 0;

		for (int c; bytesRead < n && (c = in.read(b, bytesRead, n - bytesRead)) != -1;) {
			bytesRead += c;
		}

		if (bytesRead != n) {
			throw new IOException("Unexpected end of stream reached.");
		}
		
		return b;
	}
	

	// The Type of this Message
	private final byte type;
	
	/**
	 * Create a new Message with a certain type (e.g. MESSAGE_TYPE_PUBLIC_IP_NOTIFICATION_REQUEST)
	 * 
	 * @param type The type of the message to create
	 */
	protected Message(byte type){
		
		this.type = type;
		
	}

	/**
	 * Transform the Message-Object into a byte[]-representation that can be send over the network. The steps performed by this function are
	 * - Get the Message's content
	 * - Generate a Header (Message's Type + Message's Length)
	 * - Concatenate them and return that as byte[]
	 * 
	 * @return The byte[]-representation of the Message-Object
	 * @throws MessageSerializationException
	 */
	public byte[] getBytes() throws MessageSerializationException {
		
		// Generate a new OutputStream into which the Message's bytes will be written
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		
		// Write the Message's type
		buffer.write(type);
		
		// Write the Message's length (not yet known so a dummy-value is written)
		try {
		    buffer.write(new byte[]{0,0});
		}
		catch (IOException e) {
		    throw new MessageSerializationException("Error in writing to buffer.", e);
		}
		
		// Write the Message's content
		writeContent(buffer);
		
		// Transform the OutputStream into an array
		byte[] messageBytes= buffer.toByteArray();
		
		// Assert that the Message length is not more than 16 byte (This is not allowed since the Message's length-field is only two bytes long)
		if(messageBytes.length >= (1<<16)){
			throw new IllegalArgumentException("The generated message is too long.");
		}
		
		// Store the Message's REAL length inside the Message
		byte[] messageLength = Message.intToByteArray(messageBytes.length);
		messageBytes[1] = messageLength[2];
		messageBytes[2] = messageLength[3];
		
		// Return the byte[]-representation of the Message-Object
		return messageBytes;
	}
	
	/**
	 * @return The Message's type
	 */
	public byte getType() {
		return type;
	}
		
	/**
	 * Create a byte[] representation of the messages's content.
	 * 
	 * @param out The OutputStream into which the content will be writen in a serialized form.
	 * @throws MessageSerializationException
	 */
	protected abstract void writeContent(OutputStream out) throws MessageSerializationException;
	
}