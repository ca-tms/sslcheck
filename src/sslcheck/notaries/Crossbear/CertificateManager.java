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
*/

package sslcheck.notaries.Crossbear;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Everything that is connected to processing or storing certificates is done by the CertificateManager.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class CertificateManager {

	/**
	 * STRIPPED VERSION OF CERTIFICATE MANAGER TO FIT SSLCHECK USECASE!!
	 */
	
	/**
	 * Hash a byte[] using the SHA256-algorithm
	 * 
	 * @param data
	 *            The byte[] to hash
	 * @return The SHA256 hash of data represented by a byte[] of length 32
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(data);
	}
	
	/**
	 * STRIPPED VERSION OF CERTIFICATE MANAGER TO FIT SSLCHECK USECASE!!
	 */
	
}