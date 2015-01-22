/*
 * This file is part of the CA Trust Management System (CA-TMS)
 *
 * Copyright 2015 by CA-TMS Team.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package sslcheck.core;

import sslcheck.notaries.NotaryException;

/**
 * @author Fabian Letzkus
 */
public class NotaryConfigurationException extends NotaryException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2432290993021963868L;

	public NotaryConfigurationException(String msg) {
		super(msg);
	}

}
