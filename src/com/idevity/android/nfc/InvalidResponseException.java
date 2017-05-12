/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: InvalidResponseException.java 293 2013-12-19 15:49:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 293 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-19 10:49:22 -0500 (Thu, 19 Dec 2013) $
 *****************************************************************************/

package com.idevity.android.nfc;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 293 $ 
 *
 */
public class InvalidResponseException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 755433899251156402L;

	/**
	 * 
	 */
	public InvalidResponseException() {
	}

	/**
	 * @param detailMessage
	 */
	public InvalidResponseException(String detailMessage) {
		super(detailMessage);
	}

	/**
	 * @param throwable
	 */
	public InvalidResponseException(Throwable throwable) {
		super(throwable);
	}

	/**
	 * @param detailMessage
	 * @param throwable
	 */
	public InvalidResponseException(String detailMessage, Throwable throwable) {
		super(detailMessage, throwable);
	}

}
