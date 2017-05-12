/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: CardChannel.java 295 2013-12-22 18:07:11Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 295 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-22 13:07:11 -0500 (Sun, 22 Dec 2013) $
 *****************************************************************************/

package com.idevity.android.nfc;

import java.io.IOException;

import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.smartcardio.ResponseAPDU;
import org.keysupport.util.DataUtil;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 295 $ 
 *
 */
public class CardChannel {
	
	/**
	 * Field MAX_APDU_SIZE
	 * No support at this time for extended length APDUs
	 */
	public final static int MAX_APDU_SIZE = 255;
	/**
	 * Field MIN_TIMEOUT.
	 * (value is 3000)
	 */
	public static final int MIN_TIMEOUT = 3500;
	/**
	 * Field TAG.
	 */
	private static final String TAG = CardChannel.class.getSimpleName();
	/**
	 * Field debug.
	 * (value is true)
	 */
	private static final boolean debug = true;
	/**
	 * Field channel.
	 */
	private IsoDep channel = null;
	/**
	 * Field isConnected.
	 */
	private boolean isConnected = false;
	/**
	 * Field timeOut.
	 */
	private int timeOut = 0;
	/**
	 * Field maxTransceive.
	 */
	private int maxTransceive = 0;
	/**
	 * Field elApduSupport.
	 */
	private boolean elApduSupport = false;
	/**
	 * Field historicalBytes.
	 */
	private byte[] historicalBytes = null;
	/**
	 * Constructor for CardChannel.
	 */
	@SuppressWarnings("unused")
	private CardChannel() {
		//Default Hidden Constructor
	}

	/**
	 * Constructor for CardChannel.
	 * @param tag Tag
	 */
	public CardChannel(Tag tag) {
		channel = IsoDep.get(tag);
		try {
			channel.connect();
			isConnected = channel.isConnected();
		} catch (IOException e) {
			Log.d(TAG, "Failed to connect");
			isConnected = false;
		}
		if (isConnected) {
			timeOut = channel.getTimeout();
			maxTransceive = channel.getMaxTransceiveLength();
			elApduSupport = channel.isExtendedLengthApduSupported();
			historicalBytes = channel.getHistoricalBytes();
			/*
			 * Increase the timeout if it is smaller than our min.
			 */
			if (timeOut < MIN_TIMEOUT) {
				if (debug) {
					Log.d(TAG, "Increasing timeout from: " + timeOut + " to: " + MIN_TIMEOUT);
				}
				channel.setTimeout(MIN_TIMEOUT);
				timeOut = channel.getTimeout();
			}
		}
		if (debug) {
			Log.d(TAG, "Currently Connected: " + isConnected);
			Log.d(TAG, "Current Timeout: " + timeOut);
			Log.d(TAG, "Max Tranceive: " + maxTransceive);
			Log.d(TAG, "Supports EL-APDUs: " + elApduSupport);
		}
	}
	
	/**
	 * Method close.
	 */
	public void close() {
		
		isConnected = channel.isConnected();
		
		if (isConnected) {
			try {
				channel.close();
			} catch (IOException e) {
				Log.d(TAG, "Failure on close: " + e.getMessage());
				isConnected = false;
			}
		}
	}
	
	/**
	 * Method isConnected.
	 * @return boolean
	 */
	public boolean isConnected() {
		return isConnected;
	}
	
	/**
	 * Method transceive.
	 * 
	 * @param data
	 *            byte[]
	 *
	 * @return byte[] 
	 */
	public byte[] transceive(byte[] data) {
		try {
			isConnected = channel.isConnected();
			if (isConnected) {
				return channel.transceive(data);
			}
		} catch (IOException e) {
			Log.d(TAG, "Failed to communicate: " + e.getMessage());
			isConnected = false;
		}
		return null;
	}

	/**
	 * Method transmit.
	 * 
	 * @param req
	 *            CommandAPDU
	 *
	 * @return ResponseAPDU 
	 * @throws InvalidResponseException 
	 */
	public ResponseAPDU transmit(CommandAPDU req) throws InvalidResponseException {

		ResponseAPDU response = null;
		
		if (debug) {
			Log.d(TAG,
					String.format("[%s] --> %s", "Reader",
							DataUtil.byteArrayToString(req.getBytes())));
		}
		byte[] respBuff = this.transceive(req.getBytes());
		if (respBuff != null && respBuff.length >= 2) {
			response = new ResponseAPDU(respBuff);
		} else {
			if (respBuff == null) {
				throw new InvalidResponseException("Response was null!");
			} else {
				throw new InvalidResponseException("Response: " + DataUtil.byteArrayToString(respBuff));
			}
		}
		if (debug) {
			Log.d(TAG,
					String.format("[%s] <-- %s", "Reader",
							DataUtil.byteArrayToString(response.getBytes())));
		}
		return response;
	}

	/**
	 * @return the historicalBytes
	 */
	public byte[] getHistoricalBytes() {
		return historicalBytes;
	}

}
