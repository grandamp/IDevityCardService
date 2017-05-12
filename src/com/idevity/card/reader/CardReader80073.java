/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: CardReader80073.java 307 2014-02-03 00:56:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 * 
 * Changed: $LastChangedDate: 2014-02-02 19:56:22 -0500 (Sun, 02 Feb 2014) $
 *****************************************************************************/

package com.idevity.card.reader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.keysupport.encoding.Tag;
import org.keysupport.nist80073.cardedge.PIVAPDUInterface;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.smartcardio.ResponseAPDU;
import org.keysupport.util.DataUtil;

import android.util.Log;

import com.idevity.android.nfc.CardChannel;
import com.idevity.android.nfc.InvalidResponseException;
import com.idevity.card.data.CardData80073;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 */
public class CardReader80073 {

	private static final String TAG = CardReader80073.class.getSimpleName();

	private CardChannel channel;
	private CardData80073 carddata;
	private boolean dataavailable = false;
	private int threadcount = 0;
	private boolean isRunning = false;
	private Thread readerThread;

	/**
	 * Constructor for CardReader80073.
	 * 
	 * @param ctx
	 *            Context
	 * @param pop
	 */
	public CardReader80073() {
		Log.d(TAG, "800-73-3 Reader Initialized");
	}

	/**
	 * Method start.
	 * 
	 * @param tag
	 *            CardChannel
	 * @throws IOException
	 */
	public void start(CardChannel tag) {
		this.channel = tag;
		this.carddata = new CardData80073();
		threadcount++;
		Log.d(TAG, "800-73-3 Reader Thread: " + threadcount);
		Runnable r = new Runnable() {
			@Override
			public void run() {
				try {
					dataavailable = false;
					ResponseAPDU response;

					/*
					 * Obtain and Store Historical Bytes as well as explicitly
					 * select the PIV application
					 */
					Log.d(TAG, "Fetching Historical Bytes for card data");
					byte[] historicalBytes = channel.getHistoricalBytes();
					carddata.setATSHB(historicalBytes);
					Log.d(TAG,
							"Historical Bytes: "
									+ DataUtil
											.byteArrayToString(historicalBytes));
					Log.d(TAG, "Selecting PIV Card Application");
					response = transmit(new CommandAPDU(
							PIVAPDUInterface.SELECT_PIV));
					Log.d(TAG,
							"Response from select: "
									+ DataUtil.byteArrayToString(response
											.getBytes()));

					/*
					 * Obtain and Store PIV Discovery Object
					 */
					Log.d(TAG, "Fetching PIV Discovery Object for card data");
					PIVDataTempl pdo = getPIVData(new Tag(Tag.PIV_DISCOVERY_OBJECT));
					if (pdo != null) {
						carddata.setPIVDiscoveryObject(pdo);
					}

					/*
					 * Obtain and Store CHUID Object
					 */
					Log.d(TAG, "Fetching CHUID Object for card data");
					PIVDataTempl chuid = getPIVData(new Tag(Tag.PIV_CHUID));
					if (chuid != null) {
						carddata.setPIVCardHolderUniqueID(chuid);
					}

					/*
					 * Obtain and Store Card Authentication Certificate Object
					 */
					Log.d(TAG, "Fetching Card Authentication Certificate Object for card data");
					PIVDataTempl cac = getPIVData(new Tag(Tag.PIV_CERT_CARDAUTH));
					if (cac != null) {
						carddata.setCardAuthCertificate(cac);
					}

					/*
					 * State that we have a CardData Object available for
					 * consumption
					 */
					setCardData(carddata);
					dataavailable = true;
				} catch (IOException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					Log.d(TAG, String.format("Stopping reader thread '%s'",
							readerThread.getName()));
					stop();
					return;
				} catch (NullPointerException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					Log.d(TAG, String.format("Stopping reader thread '%s'",
							readerThread.getName()));
					stop();
					return;
				} catch (InvalidResponseException e) {
					Log.d(TAG,
							"Invalid Response Received by reader: "
									+ e.getLocalizedMessage());
					Log.e(TAG, "Error: " + e.getMessage());
					Log.d(TAG, String.format("Stopping reader thread '%s'",
							readerThread.getName()));
					stop();
					return;
				}
				Log.d(TAG, String.format("Stopping reader thread '%s'",
						readerThread.getName()));
				stop();
				return;
			}
		};
		readerThread = new Thread(r);
		readerThread.setName("800-73 reader thread#" + readerThread.getId());
		readerThread.start();
		isRunning = true;
		Log.d(TAG,
				String.format("Started reader thread '%s'",
						readerThread.getName()));
	}

	private void setCardData(CardData80073 carddata) {
		this.carddata = carddata;
	}

	/**
	 * Method transmit.
	 * 
	 * @param command
	 *            CommandAPDU
	 * @return ResponseAPDU
	 * @throws IOException
	 * @throws InvalidResponseException
	 */
	private ResponseAPDU transmit(CommandAPDU command) throws IOException,
			InvalidResponseException {
		ResponseAPDU response;
		Log.d(TAG,
				String.format("[%s] --> %s", "Reader",
						DataUtil.byteArrayToString(command.getBytes())));
		response = channel.transmit(command);
		Log.d(TAG,
				String.format("[%s] <-- %s", "Reader",
						DataUtil.byteArrayToString(response.getBytes())));
		return response;
	}

	/**
	 * Method getPIVData.
	 * 
	 * @param pivObjectTag
	 *            Tag
	 * @return CommandAPDU
	 * @throws IOException
	 */
	public static CommandAPDU getDataAPDU(Tag pivObjectTag) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] tag_bytes = pivObjectTag.getBytes();
		baos.write(PIVAPDUInterface.PIV_GET_DATA_HEADER);
		baos.write(tag_bytes.length + 2);
		baos.write((byte) 0x5c);
		baos.write(tag_bytes.length);
		baos.write(tag_bytes);
		baos.write(0x00);
		return new CommandAPDU(baos.toByteArray());
	}

	/**
	 * Method getPIVData.
	 * 
	 * @param pivObjectTag
	 *            Tag
	 * @return PIVDataTempl
	 * @throws IOException
	 * @throws InvalidResponseException
	 */
	private PIVDataTempl getPIVData(Tag pivObjectTag) throws IOException,
			InvalidResponseException {
		PIVDataTempl data = null;
		try {
			ResponseAPDU response = transmit(getDataAPDU(pivObjectTag));
			int status_word = response.getSW();
			int SW1 = response.getSW1();
			int SW2 = response.getSW2();
			if (SW1 == 0x61) {
				ByteArrayOutputStream rbaos = new ByteArrayOutputStream();
				rbaos.write(response.getData());
				while (SW1 == 0x61) {
					// Craft a GET-DATA APDU to collect the bytes remaining
					if (SW2 == 0x00) {
						response = transmit(new CommandAPDU(
								DataUtil.stringToByteArray("00C0000000")));
					} else {
						CommandAPDU remain = new CommandAPDU(0x00, 0xc0, 0x00,
								0x00, SW2);
						response = transmit(remain);
					}
					rbaos.write(response.getData());
					SW1 = response.getSW1();
					SW2 = response.getSW2();
				}
				data = new PIVDataTempl(rbaos.toByteArray());
			} else if (status_word == PIVAPDUInterface.PIV_SW_SUCCESSFUL_EXECUTION) {
				if (response.getData().length <= 2) {
					Log.d(TAG, "Response APDU is empty.");
					data = null;
				} else {
					data = new PIVDataTempl(response.getData());
				}
			} else if (status_word == PIVAPDUInterface.PIV_SW_OBJECT_OR_APPLICATION_NOT_FOUND) {
				Log.d(TAG, "Tag Not Found.");
				data = null;
			} else if (status_word == PIVAPDUInterface.PIV_SW_SECURITY_CONDITION_NOT_SATISFIED) {
				Log.d(TAG, "Security Condition Not Satisfied");
				data = null;
			} else {
				Log.d(TAG, "Error");
				data = null;
			}
		} catch (java.io.IOException ex) {
			throw new IOException(ex);
		}
		return data;
	}

	/**
	 * Method cardDataAvailable.
	 * 
	 * @return boolean
	 */
	public boolean cardDataAvailable() {
		return dataavailable;
	}

	/**
	 * Method getData.
	 * 
	 * @return CardData80073
	 */
	public CardData80073 getData() {
		dataavailable = false;
		return carddata;
	}

	/**
	 * Method isRunning.
	 * 
	 * @return boolean
	 */
	public boolean isRunning() {
		return isRunning;
	}

	public synchronized void stop() {
		Log.d(TAG, "stopping reader thread");
		if (readerThread != null) {
			readerThread.interrupt();
			isRunning = false;
			Log.d(TAG, "reader thread running: " + isRunning);
		}
		Log.d(TAG, "Resetting reader state");
		if (channel != null) {
			if (channel.isConnected()) {
				channel.close();
			}
			channel = null;
		}
	}

}
