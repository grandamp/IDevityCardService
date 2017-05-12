/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 *****************************************************************************/

package com.idevity.android.contact;

import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;

import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.smartcardio.ResponseAPDU;
import org.keysupport.util.DataUtil;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import com.acs.smartcard.Reader;
import com.acs.smartcard.Reader.OnStateChangeListener;
import com.acs.smartcard.ReaderException;
import com.idevity.android.nfc.InvalidResponseException;
import com.idevity.card.service.IDevityCardService;

/**
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 */
public class CardProxy {

	private static final String TAG = CardProxy.class.getSimpleName();
	private static final boolean debug = true;

	private Context ctx;
	private UsbDevice usbDevice;
	private StringBuffer log;
	private boolean readerConnected = false;
	private boolean cardInserted = false;
	private boolean logupdated = false;

	@SuppressWarnings("unused")
	private UsbManager mManager;
	private Reader mReader;
	
	/** Messenger for communicating with service. */
	static Messenger mService = null;
	
	/** Flag indicating whether we have called bind on the service. */
	boolean mIsBound;

	/**
	 * Constructor for CardProxy.
	 * 
	 * @param ctx
	 *            Context
	 * @param pop 
	 */
	public CardProxy(Context ctx, UsbManager mManager, UsbDevice usbDevice) {
		this.ctx = ctx;
		this.mManager = mManager;
		this.usbDevice = usbDevice;
		this.log = new StringBuffer();
		
		// Initialize reader
		mReader = new Reader(mManager);
		mReader.setOnStateChangeListener(new OnStateChangeListener() {
			@Override
			public void onStateChange(int slotNum, int prevState, int currState) {
				if (currState == Reader.CARD_PRESENT) {
					cardInserted = true;
					Log.d(TAG, "Card Inserted.");
					performWarmReset();
				} else {
					cardInserted = false;
					Log.d(TAG, "Card Removed.");
				}
			}
		});

		if (usbDevice != null) {
			attach();
		}

		if (debug) {
			log("[" + System.currentTimeMillis() + "]" + "Card Proxy Initialized\n");
		}
		
		//Connect to the Emulation Service
		doBindService();
	}

	/**
	 * Handler of incoming messages from service.
	 */
	class IncomingHandler extends Handler {
		
		Calendar now = Calendar.getInstance();
		
		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case IDevityCardService.MSG_REQUEST_APDU: {
				Log.d(TAG, "Received: MSG_REQUEST_APDU");
				Bundle bundle = msg.getData();
				byte[] reqAPDU = bundle.getByteArray("APDU");
				Log.d(TAG, "APDU: " + DataUtil.byteArrayToString(reqAPDU));
				byte[] resAPDU = processAPDU(reqAPDU);
				
				Message res = Message.obtain(null, IDevityCardService.MSG_RESPONSE_APDU, 0, 0);
				Bundle rBundle = new Bundle();
				rBundle.putByteArray("APDU", resAPDU);
				Log.d(TAG, "Objects in sent bundle: " + rBundle.size());
				res.setData(rBundle);
				try {
					if (mService == null) {
						Log.d(TAG, "Service handle is null!");
					}
					mService.send(res);
				} catch (RemoteException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
				break;
			}
			case IDevityCardService.MSG_SERVICE_MESSAGE:
				Log.d(TAG, "Received: MSG_SERVICE_MESSAGE");
				Bundle bundle = msg.getData();
				Log.d(TAG, "Objects in received bundle: " + bundle.size());
				String message = bundle.getString("MSG");
				Log.d(TAG, "MSG: " + message);
				log("[" + System.currentTimeMillis() + "]" + message + "\n");
				break;
			default: {
				Log.d(TAG, "Default handler reached!");
				//super.handleMessage(msg);
				break;
			}
			}
		}
	}

	private byte[] processAPDU(byte[] apdu) {
		ResponseAPDU response = new ResponseAPDU(ResponseAPDU.SW_UNKNOWN);
		CommandAPDU command = new CommandAPDU(apdu);
		
		if (this.readerConnected && this.cardInserted) {
			//Log.d(TAG, "Sending ");
			try {
				response = transmit(command);
			} catch (IOException e) {
				Log.e(TAG, "Error: " + e.getMessage());
				if (debug) {
					e.printStackTrace();
				}
			} catch (ReaderException e) {
				Log.e(TAG, "Error: " + e.getMessage());
				if (debug) {
					e.printStackTrace();
				}
			}
		}
		return response.getBytes();
	}

	/**
	 * Target we publish for clients to send messages to IncomingHandler.
	 */
	final Messenger mMessenger = new Messenger(new IncomingHandler());
	
	/**
	 * Class for interacting with the main interface of the service.
	 */
	private ServiceConnection mConnection = new ServiceConnection() {
		@Override
		public void onServiceConnected(ComponentName className, IBinder service) {
			mService = new Messenger(service);
			log("Attached to Emulation Service.\n");
			try {
				Message msg = Message.obtain(null,
						IDevityCardService.MSG_REGISTER_PROXY_CLIENT);
				msg.replyTo = mMessenger;
				mService.send(msg);
			} catch (RemoteException e) {
				Log.e(TAG, "Error: " + e.getMessage());
				if (debug) {
					e.printStackTrace();
				}
			}
		}

		@Override
		public void onServiceDisconnected(ComponentName className) {
			mService = null;
		}
	};

	void doBindService() {
		ctx.bindService(
				new Intent(ctx.getApplicationContext(), IDevityCardService.class),
				mConnection, Context.BIND_AUTO_CREATE);
		mIsBound = true;
		Log.d(TAG, "Binding to service");
	}

	void doUnbindService() {
		if (mIsBound) {
			if (mService != null) {
				try {
					Message msg = Message.obtain(null,
							IDevityCardService.MSG_UNREGISTER_LOG_CLIENT);
					msg.replyTo = mMessenger;
					mService.send(msg);
				} catch (RemoteException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
			}
			ctx.unbindService(mConnection);
			mIsBound = false;
		}
	}

	public void attach() {
		try {
			if (!mReader.isOpened()) {
				mReader.open(usbDevice);
				this.readerConnected = true;
			}
		} catch (IllegalArgumentException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
	}

	public void deviceDisconnected(UsbDevice usbDevice) {
		if (mReader != null && mReader.getDevice().equals(usbDevice)) {
			detach();
		}
	}

	public void detach() {
		if (mReader != null) {
			Log.i(TAG, "Closing reader...");
			mReader.close();
			this.readerConnected = false;
			this.cardInserted = false;
		}
	}

	public void performWarmReset() {
		if (debug) {
			Log.d(TAG, String.format("Performing a warm reset."));
			log("[" + System.currentTimeMillis() + "]Performing a warm reset.\n");
		}
		try {
			/*
			 * Logic that captures messages from the service
			 * and exposes it via the log
			 */
			int slotNum = 0;
			// Get ATR
			byte[] atr = mReader.power(slotNum, Reader.CARD_WARM_RESET);
			Log.i(TAG, "Slot " + slotNum + ": Getting ATR...");
			atr = mReader.getAtr(slotNum);
			// Show ATR
			if (atr != null) {
				if (debug) {
					Log.d(TAG, "ATR: " + DataUtil.byteArrayToString(atr));
				}
				log("[" + System.currentTimeMillis() + "]" + "ATR: " + DataUtil.byteArrayToString(atr) + "\n");
			} else {
				if (debug) {
					Log.d(TAG, "ATR: No ATR Provided");
				}
				log("[" + System.currentTimeMillis() + "]" + "ATR: No ATR Provided\n");
			}
			mReader.setProtocol(slotNum, Reader.PROTOCOL_TX);
		} catch (NullPointerException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
			return;
		} catch (ReaderException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
			return;
		}
		if (debug) {
			Log.d(TAG, String.format("Warm reset complete."));
			log("[" + System.currentTimeMillis() + "]Warm reset complete.\n");
		}
		return;
	}

	public boolean isReaderConnected() {
		return this.readerConnected;
	}

	public boolean isCardInserted() {
		return this.cardInserted;
	}

	/**
	 * Method log.
	 * 
	 * @param msg
	 *            String
	 */
	public void log(String msg) {
		log.append(msg);
		logupdated = true;
	}

	/**
	 * Method logUpdated.
	 * 
	 * @return boolean
	 */
	public boolean logUpdated() {
		return logupdated;
	}

	/**
	 * Method getLog.
	 * 
	 * @return String
	 */
	public String getLog() {
		logupdated = false;
		String retlog = log.toString();
		log = new StringBuffer();
		return retlog;
	}

	/**
	 * Method transmit.
	 * 
	 * @param command
	 *            CommandAPDU
	 * @return ResponseAPDU
	 * @throws IOException
	 * @throws ReaderException
	 * @throws InvalidResponseException
	 */
	private ResponseAPDU transmit(CommandAPDU command) throws IOException, ReaderException {
		ResponseAPDU response = new ResponseAPDU(ResponseAPDU.SW_UNKNOWN);
		log(String.format("[" + System.currentTimeMillis() + "][%s] --> %s\n", "Reader", DataUtil.byteArrayToString(command.getBytes())));
		Log.i(TAG, String.format("[" + System.currentTimeMillis() + "][%s] --> %s", "Reader", DataUtil.byteArrayToString(command.getBytes())));
		byte[] respba = new byte[300];
		int respLen = 0;
		try {
			respLen = mReader.transmit(0, command.getBytes(), command.getBytes().length, respba, respba.length);
		} catch (Throwable e) {
			log("[" + System.currentTimeMillis() + "]Error communicating with card in contact reader.\n");
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
		if (respLen >= 2) {
			response = new ResponseAPDU(Arrays.copyOf(respba, respLen));
			log(String.format("[" + System.currentTimeMillis() + "][%s] <-- %s\n", "Reader", DataUtil.byteArrayToString(response.getBytes())));
			Log.i(TAG, String.format("[" + System.currentTimeMillis() + "][%s] <-- %s", "Reader", DataUtil.byteArrayToString(response.getBytes())));
		} else {
			log(String.format("[" + System.currentTimeMillis() + "][%s] <-- %s\n", "Reader", "No response received.  Returning SW_UNKNOWN to HCE."));
			Log.i(TAG, String.format("[" + System.currentTimeMillis() + "][%s] <-- %s", "Reader", "No response received.  Returning SW_UNKNOWN to HCE."));
		}
		return response;
	}

}
