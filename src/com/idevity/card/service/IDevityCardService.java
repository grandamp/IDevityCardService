package com.idevity.card.service;

import org.keysupport.util.DataUtil;

import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Toast;

import com.acs.smartcard.Reader;
import com.idevity.card.service.applets.Applet80073;
import com.idevity.card.service.applets.PIVApplet;
import com.idevity.card.data.CardData80073;

/**
 * This class represents our overall card service.  It will
 * interface with NFC (contactless) and USB (contact) to 
 * communicate with a smart card.  It will also provide card
 * emulation services so that the Android NFC HCE can register
 * with us when in contact with a PCD (a contactless reader).
 * 
 * The intent is to have (at most) three forms of clients that 
 * will communicate with us:
 * 
 * -Clients that want data from a card
 * 
 *   This may be through NFC (contactless) and USB (Contact).
 *   When finalized, we will also implement the NIST 800-73-4
 *   Virtual Contactless Interface as a reference implementation.
 * 
 * -Clients that want us to emulate a card (Via NFC)
 * 
 *  We will require an Applet and an associated Android NFC HCE
 *  implementation.  For the moment, our reference implementation
 *  is for PIV (NIST 800-73).  Based on the way NFC HCE works in
 *  KitKat, we must have the HCE service implementation up front,
 *  as the AIDs must be pre-registered via the manifest.  The new
 *  "L" release will allow us to dynamically register AIDs, and may
 *  allow us to have a "generic" HCE implementation, passing it
 *  the AIDs for the emulated applet.  We will need to provide an
 *  abstract Applet implementation (similar to the HCE service)
 *  so that a developer may write their own implementation.
 * 
 * -Clients that are an extension of the Android NFC HCE service
 *  to communicate with our emulated card.
 *  
 *  As stated above, this may no longer be necessary if we
 *  require the "L" Android release as our baseline.  This will
 *  allow us to derive a generic HCE client that will dynamically
 *  register the AIDs when a client passes an applet to us that
 *  they would like implemented.
 * 
 * @author tejohnson
 *
 */
public class IDevityCardService extends Service {

	private static final String TAG = IDevityCardService.class.getSimpleName();
	private static final boolean debug = true;

	/*
	 *  For showing and hiding our notification.
	 */
	NotificationManager mNM;

	/*
	 *  Keeps track of all current registered clients.
	 */
	static Messenger mHCEClient;
	static Messenger mLogClient = null;
	static Messenger mProxyClient = null;

	/*
	 * Holds Card Data
	 */
	private static CardData80073 cardData = null;

	/*
	 * Provides PIV Emulation
	 */
	private static Applet80073 applet = null;

	/*
	 * Provides Communication to Contact reader and
	 * acts as a proxy for HCE to access
	 */
	private UsbManager mManager;
	private Reader mReader;
	private UsbDevice usbDevice;

	/*
	 * Commands to the service to register an HCE client
	 * 
	 * This is a client that provides Android NFC Host
	 * card emulation services.
	 */
	public static final int MSG_REGISTER_HCE_CLIENT = 1;
	public static final int MSG_UNREGISTER_HCE_CLIENT = 2;

	/*
	 * Commands to the service to register a Log client
	 * 
	 * This is a client that merely logs APDUs.
	 * 
	 * For the time being, it also passes a data object
	 * for the emulation applet within this service.
	 * 
	 * It should be merged with the proxy client.
	 */
	public static final int MSG_REGISTER_LOG_CLIENT = 3;
	public static final int MSG_UNREGISTER_LOG_CLIENT = 4;

	/*
	 * Commands to the service to register a Proxy client
	 * 
	 * This is a client that merely logs APDUs.
	 * 
	 * For the time being, it also passes a UsbDevice object
	 * for the proxy within this service. I.e., USB Connect
	 * and Disconnect intents.
	 * 
	 * It should be merged with the Log client.
	 */
	public static final int MSG_REGISTER_PROXY_CLIENT = 5;
	public static final int MSG_UNREGISTER_PROXY_CLIENT = 6;

	/*
	 * Commands to the service conveying data and interaction as
	 * well as String identifiers for key/values sent in a bundle
	 */
	
	/*
	 * APDUs will be transmitted as byte[]
	 */
	public static final int MSG_REQUEST_APDU = 7;
	public static final int MSG_RESPONSE_APDU = 8;
	public static final String APDU_OBJ = "APDU";
	/*
	 * Informational messages will be transmitted as
	 * a String
	 */
	public static final int MSG_SERVICE_MESSAGE = 9;
	public static final String MSG_OBJ = "MSG";
	/*
	 * The following messages have no payload
	 */
	public static final int MSG_SERVICE_STARTED = 10;
	public static final int CARD_PRESENT = 11;
	public static final int CARD_REMOVED = 12;
	/*
	 * Data and Authentication objects will be
	 * transmitted as byte[]
	 */
	public static final int MSG_CARD_DATA = 13;
	public static final String DATA_OBJ = "DATA";
	public static final int GET_CARD_DATA = 14;
	public static final String EAUTH_OBJ = "EAUTH";
	/*
	 * UsbDevice objects will be transmitted in a
	 * Parcelable object
	 */
	public static final int USB_READER_CONNECT = 15;
	public static final int USB_READER_DISCONNECT = 16;
	public static final String USB_OBJ = "USBDEVICE";
	/*
	 * Test case objects will be sent in a byte[]
	 * object.
	 * 
	 * TODO: Create a TestCase object similar to
	 * CardData80073 that encodes known test cases
	 * into identifiers, then serialize into a byte[]
	 * using BER-TLV
	 */
	public static final int MSG_TEST_CASE = 17;
	public static final String TC_OBJ = "TEST_CASE";

	/**
	 * Handler of incoming messages from clients.
	 */
	static class IncomingHandler extends Handler {
		@Override
		public void handleMessage(Message msg) {

			Bundle rBundle = null;

			/*
			 * Begin Message Handler
			 */
			switch (msg.what) {
			case MSG_REGISTER_HCE_CLIENT: {
				mHCEClient = msg.replyTo;
				if (mLogClient != null) {
					Message msgMSG = Message.obtain(null,
							IDevityCardService.MSG_SERVICE_MESSAGE, 0, 0);
					Bundle bundle = new Bundle();
					bundle.putString(MSG_OBJ, "[New connection from PCD]");
					msgMSG.setData(bundle);
					try {
						mLogClient.send(msgMSG);
					} catch (RemoteException e) {
						mLogClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else {
					if (debug) {
						Log.d(TAG, "Client handle is NULL!");
					}
				}
				break;
			}
			case MSG_UNREGISTER_HCE_CLIENT: {
				mHCEClient = null;
				break;
			}
			case MSG_REGISTER_LOG_CLIENT: {
				mLogClient = msg.replyTo;
				if (mLogClient != null) {
					Message started = Message.obtain(null,
							IDevityCardService.MSG_SERVICE_STARTED, 0, 0);
					try {
						mLogClient.send(started);
					} catch (RemoteException e) {
						mLogClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else {
					if (debug) {
						Log.d(TAG, "Client handle is NULL!");
					}
				}
				break;
			}
			case MSG_UNREGISTER_LOG_CLIENT: {
				mLogClient = null;
				break;
			}
			case MSG_REGISTER_PROXY_CLIENT: {
				mProxyClient = msg.replyTo;
				if (mLogClient != null) {
					Message started = Message.obtain(null,
							IDevityCardService.MSG_SERVICE_STARTED, 0, 0);
					try {
						mProxyClient.send(started);
					} catch (RemoteException e) {
						mProxyClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else {
					if (debug) {
						Log.d(TAG, "Client handle is NULL!");
					}
				}
				break;
			}
			case MSG_UNREGISTER_PROXY_CLIENT: {
				mProxyClient = null;
				break;
			}
			case MSG_CARD_DATA: {
				if (debug) {
					Log.d(TAG,
							"Data received.  Initializing our emulation applet.");
				}
				rBundle = msg.getData();
				if (debug) {
					Log.d(TAG, "Objects in received bundle: "
						+ rBundle.size());
				}
				byte[] tlvData = rBundle.getByteArray(DATA_OBJ);
				if (tlvData != null) {
					cardData = new CardData80073(tlvData);
				} else {
					cardData = new CardData80073();
				}
				// Initialize our applet
				applet = new PIVApplet(cardData);
				break;
			}
			case USB_READER_CONNECT: {
				/*
				 * TODO: Manage UsbDevice if it was forwarded from
				 * an Activity
				 */
				break;
			}
			case USB_READER_DISCONNECT: {
				/*
				 * TODO: Manage UsbDevice if it was forwarded from
				 * an Activity
				 */
				break;
			}
			case MSG_REQUEST_APDU: {
				if (debug) {
					Log.d(TAG, "Received: MSG_REQUEST_APDU");
				}
				rBundle = msg.getData();
				if (debug) {
					Log.d(TAG, "Objects in received bundle: "
						+ rBundle.size());
				}
				byte[] mReqAPDUValue = rBundle.getByteArray(APDU_OBJ);
				if (debug) {
					Log.d(TAG,
							"APDU: "
									+ DataUtil.byteArrayToString(mReqAPDUValue));
				}
				routeAPDU(mReqAPDUValue);
				break;
			}
			case MSG_RESPONSE_APDU: {
				/*
				 * TODO:  This functionality may be removed,
				 * as this service will like be the source of most
				 * ResponseAPDUs
				 */
				if (debug) {
					Log.d(TAG, "Received: MSG_RESPONSE_APDU");
				}
				rBundle = msg.getData();
				if (debug) {
					Log.d(TAG, "Objects in received bundle: "
						+ rBundle.size());
				}
				byte[] mResAPDUValue = rBundle.getByteArray(APDU_OBJ);
				if (debug) {
					Log.d(TAG,
							"APDU: "
									+ DataUtil.byteArrayToString(mResAPDUValue));
				}
				if (mHCEClient != null) {
					Message msgAPDU = Message.obtain(null,
							IDevityCardService.MSG_RESPONSE_APDU, 0, 0);
					Bundle bundle = new Bundle();
					bundle.putByteArray(APDU_OBJ, mResAPDUValue);
					msgAPDU.setData(bundle);
					try {
						mHCEClient.send(msgAPDU);
					} catch (RemoteException e) {
						mHCEClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else {
					if (debug) {
						Log.d(TAG, "Client handle is NULL!");
					}
				}
				break;
			}
			case MSG_SERVICE_MESSAGE: {
				if (debug) {
					Log.d(TAG, "Received: MSG_SERVICE_MESSAGE");
				}
				rBundle = msg.getData();
				if (debug) {
					Log.d(TAG, "Objects in received bundle: "
						+ rBundle.size());
				}
				String message = rBundle.getString(MSG_OBJ);
				if (debug) {
					Log.d(TAG, "MSG: " + message);
				}
				if (mLogClient != null) {
					Message msgMSG = Message.obtain(null,
							IDevityCardService.MSG_SERVICE_MESSAGE, 0, 0);
					Bundle bundle = new Bundle();
					bundle.putString(MSG_OBJ, message);
					msgMSG.setData(bundle);
					try {
						mLogClient.send(msgMSG);
					} catch (RemoteException e) {
						mLogClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else if (mProxyClient != null) {
					Message msgMSG = Message.obtain(null,
							IDevityCardService.MSG_SERVICE_MESSAGE, 0, 0);
					Bundle bundle = new Bundle();
					bundle.putString(MSG_OBJ, message);
					msgMSG.setData(bundle);
					try {
						mProxyClient.send(msgMSG);
					} catch (RemoteException e) {
						mProxyClient = null;
						Log.e(TAG, "Error: " + e.getMessage());
						if (debug) {
							e.printStackTrace();
						}
					}
				} else {
					if (debug) {
						Log.d(TAG, "Client handle is NULL!");
					}
				}
				break;
			}
			default: {
				super.handleMessage(msg);
				break;
			}
			/*
			 * End Message Handler
			 */
			}
		}
	}

	/**
	 * Target we publish for clients to send messages to IncomingHandler.
	 */
	final Messenger mMessenger = new Messenger(new IncomingHandler());

	@Override
	public void onCreate() {
		Toast.makeText(this, R.string.remote_service_started,
				Toast.LENGTH_SHORT).show();
	}

	@Override
	public void onDestroy() {
		Toast.makeText(this, R.string.remote_service_stopped,
				Toast.LENGTH_SHORT).show();
	}

	/**
	 * When binding to the service, we return an interface to our messenger for
	 * sending messages to the service.
	 */
	@Override
	public IBinder onBind(Intent intent) {
		return mMessenger.getBinder();
	}

	private static void routeAPDU(byte[] apdu) {
		if (mProxyClient != null) {
			if (debug) {
				Log.d(TAG, "Routing request APDU to Proxy Client!");
			}
			Message msgAPDU = Message.obtain(null,
					IDevityCardService.MSG_REQUEST_APDU, 0, 0);
			Bundle bundle = new Bundle();
			bundle.putByteArray(APDU_OBJ, apdu);
			msgAPDU.setData(bundle);
			try {
				mProxyClient.send(msgAPDU);
			} catch (RemoteException e) {
				mProxyClient = null;
				Log.e(TAG, "Error: " + e.getMessage());
				if (debug) {
					e.printStackTrace();
				}
			}
		} else if (mLogClient != null) {
			if (debug) {
				Log.d(TAG, "Routing request APDU to Log Client!");
			}
			Message msgAPDU = Message.obtain(null,
					IDevityCardService.MSG_REQUEST_APDU, 0, 0);
			Bundle bundle = new Bundle();
			bundle.putByteArray(APDU_OBJ, apdu);
			msgAPDU.setData(bundle);
			try {
				mLogClient.send(msgAPDU);
			} catch (RemoteException e) {
				mLogClient = null;
				Log.e(TAG, "Error: " + e.getMessage());
				if (debug) {
					e.printStackTrace();
				}
			}
			if (mHCEClient != null) {
				if (debug) {
					Log.d(TAG, "Sending request APDU to emulated applet!");
				}
				byte[] mResAPDUValue = applet.processCommand(apdu).getBytes();
				if (debug) {
					Log.d(TAG, "Sending response APDU to HCE service!");
				}
				Message rAPDU = Message.obtain(null,
						IDevityCardService.MSG_RESPONSE_APDU, 0, 0);
				Bundle rBundle = new Bundle();
				rBundle.putByteArray(APDU_OBJ, mResAPDUValue);
				rAPDU.setData(rBundle);
				try {
					mLogClient.send(rAPDU);
				} catch (RemoteException e) {
					mLogClient = null;
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
				try {
					mHCEClient.send(rAPDU);
				} catch (RemoteException e) {
					mHCEClient = null;
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
			}
		} else {
			if (debug) {
				Log.d(TAG, "All clients are NULL! Swallowing APDU!");
			}
		}
	}

}