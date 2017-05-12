package com.idevity.android.nfc.hce;

import org.keysupport.util.DataUtil;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

import com.idevity.card.service.IDevityCardService;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: SmartCardService.java 235 2013-11-09 16:30:34Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 235 $
 * 
 *          Changed: $LastChangedDate: 2013-11-07 00:31:22 -0500 (Thu, 07 Nov
 *          2013) $
 *****************************************************************************/
public class PIVCardService extends HostApduService {

	private static final String TAG = PIVCardService.class.getSimpleName();
	private static final boolean debug = true;

	/** Messenger for communicating with service. */
	Messenger mService = null;
	
	/** Flag indicating whether we have called bind on the service. */
	boolean mIsBound;

	/**
	 * Handler of incoming messages from service.
	 */
	class IncomingHandler extends Handler {
		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case IDevityCardService.MSG_RESPONSE_APDU:
				Log.d(TAG, "Received: MSG_RESPONSE_APDU");
				Bundle bundle = msg.getData();
				byte[] mAPDU = bundle.getByteArray("APDU");
				Log.d(TAG, "APDU: " + DataUtil.byteArrayToString(mAPDU));
				sendResponseApdu(mAPDU);
				break;
			default:
				super.handleMessage(msg);
			}
		}
	}
	
	/**
	 * Target we publish for clients to send messages to IncomingHandler.
	 */
	final Messenger mMessenger = new Messenger(new IncomingHandler());
	
	/**
	 * Class for interacting with the main interface of the service.
	 */
	private ServiceConnection mConnection = new ServiceConnection() {
		public void onServiceConnected(ComponentName className, IBinder service) {
			// This is called when the connection with the service has been
			// established, giving us the service object we can use to
			// interact with the service. We are communicating with our
			// service through an IDL interface, so get a client-side
			// representation of that from the raw service object.
			mService = new Messenger(service);
			// We want to monitor the service for as long as we are
			// connected to it.
			try {
				Message msg = Message.obtain(null,
						IDevityCardService.MSG_REGISTER_HCE_CLIENT);
				msg.replyTo = mMessenger;
				mService.send(msg);
			} catch (RemoteException e) {
				// In this case the service has crashed before we could even
				// do anything with it; we can count on soon being
				// disconnected (and then reconnected if it can be restarted)
				// so there is no need to do anything here.
			}
		}

		public void onServiceDisconnected(ComponentName className) {
			// This is called when the connection with the service has been
			// unexpectedly disconnected -- that is, its process crashed.
			mService = null;
		}
	};

	void doBindService() {
		// Establish a connection with the service. We use an explicit
		// class name because there is no reason to be able to let other
		// applications replace our component.
		bindService(
				new Intent(getApplicationContext(), IDevityCardService.class),
				mConnection, Context.BIND_IMPORTANT);
		mIsBound = true;
	}

	void doUnbindService() {
		if (mIsBound) {
			// If we have received the service, and hence registered with
			// it, then now is the time to unregister.
			if (mService != null) {
				try {
					Message msg = Message.obtain(null,
							IDevityCardService.MSG_UNREGISTER_HCE_CLIENT);
					msg.replyTo = mMessenger;
					mService.send(msg);
				} catch (RemoteException e) {
					// There is nothing special we need to do if the service
					// has crashed.
				}
			}
			// Detach our existing connection.
			unbindService(mConnection);
			mIsBound = false;
		}
	}

	/**
	 * The card service will need to handle the Command and Response APDU
	 * Chaining using processCommandApdu and sendResponseApdu.
	 * 
	 * Outstanding Questions:
	 * 
	 * -The service should maintain a running APDU Log. How should we make it
	 * available? -How will the configuration app maintain this service to
	 * inject a new CardData80073?
	 */
	@Override
	public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
		if (debug) {
			Log.d(TAG, "APDU Received: " + DataUtil.byteArrayToString(apdu));
		}
		Message msg = Message.obtain(null, IDevityCardService.MSG_REQUEST_APDU, 0, 0);
		Bundle bundle = new Bundle();
		Log.d(TAG, "Sending: " + DataUtil.byteArrayToString(apdu));
		bundle.putByteArray("APDU", apdu);
		System.out.println("Objects in sent bundle: " + bundle.size());
		msg.setData(bundle);
		try {
			mService.send(msg);
		} catch (RemoteException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@Override
	public void onDeactivated(int reason) {
		/*
		 * Our applet will need to maintain state based on the commands it
		 * receives.
		 * 
		 * TODO: Once deactivated, we will need to reset the applet's state.
		 */
		switch (reason) {
		case HostApduService.DEACTIVATION_DESELECTED: {
			/*
			 * We were deselected.
			 */
			String message = "[Applet was deseleted]";
			if (debug) {
				Log.d(TAG, message);
			}
			Message msg = Message.obtain(null, IDevityCardService.MSG_SERVICE_MESSAGE, 0, 0);
			Bundle bundle = new Bundle();
			Log.d(TAG, "Sending: " + message);
			bundle.putString("MSG", message);
			System.out.println("Objects in sent bundle: " + bundle.size());
			msg.setData(bundle);
			try {
				mService.send(msg);
			} catch (RemoteException e) {
				e.printStackTrace();
			}

			doUnbindService();
			break;
		}
		case HostApduService.DEACTIVATION_LINK_LOSS: {
			/*
			 * We lost our connection to the PCD.
			 */
			String message = "[Lost communication with PCD]";
			if (debug) {
				Log.d(TAG, message);
			}
			Message msg = Message.obtain(null, IDevityCardService.MSG_SERVICE_MESSAGE, 0, 0);
			Bundle bundle = new Bundle();
			Log.d(TAG, "Sending: " + message);
			bundle.putString("MSG", message);
			System.out.println("Objects in sent bundle: " + bundle.size());
			msg.setData(bundle);
			try {
				mService.send(msg);
			} catch (RemoteException e) {
				e.printStackTrace();
			}
			doUnbindService();
			break;
		}
		default: {
			/*
			 * Do nothing, as we should never get here.
			 */
		}
		}

	}

	@Override
	public void onCreate() {
		doBindService();
		String message = "New connection from PCD.";
		if (debug) {
			Log.d(TAG, message);
		}
		
		/*
		 * TODO: Determine our applet type based on the data, and then create
		 * it's instance.
		 */
	}

	@Override
	public void onDestroy() {
		if (debug) {
			Log.d(TAG, "Emulation Service Stopping");
		}
		
		/*
		 * TODO: Save the APDU log as "results" for the user to view.
		 */
	}

}
