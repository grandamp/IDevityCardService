package com.idevity.android.contact;

import java.util.Calendar;

import org.keysupport.util.DataUtil;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcelable;
import android.os.RemoteException;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import com.idevity.card.read.SettingsActivity;
import com.idevity.card.service.IDevityCardService;
import com.idevity.card.service.R;

/*
 * TODO:  Rather than forward the UsbDevice only
 * to the CardProxy, we should restructure this
 * to operate more like the EmulationActivity.
 * 
 * Upon registering with the IDevityCardService
 * we should send the UsbDevice to the service
 * and send any connect/disconnect intents as
 * messages to the service.
 * 
 * This SHOULD yield better performance, because the current method is:
 * 
 * PCD <=> HCE Service <=> Emulation Service <=> CardProxy <=> UsbDevice
 * 
 * and will be:
 * 
 * PCD <=> HCE Service <=> Emulation Service <=> UsbDevice
 * 
 * This should allow us to also get log data using the messages
 * rather than the old-school UI update thread.
 * 
 * Need service message types for:
 * 
 * -USB_READER_CONNECT
 * -USB_READER_DISCONNECT
 * -CARD_PRESENT
 * -CARD_REMOVED
 * -GET_CARD_DATA
 * 
 * Need code here to:
 * 
 * -Register with the service
 * -Send the USB device to the service
 * -Receive CARD_PRESENT & CARD_REMOVED messages
 * -Receive command and response APDUs to log
 * -Send command to request card data
 * -Send user PIN to service
 * -Receive a CardData80073 object from service
 * 
 * Need code in the service to perform the above, and:
 * 
 * -process apdus to and from the card
 * -monitor for card removal and insertion
 * -call another class to build the data object
 * 
 * Finally, we need some code to check for a reader in the event
 * the activity was not launched with a ACTION_USB_DEVICE_ATTACHED
 * intent.
 * 
 */
public class ProxyActivity extends Activity {

	private static final String TAG = ProxyActivity.class.getSimpleName();
	private static final boolean debug = true;

	private static final String ACTION_USB_PERMISSION = "com.idevity.android.contact.USB_PERMISSION";
	private PendingIntent mPermissionIntent;

	private UsbManager mManager;
	private UsbDevice usbDevice;
	private CardProxy proxy;
	
	private StatusFragment sf = null;
	private LogFragment lf = null;

	/** Messenger for communicating with service. */
	static Messenger mService = null;

	/** Flag indicating whether we have called bind on the service. */
	boolean mIsBound;

	private boolean mReceiverRegistered = false;

	private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
		@Override
		public void onReceive(Context context, Intent intent) {
			String action = intent.getAction();
			if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
				synchronized (this) {
					UsbDevice device = (UsbDevice) intent
							.getParcelableExtra(UsbManager.EXTRA_DEVICE);
					if (proxy != null) {
						proxy.deviceDisconnected(device);
						/*
						 * Begin code to send device to service
						 */
						Parcelable usbDevice = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
						Message res = Message.obtain(null, IDevityCardService.USB_READER_DISCONNECT, 0, 0);
						Bundle rBundle = new Bundle();
						rBundle.putParcelable("USBDEVICE", usbDevice);
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
						/*
						 * End code to send device to service
						 */

					}
				}
			}
		}
	};

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
//				byte[] resAPDU = processAPDU(reqAPDU);
				
				Message res = Message.obtain(null, IDevityCardService.MSG_RESPONSE_APDU, 0, 0);
				Bundle rBundle = new Bundle();
//				rBundle.putByteArray("APDU", resAPDU);
				Log.d(TAG, "Objects in sent bundle: " + bundle.size());
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
//				log("[" + System.currentTimeMillis() + "]" + message + "\n");
				break;
			default: {
				Log.d(TAG, "Default handler reached!");
				//super.handleMessage(msg);
				break;
			}
			}
		}
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_proxy);

		lf = (LogFragment) getFragmentManager().findFragmentById(
				R.id.logContainer);
		sf = (StatusFragment) getFragmentManager().findFragmentById(
				R.id.statusContainer);
		sf.setReaderStatus("Disconnected");

		/****************** Launch UI Updating Thread ******************/
		Thread thread = new Thread() {
			@Override
			public void run() {
				try {
					while (!isInterrupted()) {
						Thread.sleep(10);
						runOnUiThread(new Runnable() {
							@Override
							public void run() {
								if (proxy != null) {
									if (proxy.logUpdated()) {
										String lognibble = proxy.getLog();
										lf.appendLog(lognibble);
									}
									if (proxy.isReaderConnected()) {
										sf.setReaderStatus("Connected");
									} else {
										sf.setReaderStatus("Disconnected");
									}
									sf.setCardStatus(proxy.isCardInserted());
								}
							}
						});
					}
				} catch (InterruptedException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
			}
		};
		thread.start();

		Intent intent = getIntent();
		processIntent(intent);

	}

	@Override
	protected void onNewIntent(Intent intent) {
		processIntent(intent);
	}

	protected void processIntent(Intent intent) {

		// Get USB manager
		mManager = (UsbManager) getSystemService(Context.USB_SERVICE);
		if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(intent.getAction())) {
			usbDevice = (UsbDevice) intent
					.getParcelableExtra(UsbManager.EXTRA_DEVICE);
		}
		// Register receiver for USB permission and disconnect notification
		mPermissionIntent = PendingIntent.getBroadcast(this, 0, new Intent(
				ACTION_USB_PERMISSION), 0);
		IntentFilter filter = new IntentFilter();
		filter.addAction(ACTION_USB_PERMISSION);
		filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
		this.registerReceiver(mReceiver, filter);
		this.mReceiverRegistered = true;
		mManager.requestPermission(usbDevice, mPermissionIntent);

		/*
		 * Begin code to send device to service
		 */
		Parcelable usbDev = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
		Message res = Message.obtain(null, IDevityCardService.USB_READER_CONNECT, 0, 0);
		Bundle rBundle = new Bundle();
		rBundle.putParcelable("USBDEVICE", usbDev);
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
		/*
		 * End code to send device to service
		 */


		/****************** Launch the Proxy ******************/
		if (debug) {
			Log.d(TAG, "Calling CardProxy...");
		}
		proxy = new CardProxy(this, mManager, usbDevice);

	}
	
	@Override
	protected void onResume(){
		// Register receiver for USB permission and disconnect notification
		mPermissionIntent = PendingIntent.getBroadcast(this, 0, new Intent(
				ACTION_USB_PERMISSION), 0);
		IntentFilter filter = new IntentFilter();
		filter.addAction(ACTION_USB_PERMISSION);
		filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
		this.registerReceiver(mReceiver, filter);
		mManager.requestPermission(usbDevice, mPermissionIntent);
		this.mReceiverRegistered = true;
		super.onResume();
	}

	@Override
	protected void onPause() {
		if (this.mReceiverRegistered) {
			this.unregisterReceiver(mReceiver);
			this.mReceiverRegistered = false;
		}
		super.onPause();
	}

	@Override
	protected void onStop() {
		if (this.mReceiverRegistered) {
			this.unregisterReceiver(mReceiver);
			this.mReceiverRegistered = false;
		}
		super.onStop();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.emulation_log, menu);
		return true;
	}

	/**
	 * Method onOptionsItemSelected.
	 * 
	 * @param item
	 *            MenuItem
	 * @return boolean
	 */
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		/*
		 * Handle item selection
		 */
		switch (item.getItemId()) {
		case R.id.action_share_log:
			shareData();
			return true;
		case R.id.action_settings:
			Intent callsettings = new Intent(this, SettingsActivity.class);
			startActivity(callsettings);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	@SuppressWarnings("null")
	private void shareData() {

		/*
		 * Save card data to a file so we can attach it to our email
		 */
//		byte[] cardDataModel = cardData.toByteArray();
//		String cdmFileName = cardData.digestString() + ".katd";
//		File cdmFile = null;
//		try {
//			cdmFile = new File(getExternalFilesDir(null), cdmFileName);
//			FileOutputStream fos = new FileOutputStream(cdmFile);
//			fos.write(cardDataModel);
//			fos.flush();
//			fos.close();
//			if (debug) {
//				Log.d(TAG, "Wrote to file: " + cdmFileName);
//			}
//		} catch (IOException e1) {
//			Log.e(TAG, "Failed to create datamodel file.");
//			Log.e(TAG, "Error: " + e1.getMessage());
//			if (debug) {
//				e1.printStackTrace();
//			}
//		}
//		Uri cdmUri = Uri.fromFile(cdmFile);
//		if (debug) {
//			Log.d(TAG, "CDM File: " + cdmUri.toString());
//		}

		/*
		 * Build the email intent we always have, but add the file URI
		 */
		Intent sharingIntent = new Intent(android.content.Intent.ACTION_SEND);
		sharingIntent.setType("message/rfc822");

		Calendar now = Calendar.getInstance();
		String[] defEmail = { getString(R.string.supportemail) };

		PackageManager manager = this.getPackageManager();
		PackageInfo info = null;
		try {
			info = manager.getPackageInfo(this.getPackageName(), 0);
		} catch (NameNotFoundException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
		String ls = System.getProperty("line.separator");
		StringBuffer mail_body = new StringBuffer();
		mail_body.append("############################################" + ls);
		mail_body.append("########  Device and OS Information ########" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("Device Manufacturer:       " + Build.MANUFACTURER
				+ ls);
		mail_body.append("Device Model:              " + Build.MODEL + ls);
		mail_body.append("Device Model Code Name:    " + Build.BOARD + ls);
		mail_body.append("Android Brand:             " + Build.BRAND + ls);
		mail_body.append("Android Version Code Name: " + Build.VERSION.CODENAME
				+ ls);
		mail_body.append("Android Rel Version:       " + Build.VERSION.RELEASE
				+ ls);
		mail_body.append("Android Inc Version:       "
				+ Build.VERSION.INCREMENTAL + ls);
		mail_body.append("Android SDK Version:       " + Build.VERSION.SDK_INT
				+ ls);
		mail_body.append("App Package Name:          " + info.packageName + ls);
		mail_body.append("App Version Code:          " + info.versionCode + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("#########  Additional Information  #########" + ls);
		mail_body.append("############################################" + ls);
		mail_body
				.append("[ Please provide any additional feedback here ]" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("################  APDU LOG  ################" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append(lf.getLog());

		String shareSubject = "KATD Proxy Log  - "
				+ now.getTime().toString();
		sharingIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
				shareSubject);
		sharingIntent.putExtra(android.content.Intent.EXTRA_TEXT,
				mail_body.toString());
//		sharingIntent.putExtra(android.content.Intent.EXTRA_STREAM, cdmUri);
		sharingIntent.putExtra(android.content.Intent.EXTRA_EMAIL, defEmail);
		startActivity(Intent.createChooser(sharingIntent, "Share Via..."));
	}

}
