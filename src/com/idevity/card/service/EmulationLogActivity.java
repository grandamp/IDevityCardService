package com.idevity.card.service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;

import org.keysupport.util.DataUtil;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import com.idevity.card.data.CardData80073;
import com.idevity.card.read.Globals;
import com.idevity.card.read.Read80073;
import com.idevity.card.read.SettingsActivity;

public class EmulationLogActivity extends Activity {

	private static final String TAG = EmulationLogActivity.class
			.getSimpleName();
	private static final boolean debug = true;

	/** Messenger for communicating with service. */
	static Messenger mService = null;

	/** Flag indicating whether we have called bind on the service. */
	boolean mIsBound;

	private static CardData80073 cardData = null;
	private static TextView mCallbackText;
	private static ScrollView mCallbackScroll;
	Globals g = Globals.getInstance();

	/**
	 * Handler of incoming messages from service.
	 */
	class IncomingHandler extends Handler {

		Calendar now = Calendar.getInstance();

		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case IDevityCardService.MSG_REQUEST_APDU: {
				if (debug) {
					Log.d(TAG, "Received: MSG_REQUEST_APDU");
				}
				Bundle bundle = msg.getData();
				byte[] mAPDU = bundle.getByteArray("APDU");
				if (debug) {
					Log.d(TAG, "APDU: " + DataUtil.byteArrayToString(mAPDU));
				}
				mCallbackText.append("[" + System.currentTimeMillis()
						+ "][Reader] -> " + DataUtil.byteArrayToString(mAPDU)
						+ "\n");
				mCallbackScroll.fullScroll(View.FOCUS_DOWN);
				break;
			}
			case IDevityCardService.MSG_RESPONSE_APDU: {
				if (debug) {
					Log.d(TAG, "Received: MSG_RESPONSE_APDU");
				}
				Bundle bundle = msg.getData();
				byte[] mAPDU = bundle.getByteArray("APDU");
				if (debug) {
					Log.d(TAG, "APDU: " + DataUtil.byteArrayToString(mAPDU));
				}
				mCallbackText.append("[" + System.currentTimeMillis()
						+ "][Reader] <- " + DataUtil.byteArrayToString(mAPDU)
						+ "\n");
				mCallbackScroll.fullScroll(View.FOCUS_DOWN);
				break;
			}
			case IDevityCardService.MSG_SERVICE_STARTED: {
				Message appData = Message.obtain(null,
						IDevityCardService.MSG_CARD_DATA, 0, 0);
				Bundle bundle = new Bundle();
				if (debug) {
					Log.d(TAG,
							"Initializing with data: "
									+ DataUtil.byteArrayToString(cardData
											.toByteArray()));
				}
				bundle.putByteArray("DATA", cardData.toByteArray());
				if (debug) {
					Log.d(TAG, "Objects in sent bundle: " + bundle.size());
				}
				appData.setData(bundle);
				try {
					if (mService == null) {
						Log.d(TAG, "Service handle is null!");
					}
					mService.send(appData);
				} catch (RemoteException e) {
					Log.e(TAG, "Error: " + e.getMessage());
					if (debug) {
						e.printStackTrace();
					}
				}
				break;
			}
			case IDevityCardService.MSG_SERVICE_MESSAGE:
				if (debug) {
					Log.d(TAG, "Received: MSG_SERVICE_MESSAGE");
				}
				Bundle bundle = msg.getData();
				if (debug) {
					Log.d(TAG, "Objects in received bundle: " + bundle.size());
				}
				String message = bundle.getString("MSG");
				if (debug) {
					Log.d(TAG, "MSG: " + message);
				}
				mCallbackText.append("[" + System.currentTimeMillis() + "]"
						+ message + "\n");
				mCallbackScroll.fullScroll(View.FOCUS_DOWN);
				break;
			default: {
				if (debug) {
					Log.d(TAG, "Default handler reached!");
				}
				super.handleMessage(msg);
			}
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
		@Override
		public void onServiceConnected(ComponentName className, IBinder service) {
			mService = new Messenger(service);
			mCallbackText.setText("Attached to Emulation Service.\n");
			try {
				Message msg = Message.obtain(null,
						IDevityCardService.MSG_REGISTER_LOG_CLIENT);
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
		bindService(
				new Intent(getApplicationContext(), IDevityCardService.class),
				mConnection, Context.BIND_AUTO_CREATE);
		mIsBound = true;
		mCallbackText.setText("Binding.");
		if (debug) {
			Log.d(TAG, "Binding to service");
		}
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
			/*
			 *  Detach our existing connection.
			 */
			unbindService(mConnection);
			mIsBound = false;
			mCallbackText.setText("Unbinding.");
		}
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_emulation_log);

		/*
		 * Check and see if an intent was used to launch us. If the intent has
		 * data, obtain it, otherwise, send them back.
		 */
		try {
			if (getIntent() != null) {
				Intent intent = getIntent();
				Uri data = intent.getData();
				if (debug) {
					Log.d(TAG, "Intent Contents: " + intent.toString());
				}
				if (intent.getExtras() != null) {
					if (debug) {
						Log.d(TAG, "Intent hasExtras: "
								+ intent.getExtras().toString());
					}
					byte[] _data = getIntent().getExtras().getByteArray(
							g.getCardData());
					EmulationLogActivity.cardData = new CardData80073(_data);
					if (debug) {
						Log.d(TAG, "Using new card data");
					}
					g.putCard(cardData.toByteArray());
				} else {
					InputStream is = this.getContentResolver().openInputStream(
							data);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					byte[] _data = new byte[1];
					int i;
					while ((i = is.read(_data, 0, _data.length)) != -1) {
						baos.write(_data, 0, i);
					}
					baos.flush();
					_data = baos.toByteArray();
					EmulationLogActivity.cardData = new CardData80073(_data);
					if (debug) {
						Log.d(TAG, "Using new card data");
					}
					g.putCard(cardData.toByteArray());
				}
			} else if (g.getCard() != null) {
				byte[] _data = g.getCard();
				EmulationLogActivity.cardData = new CardData80073(_data);
				Log.e(TAG, "Using saved card data");
			} else {
				Intent returnuser = new Intent(this, Read80073.class);
				startActivity(returnuser);
				Log.e(TAG,
						"No card data found; returning user to read a new card.");
			}
		} catch (Throwable e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}

		mCallbackText = (TextView) findViewById(R.id.textView1);
		mCallbackScroll = (ScrollView) findViewById(R.id.scrollView);
		doBindService();
	}

	@Override
	protected void onDestroy() {
		doUnbindService();
		super.onDestroy();
	}

	/**
	 * Method onCreateOptionsMenu.
	 * 
	 * @param menu
	 *            Menu
	 * @return boolean
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		/*
		 * Inflate the menu; this adds items to the action bar if it is present.
		 */
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
		byte[] cardDataModel = cardData.toByteArray();
		String cdmFileName = cardData.digestString() + ".katd";
		File cdmFile = null;
		try {
			cdmFile = new File(getExternalFilesDir(null), cdmFileName);
			FileOutputStream fos = new FileOutputStream(cdmFile);
			fos.write(cardDataModel);
			fos.flush();
			fos.close();
			if (debug) {
				Log.d(TAG, "Wrote to file: " + cdmFileName);
			}
		} catch (IOException e1) {
			Log.e(TAG, "Failed to create datamodel file.");
			Log.e(TAG, "Error: " + e1.getMessage());
			if (debug) {
				e1.printStackTrace();
			}
		}
		Uri cdmUri = Uri.fromFile(cdmFile);
		if (debug) {
			Log.d(TAG, "CDM File: " + cdmUri.toString());
		}

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
		mail_body.append(mCallbackText.getText().toString());

		String shareSubject = "KATD Emulation Log  - "
				+ now.getTime().toString();
		sharingIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
				shareSubject);
		sharingIntent.putExtra(android.content.Intent.EXTRA_TEXT,
				mail_body.toString());
		sharingIntent.putExtra(android.content.Intent.EXTRA_STREAM, cdmUri);
		sharingIntent.putExtra(android.content.Intent.EXTRA_EMAIL, defEmail);
		startActivity(Intent.createChooser(sharingIntent, "Share Via..."));
	}

}
