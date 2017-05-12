package com.idevity.card.read;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.idevity.android.nfc.CardChannel;
import com.idevity.card.data.CardData80073;
import com.idevity.card.reader.CardReader80073;
import com.idevity.card.service.R;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: Read80073.java 307 2014-02-03 00:56:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 * 
 *          Changed: $LastChangedDate: 2013-11-07 00:31:22 -0500 (Thu, 07 Nov
 *          2013) $
 *****************************************************************************/
public class Read80073 extends Activity implements OnClickListener {

	/**
	 * Field TAG.
	 */
	private static final String TAG = Read80073.class.getSimpleName();

	// open global variables
	/**
	 * Field g.
	 */
	Globals globals = Globals.getInstance();

	/**
	 * Field timeoutlabel.
	 */
	private TextView timeoutlabel;
	/**
	 * Field timeouturl.
	 */
	private TextView timeouturl;

	/**
	 * Field spinnertext.
	 */
	private TextView spinnertext;
	/**
	 * Field spinner.
	 */
	private ProgressBar spinner;

	/**
	 * Field sharedPref.
	 */
	private SharedPreferences sharedPref;

	/**
	 * Field adapter.
	 */
	private NfcAdapter adapter;
	/**
	 * Field pendingIntent.
	 */
	private PendingIntent pendingIntent;
	/**
	 * Field filters.
	 */
	private IntentFilter[] filters;
	/**
	 * Field techLists.
	 */
	private String[][] techLists;
	/**
	 * Field card.
	 */
	private CardReader80073 card;
	/**
	 * Field carddata.
	 */
	private CardData80073 carddata;
	/**
	 * Field debug.
	 */
	private boolean debug = false;
	/**
	 * Field last_touch.
	 */
	private long last_touch = 0;
	/**
	 * Field touch_seq.
	 */
	private int touch_seq = 0;

	/**
	 * Method onCreate.
	 * 
	 * @param savedInstanceState
	 *            Bundle
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		sharedPref = PreferenceManager.getDefaultSharedPreferences(this);
		debug = sharedPref.getBoolean(globals.getShowDebug(), false);

		/******************** Setup NFC ********************/
		setupNFC();

		/****************** Manage the UI ******************/
		// setContentView(R.layout.activity_show_card_layout);
		setContentView(R.layout.activity_reading_progress);
		spinnertext = (TextView) findViewById(R.id.progressText);
		spinner = (ProgressBar) findViewById(R.id.spinner);
		spinnertext.setVisibility(View.INVISIBLE);
		spinner.setVisibility(View.INVISIBLE);

		/************ Easter Egg Touch Listener ************/
		View logo = findViewById(R.id.idevityidlogo);
		logo.setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View view) {
				if (debug) {
					Log.d(TAG, "IDevity Logo Touched!");
				}
				logoTouched();
			}
		});

		/*************** JellyBean Issues ******************/
		boolean nfc_timeout_issue = false;
		timeoutlabel = (TextView) findViewById(R.id.nfc_disclaimer);
		timeouturl = (TextView) findViewById(R.id.nfc_disclaimer2);
		timeoutlabel.setVisibility(View.INVISIBLE);
		timeouturl.setVisibility(View.INVISIBLE);
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
			nfc_timeout_issue = true;
		}
		if (nfc_timeout_issue) {
			timeoutlabel.setVisibility(View.VISIBLE);
			timeouturl.setVisibility(View.VISIBLE);
			timeouturl.setMovementMethod(LinkMovementMethod.getInstance());
		}

		/****************** Launch the Reader ******************/
		if (debug) {
			Log.d(TAG, "Calling CardReader80073...");
		}
		card = new CardReader80073();

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
								if (card != null) {
									if (card.isRunning()) {
										spinnertext.setVisibility(View.VISIBLE);
										spinner.setVisibility(View.VISIBLE);
									} else {
										spinnertext
												.setVisibility(View.INVISIBLE);
										spinner.setVisibility(View.INVISIBLE);
									}
									if (card.cardDataAvailable()) {
										processData();
									}
								}
							}
						});
					}
				} catch (InterruptedException e) {
					if (debug) {
						Log.d(TAG, "Error in UI Thread: " + e.getMessage());
					}
				}
			}
		};
		thread.start();

	}

	/**
	 * Method setupNFC.
	 */
	@TargetApi(19)
	private void setupNFC() {
		/****************** Initialize NFC ******************/
		if (debug) {
			Log.d(TAG, "Getting Adaptor...");
		}
		adapter = NfcAdapter.getDefaultAdapter(this);
		/*
		 * Open NFC settings if NFC is not enabled.
		 */
		if (debug) {
			Log.d(TAG, "Checking Adaptor...");
		}
		if (!adapter.isEnabled()) {
			startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
		}
		/*
		 * Platform version specific handling: JellyBean
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN
				&& Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
			if (debug) {
				Log.d(TAG, "Setting Adaptor up for JellyBean");
			}
			adapter.setNdefPushMessage(null, this);
			adapter.setBeamPushUris(null, this);

			pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
					getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
			filters = new IntentFilter[] { new IntentFilter(
					NfcAdapter.ACTION_TECH_DISCOVERED) };
			techLists = new String[][] { { "android.nfc.tech.NfcA" },
					{ "android.nfc.tech.IsoDep" } };

		}
		/*
		 * Platform version specific handling: KitKat
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR2) {
			if (debug) {
				Log.d(TAG, "Setting Adaptor up for KitKat");
			}
			ReaderCallback listener = new ReaderCallback() {
				@Override
				public void onTagDiscovered(Tag tag) {
					handleTag(tag);
				}
			};
			int flags = NfcAdapter.FLAG_READER_NFC_A
					| NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
			adapter.enableReaderMode(this, listener, flags, null);
		}
	}

	/**
	 * Method shutdownNFC.
	 */
	@TargetApi(19)
	private void shutdownNFC() {
		/*
		 * Shutdown the reader thread before we shutdown NFC
		 */
		if (card != null) {
			if (debug) {
				Log.d(TAG, "killing the reader thread");
			}
			card.stop();
		}
	}

	/**
	 * Method onResume.
	 */
	@Override
	public void onResume() {
		if (debug) {
			Log.d(TAG, "onResume()");
		}
		/*
		 * Platform version specific handling: JellyBean
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN
				&& Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
			if (adapter != null) {
				adapter.enableForegroundDispatch(this, pendingIntent, filters,
						techLists);
			}
		}
		/*
		 * Everything else
		 */
		/*
		 * Reset the Reader Log for Debug Mode
		 */
		setupNFC();
		super.onResume();
	}

	/**
	 * Method onPause.
	 */
	@Override
	public void onPause() {
		if (debug) {
			Log.d(TAG, "onPause()");
		}
		/*
		 * Platform version specific handling: JellyBean
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN
				&& Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
			if (debug) {
				Log.d(TAG, "Shutting Down Adaptor for JellyBean");
			}
			if (adapter != null) {
				if (debug) {
					Log.d(TAG, "disabling foreground dispatch");
				}
				adapter.disableForegroundDispatch(this);
			}
		}
		/*
		 * Everything else
		 */
		shutdownNFC();
		super.onPause();
	}

	/**
	 * Method onDestroy.
	 */
	@Override
	public void onDestroy() {
		if (debug) {
			Log.d(TAG, "onDestroy()");
		}
		shutdownNFC();
		super.onDestroy();
	}

	/**
	 * Method onNewIntent.
	 * 
	 * @param intent
	 *            Intent
	 */
	@Override
	public void onNewIntent(Intent intent) {
		if (debug) {
			Log.d(TAG, "onNewIntent()");
		}
		handleTag(intent);
	}

	/**
	 * Method handleTag.
	 * 
	 * @param intent
	 *            Intent
	 */
	private void handleTag(Intent intent) {

		/*
		 * Platform version specific handling: JellyBean
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN
				&& Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
			spinnertext = (TextView) findViewById(R.id.progressText);
			spinner = (ProgressBar) findViewById(R.id.spinner);
			spinnertext.setVisibility(View.VISIBLE);
			spinner.setVisibility(View.VISIBLE);
		}
		if (debug) {
			Log.d(TAG, "TECH_DISCOVERED: " + intent);
		}
		Tag tag = null;
		if (intent.getExtras() != null) {
			tag = (Tag) intent.getExtras().get(NfcAdapter.EXTRA_TAG);
		}
		handleTag(tag);
	}

	/**
	 * Method handleTag.
	 * 
	 * @param tag
	 *            Tag
	 */
	private void handleTag(Tag tag) {

		CardChannel channel = null;
		if (tag == null) {
			return;
		}
		/*
		 * Stop the reader thread if it is already running because we received a
		 * new tag.
		 */
		if (card != null) {
			if (debug) {
				Log.d(TAG, "Reader running: " + card.isRunning());
			}
			if (card.isRunning()) {
				if (debug) {
					Log.d(TAG, "Reader thread alredy running, stopping");
				}
				card.stop();
			}
		}
		channel = new CardChannel(tag);
		if (channel.isConnected()) {
			card.start(channel);
		}
	}

	/**
	 * Method onClick.
	 * 
	 * @param v
	 *            View
	 * 
	 * @see android.view.View$OnClickListener#onClick(View)
	 */
	@Override
	public void onClick(View v) {
		/*
		 * Do-Nothing
		 */
	}

	/**
	 * Method processData.
	 * 
	 * Post processing and send the data to the next activity.
	 */
	private void processData() {

		carddata = card.getData();

		/*
		 * Call CloneKeys
		 */
		Intent intent = new Intent(this, CloneKeys.class);
		//String reader_log = readerLog.toString();
		//intent.putExtra(globals.getReaderLog(), reader_log);
		intent.putExtra(globals.getCardData(), carddata.toByteArray());
		startActivity(intent);
	}

	/**
	 * Method logoTouched.
	 * 
	 * The touch timer for the easter egg.
	 */
	private void logoTouched() {
		long touch_time = 1500;
		long current_touch = System.currentTimeMillis();
		if (last_touch == 0) {
			last_touch = System.currentTimeMillis();
		} else if (current_touch - last_touch <= touch_time) {
			touch_seq++;
		} else {
			/*
			 * Reset the timer and counter
			 */
			touch_seq = 0;
			last_touch = 0;
		}
		if (touch_seq >= 5) {
			/*
			 * Reset our timer, counter, and launch!
			 */
			touch_seq = 0;
			last_touch = 0;
			if (debug) {
				Log.d(TAG, "Launching Easter Egg!");
			}
			Intent calleasteregg = new Intent(this, Easter.class);
			startActivity(calleasteregg);
		}
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
		getMenuInflater().inflate(R.menu.reading_progress, menu);
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
		case R.id.action_about:
			Intent callinfo = new Intent(this, IdevityInfo.class);
			startActivity(callinfo);
			return true;
		case R.id.action_settings:
			Intent callsettings = new Intent(this, SettingsActivity.class);
			startActivity(callsettings);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

}
