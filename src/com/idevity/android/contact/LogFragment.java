package com.idevity.android.contact;

import com.idevity.card.service.R;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * A placeholder fragment containing a simple view.
 */
public class LogFragment extends Fragment {
	
	ScrollView scroll = null;
	TextView readerLog = null;

	public LogFragment() {
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		
		View rootView = inflater.inflate(R.layout.fragment_log, container,
				false);
		
		scroll = (ScrollView) rootView.findViewById(R.id.scrollViewLog);
		readerLog = (TextView) rootView.findViewById(R.id.readerlog);
		
		return rootView;
	}
	
	/*
	 * Append to Log
	 */
	public void appendLog(String logData) {
		readerLog.append(logData);
		scroll.fullScroll(View.FOCUS_DOWN);
	}
	
	/*
	 * Get everything in the Log
	 */
	public String getLog() {
		return readerLog.getText().toString();
	}
}