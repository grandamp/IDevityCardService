package com.idevity.android.contact;

import com.idevity.card.service.R;

import android.app.Fragment;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

/**
 * A placeholder fragment containing a simple view.
 */
public class StatusFragment extends Fragment {
	
	TextView readerLabel = null;
	TextView readerStatus = null;

	public StatusFragment() {
	}

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View rootView = inflater.inflate(R.layout.fragment_status, container,
				false);
		
		readerLabel = (TextView) rootView.findViewById(R.id.label_status);
		readerStatus = (TextView) rootView.findViewById(R.id.status);
		
		return rootView;
	}
	
	public void setReaderStatus(String status) {
		readerStatus.setText(status);
	}
	
	public void setCardStatus(boolean connected) {
		if (connected) {
			readerLabel.setBackgroundColor(Color.GREEN);
			readerStatus.setBackgroundColor(Color.GREEN);
		} else {
			readerLabel.setBackgroundColor(Color.RED);
			readerStatus.setBackgroundColor(Color.RED);
		}
	}

}