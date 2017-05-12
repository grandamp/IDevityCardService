/**
 * 
 */
package com.idevity.card.service.applets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * @author tejohnson
 *
 */
public class PIVDataObject {
	
	protected byte buf[];
	protected int pos;
	protected int count;

	/**
	 * 
	 */
	public PIVDataObject(byte[] data) {
		this.buf = data;
		this.pos = 0;
		this.count = buf.length;
	}

	/**
	 * If len < 0, IndexOutOfBoundsException will be thrown.
	 * 
	 * If len > available() We simply return what is available.
	 * 
	 * @param len Lenth of byte array to return
	 * @throws IndexOutOfBoundsException
	 */
	public synchronized byte[] read(int len) {
		if (len < 0) {
			throw new IndexOutOfBoundsException();
		} else if (len > (count - pos)) {
			len = count - pos;
		}
		
		byte[] ret = Arrays.copyOfRange(buf, pos, pos+len);
		pos += len;
		return ret;
	}
	
	public synchronized void append(byte[] data) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(buf);
		baos.write(data);
		buf = baos.toByteArray();
		this.count = buf.length;
	}
	
	public synchronized int available() {
		return count - pos;
	}

	public synchronized void reset() {
		pos = 0;
	}
}
