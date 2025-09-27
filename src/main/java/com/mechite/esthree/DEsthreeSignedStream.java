package com.mechite.esthree;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.*;

/**
 * Wraps an InputStream and signs it chunk by chunk using AWS Signature V4.
 * @see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html">AWS docs</a>
 */
final class DEsthreeSignedStream extends InputStream {

	private final InputStream source;
	private final DEsthreeSigner signer;
	private final MessageDigest sha256;
	private final byte[] signingKey;

	private byte[] previous;
	private byte[] buffer;
	private int bufferPosition = 0;
	private int bufferLimit = 0;

	DEsthreeSignedStream(InputStream source, DEsthreeSigner signer, MessageDigest sha256, String date, String candidate) {
		this.source = source;
		this.signer = signer;
		this.sha256 = sha256;

		this.signingKey = signer.signingKey(date.substring(0, 8));
		this.previous = signer.hmac(this.signingKey, candidate);

		this.buffer = new byte[0];
	}

	@Override
	public int read() throws IOException {
		if (bufferPosition >= bufferLimit && !this.fillBuffer()) return -1;
		return buffer[bufferPosition++] & 0xFF;
	}

	@Override
	public int read(byte[] buffer, int offset, int length) throws IOException {
		int count = 0;
		while (length > 0) {
			if (this.bufferPosition >= this.bufferLimit && !this.fillBuffer()) break;

			int copy = Math.min(length, this.bufferLimit - this.bufferPosition);
			System.arraycopy(this.buffer, this.bufferPosition, buffer, offset, copy);

			this.bufferPosition += copy;
			offset += copy;
			length -= copy;
			count += copy;
		}
		return (count == 0) ? -1 : count;
	}

	/** Read some bytes from {@link #source} and allocate buffer, with space for chunk size & signature. */
	private boolean fillBuffer() throws IOException {
		byte[] chunk = new byte[16 * 1024];

		int read = this.source.read(chunk);
		if (read == -1) {
			this.buffer = this.buildChunk(new byte[0]);
			this.bufferPosition = 0;
			this.bufferLimit = this.buffer.length;
			return (this.bufferLimit > 0);
		}

		byte[] actual = new byte[read];
		System.arraycopy(chunk, 0, actual, 0, read);

		this.buffer = this.buildChunk(actual);
		this.bufferPosition = 0;
		this.bufferLimit = this.buffer.length;
		return true;
	}

	/** Build a chunk from the provided read chunk, from the regular {@link InputStream}. */
	private byte[] buildChunk(byte[] payload) throws IOException {
		String hash = this.signer.hex(this.sha256.digest(payload));
		String candidate = this.signer.hex(this.previous) + hash; // todo - full impl here of string-to-sign format
		byte[] signature = this.signer.hmac(signingKey, candidate);
		this.previous = signature;

		byte[] header = (Integer.toHexString(payload.length) + ";" + this.signer.hex(signature) + "\r\n").getBytes(UTF_8);
		byte[] footer = "\r\n".getBytes(UTF_8);

		byte[] result = new byte[header.length + payload.length + footer.length];
		System.arraycopy(header, 0, result, 0, header.length);
		System.arraycopy(payload, 0, result, header.length, payload.length);
		System.arraycopy(footer, 0, result, header.length + payload.length, footer.length);

		return result;
	}
}