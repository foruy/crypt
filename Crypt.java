

public class Crypt
{
	static {
		System.loadLibrary("crypt");
	}

	private Chan ch = null;
	public static native Chan openDevice();
	public static native Message readData(Chan ch);
	public static native void writeData(Chan ch, Message out);
	public static native void closeDevice(Chan ch);

	public Crypt() {
		this.ch = openDevice();
	}

	public Message read() {
		Message in = null;
		try {
			in = readData(ch);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return in;
	}

	public void write(Message in, byte[] data) {
		writeData(ch, new Message(in.header, data, in.enc));
	}

	public void close() {
		closeDevice(ch);
	}

	public static void main(String[] args) {
		Crypt crypt = new Crypt();
		while (true) {
			try {
				Message in = crypt.read();
				if (in != null && in.data != null && in.data.length > 0) {
					byte[] data = null;
					System.out.println(in.enc);
					System.out.println(in.data.length);
					// Encrypt or Decrypt
					if (in.enc) {
for (int i=0; i < in.data.length; i++) {
  if (i % 16 == 0) {
    System.out.println();
  }
  System.out.printf("%02x", in.data[i]);
}
System.out.println();
						// Call Encrypt
						data = in.data;
					} else {
						// Call Decrypt
						data = in.data;
					}
					crypt.write(in, data);
				}
			} catch (Exception e) {
				crypt.close();
				e.printStackTrace();
				break;
			}
		}
	}
}

class Message {
	public boolean enc;
	public byte[] header;
	public byte[] data;

	public Message(byte[] header, byte[] data, boolean enc) {
		this.header = header;
		this.data = data;
		this.enc = enc;
	}
}

class Chan {
	public int server;
	public int client;
}
