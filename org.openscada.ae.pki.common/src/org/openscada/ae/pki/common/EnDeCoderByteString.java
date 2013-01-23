package org.openscada.ae.pki.common;

//import org.apache.commons.codec.binary.StringUtils;

public class EnDeCoderByteString {
	
	private static EnDeCoderByteString instance;
	private EnDeCoderByteString() {}
	
    public synchronized static EnDeCoderByteString getInstance(){
        if (instance == null){
            instance = new EnDeCoderByteString();
        }
        return instance;
    }

	public String encodeBytearrayToString(byte[] byteArray) {
		return new String(byteArray);
		//return StringUtils.newStringIso8859_1(byteArray);
	}

	public byte[] decodeStringToBytearray(String string) {
		return string.getBytes();
		//return StringUtils.getBytesIso8859_1(string);
	}

}
