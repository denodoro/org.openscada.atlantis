package org.openscada.ae.pki.common;

import java.io.IOException;

import org.openscada.utils.codec.Base64;

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
		return Base64.encodeBytes( byteArray ); 
		//return StringUtils.newStringIso8859_1(byteArray);
	}

	public byte[] decodeStringToBytearray(String string) {
		try {
			return Base64.decode(string);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

}
