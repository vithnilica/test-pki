package providers;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Collections;

public class Pkcs11 {

	public static void main(String[] args) throws Exception {
		//gnome keyring
		String configName = "data/pkcs11/gnome.cfg";
		//NSS (firefox)
		//String configName = "data/pkcs11/nss.cfg";
		Provider p = new sun.security.pkcs11.SunPKCS11(configName);
		Security.addProvider(p);

		System.out.println("provider name: " + p.getName());
		System.out.println("provider version: " + p.getVersion());
		System.out.println("provider info: " + p.getInfo());
		// for (Enumeration<?> e = p.keys(); e.hasMoreElements();){
		// System.out.println(" " + e.nextElement());
		// }
		for (Service s : p.getServices()) {
			System.out.println("  " + s.toString());
		}


		//KeyStore ks = KeyStore.getInstance("PKCS11-Gnome");
		KeyStore ks = KeyStore.getInstance("PKCS11");
		ks.load(null, "password".toCharArray());

		

		// vypsani aliasu
		System.out.println("aliases:");
		for (String a : Collections.list(ks.aliases())) {
			System.out.println(a);
			//System.out.println(ks.getCertificate(a));
		}

	}

}
