package providers;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class ProviderInfo {

	public static void main(String[] args) {
        //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //Security.addProvider(new BouncyCastlePQCProvider());


        for (Provider p : Security.getProviders()) {

            System.out.println("provider name: " + p.getName());
            System.out.println("provider version: " + p.getVersion());
            System.out.println("provider info: " + p.getInfo());
            //for (Enumeration<?> e = p.keys(); e.hasMoreElements();){
            //    System.out.println("  " + e.nextElement());
            //}
            for (Service s: p.getServices()){
                System.out.println("  " + s.toString());
            }
               
        }
	}

}
