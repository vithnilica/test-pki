package cms;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CMS1 {

	public static void main(String[] args) throws Exception {
		//registace BC
		Security.addProvider(new BouncyCastleProvider());
		
		//otevreni uloziste
		KeyStore ks=KeyStore.getInstance("PKCS12", "BC");
		ks.load(new FileInputStream("data/test-ca1-email1.p12"), "password".toCharArray());
		
		//vypsani aliasu
		//for(String a: Collections.list(ks.aliases())){
		//	System.out.println(a);
		//}
		
		//nacteni klice a certifikatu
		String alias="test-ca1-email1";
		X509Certificate signCert=(X509Certificate) ks.getCertificate(alias);
		PrivateKey signPK=(PrivateKey) ks.getKey(alias, "password".toCharArray());
		Certificate[] certList=ks.getCertificateChain(alias);
		

		//generator podpisu
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		
	    gen.addSignerInfoGenerator(
	                new JcaSimpleSignerInfoGeneratorBuilder()
	                     .setProvider("BC")
	                     .build("SHA256withRSA", signPK, signCert));
	    
		//prikladani cele cesty k podpisu
	    gen.addCertificates(new JcaCertStore(Arrays.asList(certList)));
	    
	    //podepsani
	    CMSTypedData content=new CMSProcessableFile(new File("data/cms/test.txt"));
	    CMSSignedData signed=gen.generate(content, true);
	    
	    
	    FileOutputStream os=new FileOutputStream("data/cms/test.p7s");
	    os.write(signed.getEncoded()); 
	    
	}
	
	


}
