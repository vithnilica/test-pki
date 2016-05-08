package pdfbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestPdfBox1 {
	
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
		final CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	    gen.addSignerInfoGenerator(
	                new JcaSimpleSignerInfoGeneratorBuilder()
	                     .setProvider("BC")
	                     .build("SHA256withRSA", signPK, signCert));
		//prikladani cele cesty k podpisu
	    //CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(Arrays.asList(certList)), "BC");
	    gen.addCertificates(new JcaCertStore(Arrays.asList(certList)));
	    

	    
	    
		PDDocument pdf = PDDocument.load(new File("data/pdf/test.pdf"));
		
		PDSignature pdfSig=new PDSignature();
		pdfSig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		pdfSig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		//pdfSig.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
		pdfSig.setName("Nechť již hříšné saxofony ďáblů rozzvučí síň úděsnými tóny waltzu, tanga a quickstepu.");
		pdfSig.setSignDate(Calendar.getInstance());
		
		pdf.addSignature(pdfSig, new SignatureInterface() {
			public byte[] sign(InputStream content) throws IOException {
				//CMSProcessableInputStream cmsdata = new CMSProcessableInputStream(content);
				CMSProcessableByteArray cmsdata=new CMSProcessableByteArray(IOUtils.toByteArray(content));
				try {
					return gen.generate(cmsdata, false).getEncoded();
				} catch (CMSException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return null;
				}
			}
		});
		//pdf.save(new File("data/pdf/test-signed.pdf"));
		pdf.saveIncremental(new FileOutputStream("data/pdf/test-signed.pdf"));
	}
}
