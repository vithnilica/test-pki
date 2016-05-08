package pdfbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

public class TestPdfBox2 {
	
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
		
		
		//seznam zneplatnenych certifikatu
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    X509CRL crl = (X509CRL)cf.generateCRL(new FileInputStream("data/test-ca1.crl"));

	    
	    
		PDDocument pdf = PDDocument.load(new File("data/pdf/test.pdf"));
		
		PDSignature pdfSig=new PDSignature();
		pdfSig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		//pdfSig.setFilter(PDSignature.FILTER_ENTRUST_PPKEF);
		//pdfSig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		pdfSig.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
		pdfSig.setName("Nechť již hříšné saxofony ďáblů rozzvučí síň úděsnými tóny waltzu, tanga a quickstepu.");
		pdfSig.setSignDate(Calendar.getInstance());
		
		
		SignatureOptions pdfSigOpt = new SignatureOptions();
		//nastaveni vetsiho mista pro podpis (defaultne je 0x2500)
		pdfSigOpt.setPreferredSignatureSize(0x8000);

		
		pdf.addSignature(pdfSig, new SignatureInterface() {
			public byte[] sign(InputStream content) throws IOException {
				try {
					byte[] data=IOUtils.toByteArray(content);
					
					MessageDigest md = MessageDigest.getInstance("SHA-256");
					md.update(data);
					byte[] digestSHA256=md.digest();
					
					//podepsane atributy navic
					Hashtable<ASN1ObjectIdentifier, Attribute> signedAttrs=new Hashtable<>();
					
					//casova znacka v podepsanych atributech (z obsahu, kdyby to bylo v nakem externim souboru, da se z nej vypreparovat)
					TimeStampToken tst=getTimeStamp(digestSHA256);
					if(tst!=null){
						Attribute tstAttr=new Attribute(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp, new DERSet(tst.toCMSSignedData().toASN1Structure()));
						signedAttrs.put(tstAttr.getAttrType(), tstAttr);
					}
					
					//generator podpisu
					CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

					gen.addSignerInfoGenerator(
				                new JcaSimpleSignerInfoGeneratorBuilder()
				                     //.setProvider("BC")
				                     .setSignedAttributeGenerator(new AttributeTable(signedAttrs)) //DefaultSignedAttributeTableGenerator + atributy navic
				                     .build("SHA256withRSA", signPK, signCert));
					//prikladani cele cesty k podpisu
				    gen.addCertificates(new JcaCertStore(Arrays.asList(certList)));
					gen.addCRLs(new JcaCRLStore(Arrays.asList(crl)));
				    
				    CMSSignedData sigData=gen.generate(new CMSProcessableByteArray(data), false);
				    
				    SignerInformationStore sigInfoStoreOrig=sigData.getSignerInfos();
				    List<SignerInformation> sigInfList = new ArrayList<>(); 
				    for (SignerInformation sigInfOrig: sigInfoStoreOrig.getSigners()){
				    	AttributeTable unsigAttrsTbl=sigInfOrig.getUnsignedAttributes();
				    	Hashtable<ASN1ObjectIdentifier, Attribute> unsigAttrs=new Hashtable<>();
				    	if(unsigAttrsTbl!=null)unsigAttrs=unsigAttrsTbl.toHashtable();
				    	
				    	//hash podpisu
						MessageDigest md2 = MessageDigest.getInstance("SHA-256");
						md2.update(sigInfOrig.getSignature());

				    	//casova znacka z heshe podpisu 
				    	TimeStampToken tst2=getTimeStamp(md2.digest());
						if(tst2!=null){
							Attribute tstAttr=new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(tst2.toCMSSignedData().toASN1Structure()));
							unsigAttrs.put(tstAttr.getAttrType(), tstAttr);
						}
						
				    	
				    	
				    	sigInfList.add(SignerInformation.replaceUnsignedAttributes(sigInfOrig,new AttributeTable(unsigAttrs))); 
				    }
				    SignerInformationStore sigInfoStore=new SignerInformationStore(sigInfList); 
				    sigData=CMSSignedData.replaceSigners(sigData, sigInfoStore);
				    
				    
					return sigData.getEncoded();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return null;
				}
			}
		},pdfSigOpt);
		//pdf.save(new File("data/pdf/test-signed2.pdf"));
		pdf.saveIncremental(new FileOutputStream("data/pdf/test-signed2.pdf"));
	}
	
	
	public static TimeStampToken getTimeStamp(byte[] digestSHA256) throws Exception{
		if(digestSHA256==null){
			System.out.println("otisk je prazdny");
			return null;
		}
		if(digestSHA256.length!=32){
			System.out.println("otisk ma divnou delku "+digestSHA256.length);
			return null;
		}
		TimeStampRequestGenerator trg=new TimeStampRequestGenerator();
		trg.setCertReq(true);
		TimeStampRequest req=trg.generate(TSPAlgorithms.SHA256, digestSHA256);
		
		
		//http://tsa.startssl.com/rfc3161
		
		HttpPost post=new HttpPost("http://tsa.startssl.com/rfc3161");
		post.addHeader("Content-Type", "application/timestamp-query");
		post.addHeader("Accept", "application/timestamp-reply");
		post.setEntity(new ByteArrayEntity(req.getEncoded()));

		
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = httpclient.execute(post);

		System.out.println(response.getStatusLine());
		TimeStampResponse resp=new TimeStampResponse(response.getEntity().getContent());
		System.out.println(resp.getStatus());
		System.out.println(resp.getStatusString());
		TimeStampToken tst=resp.getTimeStampToken();
		if(tst!=null){
			System.out.println(tst.getTimeStampInfo().getGenTime());
		}
		
		return tst;

	}
	
}
