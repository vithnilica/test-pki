package mail;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;

import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

public class TestSignMail {

	public static void main(String[] args) throws Exception {
		//registace BC
		//Security.addProvider(new BouncyCastleProvider());
		
		//otevreni uloziste
		KeyStore ks=KeyStore.getInstance("PKCS12");
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
		SMIMESignedGenerator gen = new SMIMESignedGenerator();
	    gen.addSignerInfoGenerator(
	                new JcaSimpleSignerInfoGeneratorBuilder()
	                     //.setProvider("BC")
	                     .build("SHA256withRSA", signPK, signCert));
		//prikladani cele cesty k podpisu
	    gen.addCertificates(new JcaCertStore(Arrays.asList(certList)));
	    
	    System.out.println("heslo pro prihlaseni k smtp:");
	    String smtpPassword=(new BufferedReader(new InputStreamReader(System.in))).readLine();
		    Session session=null;
		    if(smtpPassword!=null && !smtpPassword.isEmpty()){
		    Properties props = new Properties();
			props.put("mail.smtp.host", "smtp.gmail.com");
			props.put("mail.smtp.socketFactory.port", "465");
			props.put("mail.smtp.socketFactory.class",
					"javax.net.ssl.SSLSocketFactory");
			props.put("mail.smtp.auth", "true");
			props.put("mail.smtp.port", "465");
			session = Session.getDefaultInstance(props,
				new javax.mail.Authenticator() {
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication("vit.hnilica@gmail.com",smtpPassword);
					}
				});
	    }
		

		//otevreni mailu
		//MimeMessage message=new MimeMessage((Session) null,new FileInputStream("data/mail/test.eml"));
		MimeMessage message=new MimeMessage(session,new FileInputStream("data/mail/test.eml"));
		//message.writeTo(System.out);

	    MimeBodyPart content=new MimeBodyPart();
	    //content.setContent((MimeMultipart) message.getContent());
		if (message.getContent() instanceof Multipart){
			content.setContent((Multipart)message.getContent());
		}else{
			content.setContent(message.getContent(), message.getContentType());
		}

	    
	    //podepsani mailu
	    MimeMultipart signed=gen.generate(content);
	    //MimeMultipart signed=gen.generateEncapsulated(content);
	    
	    
	    
	    System.out.println("podepsano");
	    message.setContent(signed);
	    message.saveChanges();
	    message.writeTo(new FileOutputStream("data/mail/test-signed.eml"));


	    //odeslani mailu
	    if(session!=null){
	    	Transport.send(message);
	    }


	    
	}

}
