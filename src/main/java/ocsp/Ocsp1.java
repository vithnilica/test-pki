package ocsp;

import java.io.FileReader;
import java.math.BigInteger;
import java.security.Security;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

//import org.bouncycastle.ocsp.CertificateID; 


public class Ocsp1 {
	
	final static AlgorithmIdentifier HASH_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

	public static void main(String[] args) throws Exception {
		//registace BC
		Security.addProvider(new BouncyCastleProvider());
		
		//PEMParser pr=new PEMParser(new FileReader("data/ocsp/my-startssl.crt"));
		PEMParser pr=new PEMParser(new FileReader("data/ocsp/my-ps.crt"));
		
		X509CertificateHolder cert=(X509CertificateHolder)pr.readObject();
		X509CertificateHolder issuerCert=(X509CertificateHolder)pr.readObject();
		
		//startssl platny (muj)
		//BigInteger serialNumber=new BigInteger("32D2DC143F7192775D62755072D5BF7C", 16);
		//startssl neplatny
		//BigInteger serialNumber=new BigInteger("4E63CAB15005249AC7B0DD96E31546D5", 16);
		//postsignum qca neplatny
		BigInteger serialNumber=new BigInteger("1C9CA9", 16);
		
		//z certifikatu
		//BigInteger serialNumber=cert.getSerialNumber();
		
		
		DigestCalculatorProvider provider = new BcDigestCalculatorProvider();	
		
		JcaX509CertificateConverter certConv=new JcaX509CertificateConverter();
		System.out.println(certConv.getCertificate(issuerCert).toString());

		//CertificateID certId=new CertificateID(provider.get(HASH_SHA256), issuerCert, serialNumber);
		CertificateID certId=new CertificateID(provider.get(CertificateID.HASH_SHA1), issuerCert, serialNumber);
		System.out.println(serialNumber);
		
		OCSPReq req=new OCSPReqBuilder().addRequest(certId).build();
		

		//OCSP: URI: http://ocsp.startssl.com
		//CA Issuers: URI: http://aia.startssl.com/certs/ca.crt
		
		
		//OCSP: URI: http://ocsp.startssl.com
		//CA Issuers: URI: http://aia.startssl.com/certs/sca.client1.crt
		
		
		//OCSP Server: http://ocsp.postsignum.cz/OCSP/VCA2/OCSP_public/ 
		//CRL Distribution Point: http://www.postsignum.cz/crl/pspublicca2.crl
			
		//??? http://ocsp.postsignum.cz/OCSP/QCA2/OCSP_public/
		//URI:http://www.postsignum.cz/crl/psqualifiedca2.crl
		
		HttpPost post=new HttpPost("http://ocsp.postsignum.cz/OCSP/QCA2/OCSP_public/");
		post.addHeader("Content-Type", "application/ocsp-request");
		post.addHeader("Accept", "application/ocsp-response");
		post.setEntity(new ByteArrayEntity(req.getEncoded()));

		
		CloseableHttpClient httpclient = HttpClients.createDefault();
		CloseableHttpResponse response = httpclient.execute(post);

		System.out.println(response.getStatusLine());
		OCSPResp resp=new OCSPResp(response.getEntity().getContent());
		
		System.out.println(resp.getStatus());
	    //SUCCESSFUL = 0;  // Response has valid confirmations
	    //MALFORMED_REQUEST = 1;  // Illegal confirmation request
	    //INTERNAL_ERROR = 2;  // Internal error in issuer
	    //TRY_LATER = 3;  // Try again later
	    // (4) is not used
	    //SIG_REQUIRED = 5;  // Must sign the request
	    //UNAUTHORIZED = 6;  // Request unauthorized
		
		Object o=resp.getResponseObject();
		if(o!=null)System.out.println(o.getClass().getName());
		if(resp.getStatus()==OCSPResp.SUCCESSFUL){
			BasicOCSPResp br=(BasicOCSPResp)o;
			for(SingleResp sr:br.getResponses()){
				System.out.println(sr.getCertID().getSerialNumber());
				System.out.println(sr.getCertStatus());//null good, jinak RevokedStatus/UnknownStatus
				if(sr.getCertStatus()!=null){
					System.out.println(sr.getCertStatus().getClass().getName());
					if(sr.getCertStatus() instanceof RevokedStatus){
						System.out.println(((RevokedStatus)sr.getCertStatus()).hasRevocationReason());
						//  unspecified             (0),
						//  keyCompromise           (1),
						//  cACompromise            (2),
						//  affiliationChanged      (3),
						//  superseded              (4),
						//  cessationOfOperation    (5),
						//  certificateHold         (6),
						//  removeFromCRL           (8),
						//  privilegeWithdrawn      (9),
						//  aACompromise           (10)
						if(((RevokedStatus)sr.getCertStatus()).hasRevocationReason())System.out.println(((RevokedStatus)sr.getCertStatus()).getRevocationReason());
						System.out.println(((RevokedStatus)sr.getCertStatus()).getRevocationTime());
					}
					
				}
				System.out.println(sr.getNextUpdate());
				System.out.println(sr.getThisUpdate());
			}
		}
		
		


	}

}
