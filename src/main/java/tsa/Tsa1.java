package tsa;
import java.security.Security;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

public class Tsa1 {

	public static void main(String[] args) throws Exception {
		//registace BC
		Security.addProvider(new BouncyCastleProvider());
		
		

		byte[] digest=new byte[32];//256/8=32

		
		
		TimeStampRequestGenerator trg=new TimeStampRequestGenerator();
		trg.setCertReq(true);
		TimeStampRequest req=trg.generate(TSPAlgorithms.SHA256, digest);
		
		
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

	}

}
