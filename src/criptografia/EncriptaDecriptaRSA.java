package criptografia;

import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public class EncriptaDecriptaRSA {

	public static final String ALGORITHM = "RSA";

	/**
	 * Gera chaves Pública e Privada
	 */
	private static Map<String, Object> getRSAKeys() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		Map<String, Object> keys = new HashMap<String, Object>();
		keys.put("private", privateKey);
		keys.put("public", publicKey);

		return keys;
	}
	
	/**
	 * Criptografa o texto puro usando chave pública.
	 */
	public static byte[] criptografa(String texto, PublicKey chave) {
		byte[] cipherText = null;

		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// Criptografa o texto puro usando a chave Púlica
			cipher.init(Cipher.ENCRYPT_MODE, chave);
			cipherText = cipher.doFinal(texto.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherText;
	}

	/**
	 * Decriptografa o texto puro usando chave privada.
	 */
	public static String decriptografa(byte[] texto, PrivateKey chave) {
		byte[] dectyptedText = null;

		try {
			final Cipher cipher = Cipher.getInstance(ALGORITHM);
			// Decriptografa o texto puro usando a chave Privada
			cipher.init(Cipher.DECRYPT_MODE, chave);
			dectyptedText = cipher.doFinal(texto);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	/**
	 * Recupera uma PublicKey de uma String em Base64
	 */
	private static PublicKey geraPublicKey(String pub) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] publicBytes = Base64.getDecoder().decode(pub.getBytes());
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		
		System.out.println(pubKey);
		return null;
	}
	
	/**
	 * Recupera uma PrivateKey de uma String em Base64
	 */
	private static PrivateKey geraPrivateKey(String prv) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] privateBytes = Base64.getDecoder().decode(prv.getBytes());
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey prvKey = keyFactory.generatePrivate(keySpec);
		
		return prvKey;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		/**
		try {
			
			Map<String, Object> keys = getRSAKeys();
			PublicKey chavePublica = (PublicKey) keys.get("public");
			PrivateKey chavePrivada = (PrivateKey) keys.get("private");

			final String msgOriginal = "a";
			final byte[] textoCriptografado = criptografa(msgOriginal, chavePublica);
			
			String criptografado = Base64.getEncoder().encodeToString(textoCriptografado);

			// Decriptografa a Mensagem usando a Chave Pirvada
			final String textoPuro = decriptografa(textoCriptografado, chavePrivada);

			String pub = Base64.getEncoder().encodeToString(chavePublica.getEncoded());
			String prv = Base64.getEncoder().encodeToString(chavePrivada.getEncoded());

			// Imprime o texto original, o texto criptografado e
			// o texto descriptografado.
			System.out.println("Mensagem Original: " + msgOriginal);
			System.out.println("Mensagem Criptografada: " + criptografado);
			System.out.println("Chave Pública: " + pub);
			System.out.println(chavePublica);
			System.out.println("Chave Privada: " + prv);
			System.out.println("Mensagem Decriptografada: " + textoPuro);
			
			String teste = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/oFGbJtHuwln5Hi1djhzVkNCcfcAE+3Skcitgys+e6rk/pQ3lqlF+wvHC4JTde95ZyaS4Wbje1Eiair7U4jVcRRhTdLOTT0CIXo9tVMClQvvToMNksXlaTZaz4XrVfZwzIsWopMckJ9xC2RRpYsJb8fyaOe5nTgTffOQq4P7q6LhRAziPpIFmQjWdkW3fZtSFqA7N66qcDRd2dM6BYc70WWBVRU4COoyW4xGSHcY1KZ5tbp+KJQnIpic9IUyN8flKFVJTVBmgtgJeMTmV0P/q7eYtJH/rjoUHfGR5ksQL3fudp9BAgrXW8V6HWURku9rKPDY5/NFjdRQh+60kMQtwIDAQAB";
			System.out.println("----------------------------------------------------------------------------------");
			geraPublicKey(teste);
			
			

		} catch (Exception e) {
			e.printStackTrace();
		}
		*/
		
		String texto = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCCeOwdtbEnyTozAXpI1EjoJffoU1yIXiWhin5e2vXNt8fJv2FfMSH2ZCwFNWdssiBG1s9Yubb9Go+vWCE8XBeADAEv4poejKBcSMeF3FrozULWD5G9GaPNruPe8Jd3ocYK3/7rF80kfyf26q9Qg+9Hc2p29Gf8ln1Oc1S9xs2Q8kHLuGjU5zMrdTS7jHc715Jhcv+037rYzonp9eV00hodD1huRSDPAxlJPdkTb13UJ3sDDgyee0y5lLMo0UpSPYlS/jWGazB6NvtoiZ4KvsnOAN2iPhWeaivI/VrdvKzY9SAVGY/UkN4T6VCndmEs4tfI6+1u00CjGZLHLwb3hZeHAgMBAAECggEAHs7U2jMT8NQYNQENUfMmgAKvJiHBAMZSVnGwY0+KqRfTSjUxlduxLE/9AQHaORVaf7+rWEUKC3vhH8NMnccVGXw8L4VvZPVJzGC3FEmzAbOuK4OjoyZRwnigf/0JlwsRC3JW7EZDf3GzCx/hY76zmoiLRCl0AHW8gvDCuskdszLYlk+LldclEfQY/c7lxMZZuRyTC4pxeZtMVKoLnkKf/YPBFzMc5Vv5SR7IfRv1KtaSzmY5GkZqLSCeuPwTpzrZaUPdXc1g/U67Qw+3YJW9+v/25yzPlf4Ve14ocX3z4OqjVM6H42EBvynxQ++gcdPMx84gn9tWO/Yh9hFCMTykUQKBgQDkYNuOGMdmR8FsbJznTwXfxkER9vP29jdhTZ7Pe1kKu/5Kn93TvOnBeopunoMNq9grptwwO88uowd7g5rrtqS/dVx/vjLeb0+88T29cS3uZBOMKdgUKI95QpljIeHHFvVbuE4KpO1rJe7kum9S+oJqy2kZFBL+h8KufIfdLdk8DwKBgQCSQKjpZuZubaqim9yYN+vo6JxHojQjxDR/k66b8x3OR+jDHcGKXtwbfaPSi76qu5QEpzuDeePPSSSWKTX2RGhsXSfYZSp2B0S8C8B/NRU07mLfgSu+8eoOyxULipWCxI3/fuRbJv0CeAABhkgtnuB9eTQDL/0NMqzdtEqvQ3bVCQKBgQDSd4S/LozM8MIL1wi+ju/96ypakPkClqQw8ySxV56WquvOAAihss7GNNVQ3pouRjlA+VSgyu3DsBEcPgvOwRKRM2pce39LyM92c+iPJrfKo8Xz/TgaU8rtWHgdiMMXBEx4C6E4ZAg9H8dKWZpwoVcBbpZbu0lJ8vlybmeTaUZy9wKBgFqh0UsapnAGa/jrB7AY74vdIoPNw+vqOfJZbZpc9bqQm3DWrsp18IbkvDHMwfKB3b9odxwJ3B/nntGjZjpfuCp3LCsQvlh4NqMl0TvDhInRtNn27UoeFkLmnPsS/YYVEj4jv5WxOpdeD/rh4TbMPyfihVX4ViPopHGbubCU6T4pAoGANyLdspopQGlB7c5ipFO4irnNqIp2By6n05foMfB98IiurhOb7Z/qG5qEcpYOJ1808sbeSSq0PRFd8MkOWvUZLwNAbWejmlh+cUOiXZCKacS5to4OZxlHOLgiaeCduoykf/ig6rvOqi0TncjEFFlfmAU0jCl76bcn3wHn7o2aYgk=";
		PrivateKey prv = geraPrivateKey(texto);
		String criptografado = "cWvLuCZ7jmF++aeOg5V1r3armMO9RZq26uVYQty4Sh3RmGEWljRRAWPaQr03aQEXKaMuMD3Hk3IRHKTFFHpaks3461RF561WYRzMg3N/6cmW68b2mkdnvPzmavmRnGqeLEbGAC+7vyhWpyB7Hffo8m980jq25YA1uv9s3XIOPGdFmiQXr2a73Iek47TzSWwWqvId2jwf3RREOlHI+8Meb9onnsq+QyZzvU3rZKboiAinpLlFebdwMkOcFD3FPnljFS+YFbZE4yDr+exR4b/UGvzEruHp4c9rNyTcRAc00IGLbCYefPfj/C6DW07ZxOEGDagENZ516M9f4urjyFka9A==";
		byte[] criptografadoBytes = Base64.getDecoder().decode(criptografado.getBytes());
		
		System.out.println(decriptografa(criptografadoBytes, prv));
		
	}
}