package com.example.demo_dss.sign;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class SignXmlCadesBTest {
	
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String PKI_FACTORY_KEYSTORE_PASSWORD = "ks-password";
	private static final String KEYSTORE_ROOT_PATH = "/keystore/";
	private static final String PKI_FACTORY_HOST = "http://dss.nowina.lu/pki-factory/";
	private static final int TIMEOUT_MS = 10000;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		DSSDocument toSignDocument = new FileDocument(new File("src/main/resources/xml_example.xml"));
		
		SignatureTokenConnection signingToken;
		try {
			signingToken = getPkcs12Token();
		
		
			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
			
			// tag::demo[]
		
	
			// Preparing parameters for the CAdES signature
			CAdESSignatureParameters parameters = new CAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
			// We choose the type of the signature packaging (ENVELOPING, DETACHED).
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token. The default value is
			// SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
	
			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());
	
			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create CAdESService for signature
			CAdESService service = new CAdESService(commonCertificateVerifier);
	
			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
	
			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
	
			// We invoke the CAdESService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
	
			// end::demo[]
			
			signedDocument.save("./signed_xml_document.xml");
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	/**
	 * This method retrieves an instance of PKCS12 keystore
	 * 
	 */
	private static SignatureTokenConnection getPkcs12Token() throws IOException{
		// TODO Auto-generated method stub
		return getToken();
	}

	private static AbstractKeyStoreTokenConnection getToken() {
		// TODO Auto-generated method stub
		return new KeyStoreSignatureTokenConnection(getKeystoreContent(getKeystoreName()), KEYSTORE_TYPE,
				new PasswordProtection(PKI_FACTORY_KEYSTORE_PASSWORD.toCharArray()));
	}

	private static byte[] getKeystoreContent(String keystoreName) {
		// TODO Auto-generated method stub
		DataLoader dataLoader = getFileCacheDataLoader();
		String keystoreUrl = PKI_FACTORY_HOST + KEYSTORE_ROOT_PATH + keystoreName;
		return dataLoader.get(keystoreUrl);
	}

	private static DataLoader getFileCacheDataLoader() {
		// TODO Auto-generated method stub
		FileCacheDataLoader cacheDataLoader = new FileCacheDataLoader();
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(getProxyConfig());
		dataLoader.setTimeoutConnection(TIMEOUT_MS);
		dataLoader.setTimeoutSocket(TIMEOUT_MS);
		cacheDataLoader.setDataLoader(dataLoader);
		cacheDataLoader.setFileCacheDirectory(new File("target"));
		cacheDataLoader.setCacheExpirationTime(3600000L);
		return cacheDataLoader;
	}

	private static eu.europa.esig.dss.service.http.proxy.ProxyConfig getProxyConfig() {
		// TODO Auto-generated method stub
		return null;
	}

	private static String getKeystoreName() {
		// TODO Auto-generated method stub
		return DSSUtils.encodeURI(getSigningAlias() + ".p12");
	}

	private static String getSigningAlias() {
		// TODO Auto-generated method stub
		return "good-user";
	}

}
