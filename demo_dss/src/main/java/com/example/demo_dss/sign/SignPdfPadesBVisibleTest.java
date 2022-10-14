package com.example.demo_dss.sign;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;

public class SignPdfPadesBVisibleTest {
	
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final String PKI_FACTORY_KEYSTORE_PASSWORD = "ks-password";
	private static final String KEYSTORE_ROOT_PATH = "/keystore/";
	private static final String PKI_FACTORY_HOST = "http://dss.nowina.lu/pki-factory/";
	private static final int TIMEOUT_MS = 10000;
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		
		// GET document to be signed -
		// Return DSSDocument toSignDocument
		DSSDocument toSignDocument = new FileDocument(new File("src/main/resources/hello-world.pdf"));
		
		try {
			
			SignatureTokenConnection signingToken = getPkcs12Token();
			
			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
			
			// tag::parameters-configuration[]
			// Preparing parameters for the PAdES signature
			PAdESSignatureParameters parameters = new PAdESSignatureParameters();
			
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
			
			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());
			
			// Initialize visual signature and configure
			SignatureImageParameters imageParameters = new SignatureImageParameters();
			// set an image
			imageParameters.setImage(new InMemoryDocument((SignPdfPadesBVisibleTest.class).getResourceAsStream("/signature-pen.png")));
						
			// initialize signature field parameters
			SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
			imageParameters.setFieldParameters(fieldParameters);
			// the origin is the left and top corner of the page
			fieldParameters.setOriginX(200);
			fieldParameters.setOriginY(400);
			fieldParameters.setWidth(300);
			fieldParameters.setHeight(200);
			// end::parameters-configuration[]
			
			// tag::font[]
			// Initialize text to generate for visual signature
			DSSFont font = new DSSFileFont((SignPdfPadesBVisibleTest.class).getResourceAsStream("/fonts/OpenSansRegular.ttf"));
			// end::font[]
			// tag::text[]
			// Instantiates a SignatureImageTextParameters object
			SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
			// Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
			textParameters.setFont(font);
			// Defines the text content
			textParameters.setText("My visual signature \n #1");
			// Defines the color of the characters
			textParameters.setTextColor(Color.BLUE);
			// Defines the background color for the area filled out by the text
			textParameters.setBackgroundColor(Color.YELLOW);
			// Defines a padding between the text and a border of its bounding area
			textParameters.setPadding(20);
			// TextWrapping parameter allows defining the text wrapping behavior within  the signature field
			/*
			 	FONT_BASED - the default text wrapping, the text is computed based on the given font size;
				FILL_BOX - finds optimal font size to wrap the text to a signature field box;
				FILL_BOX_AND_LINEBREAK - breaks the words to multiple lines in order to find the biggest possible font size to wrap the text into a signature field box.
			*/
			textParameters.setTextWrapping(TextWrapping.FONT_BASED);
			// Set textParameters to a SignatureImageParameters object
			imageParameters.setTextParameters(textParameters);
			// end::text[]
			// tag::textImageCombination[]
			// Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures). 
			// Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side, 
			// and image will be aligned to the right side inside the signature field
			textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
			// Specifies a horizontal alignment of a text with respect to its area
			textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
			// Specifies a vertical alignment of a text block with respect to a signature field area
			textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
			// end::textImageCombination[]
			
			// tag::sign[]
			parameters.setImageParameters(imageParameters);

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
			// Create PAdESService for signature
			PAdESService service = new PAdESService(commonCertificateVerifier);
			// tag::custom-factory[]
			service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
			// end::custom-factory[]
			// Get the SignedInfo segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
			SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

			// We invoke the xadesService to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			// end::sign[]
			
			signedDocument.save("./signed_pdf_document.pdf");
			
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
